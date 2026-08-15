"""
    FastAPI App — Issuer (Middleware BraZKIL)
    Implementa o fluxo OID4VCI Pre-Authorized Code para emissão de SD-JWT VCs.

    Porta: 8002
    Fluxo implementado:
      POST  /issuer/issue                          → Solicita emissão, retorna Credential Offer URI
      GET   /.well-known/openid-credential-issuer  → Metadata do Issuer (OID4VCI discovery)
      GET   /issuer/nonce                          → Emite c_nonce para prova de posse
      POST  /issuer/token                          → Troca pre-authorized code por Access Token
      POST  /issuer/credential                     → Entrega a SD-JWT VC (autenticado com Bearer)
      GET   /issuer/offers/{offer_id}              → Resolve o Credential Offer URI (por referência)
"""

import os
import sys
import json
import base64
import uuid
import httpx
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

from .schema import (
    IssuanceRequest, IssuanceResponse,
    TokenRequest, TokenResponse,
    CredentialRequest, CredentialResponse,
    NonceResponse,
)
from .policy import evaluate_issuance_policy
from .sd_jwt import generate_sd_jwt_vc, ISSUER_BASE_URL, VC_TYPE, VC_TYPE_URL
from jose import jwt as jose_jwt
from jose.exceptions import JWTError
from shared.did import resolve_public_key_from_did_document

# URLs dos serviços BraZKIL
VDR_URL = "http://127.0.0.1:8001"
VALIDATOR_URL = "http://127.0.0.1:8000"

# Arquivo .env do Issuer (chave privada e DID persistidos)
ISSUER_ENV_FILE = os.path.join(os.path.dirname(__file__), ".issuer_identity.json")

# Estado em memória (para a PoC — em produção usaria Redis ou banco de dados)
# { pre_auth_code: { "holder_did": str, "sd_jwt": str, "created_at": datetime, "used": bool } }
_pending_offers: dict = {}

# { access_token: { "pre_auth_code": str, "c_nonce": str, "created_at": datetime } }
_active_tokens: dict = {}

# { c_nonce: { "created_at": datetime } }
_active_nonces: dict = {}


# =============================================================================
# Bootstrap: carrega ou cria a identidade do Issuer
# =============================================================================

def _load_or_create_issuer_identity() -> dict:
    """
    Carrega a identidade do Issuer do arquivo .issuer_identity.json.
    Se não existir (primeira execução), gera um novo DID, registra no VDR e persiste.
    """
    import json
    from shared.did import generate_brazkil_did

    if os.path.exists(ISSUER_ENV_FILE):
        with open(ISSUER_ENV_FILE, "r") as f:
            identity = json.load(f)
        print(f"[ISSUER] Identidade carregada: DID={identity['did']}")
        return identity

    print("[ISSUER] Primeira execução — gerando novo DID e tentando registrar no VDR...")
    result = generate_brazkil_did("Middleware BraZKIL")
    identity = {
        "did": result["did"],
        "did_document": result["did_document"],
        "private_key_pem": result["private_key_pem"],
    }

    # Tenta registrar no VDR de forma síncrona
    try:
        resp = httpx.post(
            f"{VDR_URL}/vdr/issuers",
            json={"name": "Middleware BraZKIL", "did_document": identity["did_document"]},
            timeout=3.0
        )
        if resp.status_code == 201:
            print("[ISSUER] DID registrado com sucesso no VDR.")
        else:
            print(f"[ISSUER AVISO] Falha ao registrar DID no VDR: HTTP {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[ISSUER AVISO] VDR indisponível. O DID será persistido localmente mas não foi registrado: {e}")

    # Persistir localmente (mesmo se o VDR falhar, para manter a consistência das chaves)
    with open(ISSUER_ENV_FILE, "w") as f:
        json.dump(identity, f, indent=2)

    print(f"[ISSUER] DID gerado e persistido: {identity['did']}")
    return identity


# Inicializa a identidade ao carregar o módulo
ISSUER_IDENTITY = _load_or_create_issuer_identity()


# =============================================================================
# Helpers
# =============================================================================

async def _resolve_holder_did(holder_did: str) -> dict:
    """Resolve o DID do Holder no VDR e retorna o DID Document."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{VDR_URL}/vdr/did/{holder_did}", timeout=5.0)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"DID do Holder não encontrado no VDR: {holder_did}"
            )
        return resp.json()["did_document"]


def _extract_jwk_from_did_document(did_document: dict) -> dict:
    """Extrai a JWK pública do primeiro verificationMethod do DID Document."""
    vm = did_document.get("verificationMethod", [])
    if not vm:
        raise HTTPException(status_code=400, detail="DID Document sem verificationMethod.")
    jwk = vm[0].get("publicKeyJwk")
    if not jwk:
        raise HTTPException(status_code=400, detail="verificationMethod sem publicKeyJwk.")
    return jwk


async def _register_credential_status(credential_id: str) -> None:
    """Registra a credencial emitida na Status List do VDR para futura revogação."""
    payload = {
        "credential_id": credential_id,
        "issuer_did": ISSUER_IDENTITY["did"],
        "status": "ACTIVE"
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{VDR_URL}/vdr/credentials/status", json=payload, timeout=5.0)
            if resp.status_code == 201:
                print(f"[ISSUER] Credencial {credential_id} registrada no VDR (status: ACTIVE)")
            else:
                print(f"[ISSUER AVISO] VDR retornou {resp.status_code} ao registrar status da credencial")
    except Exception as e:
        print(f"[ISSUER AVISO] Não foi possível registrar o status no VDR: {e}")


def _verify_bearer_token(authorization: Optional[str] = Header(None)) -> str:
    """Valida o Bearer Token e retorna o access_token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization Bearer obrigatório.")
    token = authorization.removeprefix("Bearer ").strip()
    if token not in _active_tokens:
        raise HTTPException(status_code=401, detail="Access Token inválido ou expirado.")
    token_info = _active_tokens[token]
    if datetime.now(timezone.utc) > token_info["expires_at"]:
        del _active_tokens[token]
        raise HTTPException(status_code=401, detail="Access Token expirado.")
    return token


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="BraZKIL Issuer (Middleware)",
    description=(
        "Middleware de emissão de SD-JWT VCs com divulgação seletiva (age_over_18, birthdate). "
        "Implementa OID4VCI Pre-Authorized Code Flow."
    ),
    version="1.0.0",
)

# Habilita CORS completo para permitir consumo pelo aplicativo web da walt.id
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", summary="Verificação de saúde do Issuer")
async def health_check():
    return {"status": "online", "module": "issuer", "did": ISSUER_IDENTITY["did"]}



# =============================================================================
# DEBUG: Middleware de log bruto (ativo para depuração com walt.id)
# Remove ou desabilite DEBUG_LOG_REQUESTS=false em produção.
# =============================================================================

DEBUG_LOG_REQUESTS = os.environ.get("DEBUG_LOG_REQUESTS", "true").lower() == "true"

if DEBUG_LOG_REQUESTS:
    class RawRequestLoggerMiddleware(BaseHTTPMiddleware):
        """
        Intercepta cada request/response e imprime no stdout o método, path,
        headers, body da requisição e status + body da resposta.
        Útil para depurar incompatibilidades com o walt.id OID4VCI.
        """

        async def dispatch(self, request: StarletteRequest, call_next) -> StarletteResponse:
            # --- REQUEST ---
            req_body = await request.body()
            sep = "=" * 72
            print(f"\n{sep}")
            print(f"[DEBUG ▶] {request.method} {request.url}")
            print(f"  Headers:")
            for k, v in request.headers.items():
                print(f"    {k}: {v}")
            if req_body:
                try:
                    print(f"  Body (UTF-8): {req_body.decode('utf-8')}")
                except Exception:
                    print(f"  Body (bytes): {req_body!r}")
            else:
                print("  Body: <vazio>")

            # Processa a request normalmente
            response = await call_next(request)

            # --- RESPONSE ---
            # Lê o body da resposta (consome o stream, então precisa reconstituí-lo)
            res_body_chunks = []
            async for chunk in response.body_iterator:
                res_body_chunks.append(chunk)
            res_body = b"".join(res_body_chunks)

            print(f"[DEBUG ◀] Status: {response.status_code}")
            if res_body:
                try:
                    print(f"  Response Body: {res_body.decode('utf-8')}")
                except Exception:
                    print(f"  Response Body (bytes): {res_body!r}")
            print(sep)

            # Reconstrói a resposta com o body já consumido
            from starlette.responses import Response
            return Response(
                content=res_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

    app.add_middleware(RawRequestLoggerMiddleware)
    print("[ISSUER DEBUG] Middleware de log bruto ATIVO. Defina DEBUG_LOG_REQUESTS=false para desabilitar.")


PORTAL_HTML_PATH = os.path.join(os.path.dirname(__file__), "portal.html")


# =============================================================================
# Endpoint 1: POST /issuer/issue — Solicita emissão e retorna Credential Offer
# =============================================================================

@app.post("/issuer/issue", response_model=IssuanceResponse, status_code=201,
          summary="Solicitar emissão da SD-JWT VC de maioridade")
async def issue_credential(request: IssuanceRequest):
    """
    Fluxo OID4VCI (Opção B):
    1. Chama o Validador Datavalid com os dados informados no Portal.
    2. Aplica política de aceitação (maioridade + critérios RFB).
    3. Gera a Oferta de Credencial e guarda os atributos validados em memória.
    (A SD-JWT VC será gerada apenas no endpoint /credential, quando o Holder se apresentar)
    """

    # 1. Chamar o Validador Datavalid
    validation_payload = {
        "cpf": request.cpf,
        "name": request.name,
        "birth_date": request.birth_date.isoformat()
    }
    try:
        async with httpx.AsyncClient() as client:
            val_resp = await client.post(
                f"{VALIDATOR_URL}/validate",
                json=validation_payload,
                timeout=30.0
            )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Validador Datavalid indisponível: {e}")

    if val_resp.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail=f"Validação Datavalid falhou (HTTP {val_resp.status_code}): {val_resp.text}"
        )

    val_result = val_resp.json()

    # 2. Avaliar política de aceitação
    decision = evaluate_issuance_policy(
        rfb_exists=val_result.get("rfb_exists", False),
        cpf_regular=val_result.get("cpf_regular", False),
        name_similarity=val_result.get("name_similarity", 0.0),
        birth_date_valid=val_result.get("birth_date_valid", False),
        birth_date=request.birth_date,
    )

    if not decision.approved:
        raise HTTPException(status_code=403, detail=f"Emissão negada pela política: {decision.reason}")

    credential_id = str(uuid.uuid4())

    # 3. Gerar pre-authorized code e armazenar os atributos validados
    pre_auth_code = secrets.token_urlsafe(32)
    _pending_offers[pre_auth_code] = {
        "credential_id": credential_id,
        "age_over_18": decision.age_over_18,
        "birthdate": request.birth_date,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=300),
        "used": False,
    }

    # 4. Montar o Credential Offer URI
    offer_id = str(uuid.uuid4())
    _pending_offers[f"offer_{offer_id}"] = pre_auth_code

    credential_offer_uri = (
        f"openid-credential-offer://"
        f"?credential_offer_uri={ISSUER_BASE_URL}/issuer/offers/{offer_id}"
    )

    print(f"[ISSUER] Oferta de credencial {credential_id} gerada para titular validado")
    print(f"[ISSUER] Política: {decision.reason}")

    return IssuanceResponse(
        credential_offer_uri=credential_offer_uri,
        pre_authorized_code=pre_auth_code,
        expires_in=300,
    )


# =============================================================================
# Endpoint 2: GET /.well-known/openid-credential-issuer — Metadata OID4VCI
# =============================================================================

@app.get("/.well-known/openid-credential-issuer",
         summary="Metadata do Issuer BraZKIL (OID4VCI Discovery)")
async def issuer_metadata():
    """
    Retorna o documento de metadados do Issuer conforme a spec OID4VCI.
    Formato compatível com walt.id v0.23 (sdk-libraries/oid4vc).

    Nota sobre compatibilidade:
      - O deserializador CredentialSupported do walt.id falha ao receber JsonArray
        em campos como 'display' e 'claims[x].display' aninhados.
      - proof_types_supported é obrigatório para o walt.id processar o flow.
      - format: "dc+sd-jwt" é o valor reconhecido pelo walt.id para SD-JWT VCs.
        "vc+sd-jwt" é o nome anterior da spec (draft < 13) e pode causar falha de parse.
    """
    return JSONResponse({
        "credential_issuer": ISSUER_BASE_URL,
        "credential_endpoint": f"{ISSUER_BASE_URL}/issuer/credential",
        "token_endpoint": f"{ISSUER_BASE_URL}/issuer/token",
        "nonce_endpoint": f"{ISSUER_BASE_URL}/issuer/nonce",
        "authorization_servers": [ISSUER_BASE_URL],
        "credential_configurations_supported": {
            "BraZKIL_AgeOver18": {
                # dc+sd-jwt é o formato reconhecido pelo walt.id v0.23+
                # (vc+sd-jwt era o nome no draft antigo da spec SD-JWT VC)
                "format": "dc+sd-jwt",
                "vct": VC_TYPE_URL,
                "scope": "BraZKIL_AgeOver18",
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                # proof_types_supported é obrigatório pelo walt.id para iniciar o fluxo
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                }
            }
        },
        "issuer_did": ISSUER_IDENTITY["did"],
        "grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ]
    })


@app.get("/.well-known/openid-configuration", include_in_schema=False)
@app.get("/.well-known/oauth-authorization-server", include_in_schema=False)
async def oauth_metadata():
    """
    Retorna o documento de metadados do Servidor de Autorização OAuth 2.0 (RFC 8414 / OIDC Discovery).
    Algumas carteiras OID4VCI (como Walt.id) consultam este endpoint durante a troca de tokens.
    """
    return JSONResponse({
        "issuer": ISSUER_BASE_URL,
        "token_endpoint": f"{ISSUER_BASE_URL}/issuer/token",
        "grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ],
        "response_types_supported": ["token"],
        "token_endpoint_auth_methods_supported": ["none"]
    })


@app.get(f"/.well-known/vct/{VC_TYPE}",
         summary="SD-JWT VC Type Metadata (resolução do claim 'vct')")
async def vct_type_metadata():
    """
    Metadados do tipo de credencial, resolvidos a partir da URI usada no claim 'vct'
    (draft-ietf-oauth-sd-jwt-vc). Carteiras como a walt.id buscam este documento em
    <authority>/.well-known/vct<path-do-vct> antes de exibir a tela de aceite da oferta —
    sem ele, a resolução do 'vct' falha e a tela fica em branco.
    """
    return JSONResponse({
        "vct": VC_TYPE_URL,
        "name": "BraZKIL — Comprovante de Maioridade",
        "description": (
            "Credencial de maioridade emitida pelo Middleware BraZKIL com divulgação "
            "seletiva dos atributos age_over_18 e birthdate."
        ),
    })


# =============================================================================
# Endpoint 3: GET /issuer/offers/{offer_id} — Resolve Credential Offer por URI
# =============================================================================

@app.get("/issuer/offers/{offer_id}",
         summary="Resolve o Credential Offer JSON pelo ID")
async def get_credential_offer(offer_id: str):
    """
    Retorna o JSON do Credential Offer referenciado pelo URI de oferta.
    Permite que a carteira obtenha os detalhes da oferta via credential_offer_uri.
    """
    key = f"offer_{offer_id}"
    if key not in _pending_offers:
        raise HTTPException(status_code=404, detail="Credential Offer não encontrado ou expirado.")

    pre_auth_code = _pending_offers[key]
    offer_data = _pending_offers.get(pre_auth_code, {})

    if not offer_data or offer_data.get("used"):
        raise HTTPException(status_code=410, detail="Credential Offer já utilizado.")

    return JSONResponse({
        "credential_issuer": ISSUER_BASE_URL,
        "credential_configuration_ids": ["BraZKIL_AgeOver18"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code
            }
        }
    })


# =============================================================================
# Endpoint 4: GET /issuer/nonce — Emite c_nonce
# =============================================================================

@app.get("/issuer/nonce", response_model=NonceResponse,
         summary="Gera um c_nonce para Proof of Possession JWT")
async def get_nonce():
    """
    Emite um c_nonce (challenge nonce) que a carteira deve incluir
    no proof JWT assinado ao solicitar a credencial.
    """
    c_nonce = str(uuid.uuid4())
    _active_nonces[c_nonce] = {
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=300),
    }
    return NonceResponse(c_nonce=c_nonce, c_nonce_expires_in=300)


# =============================================================================
# Endpoint 5: POST /issuer/token — Troca pre-auth code por Access Token
# =============================================================================

@app.post("/issuer/token", response_model=TokenResponse,
          summary="Troca pre-authorized code por Access Token (OID4VCI)")
async def token_endpoint(raw_request: StarletteRequest):
    """
    Pre-Authorized Code Flow — Step 2:
    A carteira troca o pre-authorized code por um Access Token e um c_nonce.
    Suporta JSON e x-www-form-urlencoded (padrão RFC 6749).
    """
    content_type = raw_request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        form_data = await raw_request.form()
        grant_type = form_data.get("grant_type")
        pre_authorized_code = form_data.get("pre-authorized_code") or form_data.get("pre_authorized_code")
    else:
        try:
            body = await raw_request.json()
            grant_type = body.get("grant_type")
            pre_authorized_code = body.get("pre_authorized_code") or body.get("pre-authorized_code")
        except Exception:
            raise HTTPException(status_code=400, detail="Formato de requisição inválido.")

    if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        raise HTTPException(status_code=400, detail="grant_type inválido para o fluxo Pre-Authorized Code.")

    if not pre_authorized_code:
        raise HTTPException(status_code=400, detail="pre_authorized_code não informado.")

    offer = _pending_offers.get(pre_authorized_code)
    if not offer or isinstance(offer, str):
        raise HTTPException(status_code=400, detail="pre_authorized_code inválido.")

    if offer.get("used"):
        raise HTTPException(status_code=400, detail="pre_authorized_code já utilizado.")

    if datetime.now(timezone.utc) > offer["expires_at"]:
        raise HTTPException(status_code=400, detail="pre_authorized_code expirado.")

    # Marcar o código como usado (single-use)
    offer["used"] = True

    # Gerar Access Token e c_nonce
    access_token = secrets.token_urlsafe(48)
    c_nonce = str(uuid.uuid4())

    _active_tokens[access_token] = {
        "pre_auth_code": pre_authorized_code,
        "credential_id": offer["credential_id"],
        "age_over_18": offer["age_over_18"],
        "birthdate": offer["birthdate"],
        "c_nonce": c_nonce,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=300),
    }

    _active_nonces[c_nonce] = {
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=300),
    }

    print(f"[ISSUER] Access Token emitido para credencial {offer['credential_id']}")

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=300,
        c_nonce=c_nonce,
        c_nonce_expires_in=300,
    )


# =============================================================================
# Endpoint 6: POST /issuer/credential — Entrega SD-JWT VC
# =============================================================================

@app.post("/issuer/credential", response_model=CredentialResponse,
          summary="Entrega a SD-JWT VC ao Holder (OID4VCI Credential Endpoint)")
async def credential_endpoint(
    request: CredentialRequest,
    access_token: str = Depends(_verify_bearer_token),
):
    """
    Pre-Authorized Code Flow — Step 3 (Final):
    O Holder apresenta o Access Token e recebe a SD-JWT VC.
    """
    token_info = _active_tokens[access_token]

    if not request.proof or request.proof.proof_type != "jwt":
        raise HTTPException(status_code=400, detail="Prova de posse (proof) do tipo JWT é obrigatória.")

    # Extrai o unverified header para obter a jwk diretamente da prova de posse (Padrão OID4VCI genérico)
    try:
        unverified_headers = jose_jwt.get_unverified_headers(request.proof.jwt)
        jwk_header = unverified_headers.get("jwk")
        if not jwk_header:
            raise HTTPException(status_code=400, detail="Cabeçalho 'jwk' não encontrado no proof JWT.")
            
        unverified_claims = jose_jwt.get_unverified_claims(request.proof.jwt)
        # O proof JWT do OID4VCI não é obrigado a carregar 'iss'/'sub' (a identidade do
        # Holder vem da chave 'jwk'/'kid' no header) — carteiras como a walt.id não os
        # enviam. Quando ausentes, derivamos um did:jwk a partir da própria jwk da prova,
        # que é exatamente como a walt.id constrói o DID default da carteira.
        holder_did = unverified_claims.get("iss") or unverified_claims.get("sub")
        if not holder_did:
            jwk_json = json.dumps(jwk_header, separators=(",", ":"))
            holder_did = "did:jwk:" + base64.urlsafe_b64encode(jwk_json.encode("utf-8")).rstrip(b"=").decode("ascii")

        from jose import jwk as jose_jwk
        public_key = jose_jwk.construct(jwk_header, algorithm="ES256")

        proof_payload = jose_jwt.decode(
            request.proof.jwt,
            public_key,
            algorithms=["ES256"],
            options={"verify_exp": True, "verify_aud": False}
        )
    except HTTPException:
        raise
    except JWTError as e:
        raise HTTPException(status_code=400, detail=f"Assinatura ou formato do proof JWT inválido: {e}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"Erro ao processar chave pública enviada pelo Holder: {e}")

    # Verifica se o nonce é válido na lista global de nonces ativos
    nonce = proof_payload.get("nonce")
    if not nonce or nonce not in _active_nonces:
        raise HTTPException(status_code=400, detail="c_nonce inválido, ausente ou expirado na prova de posse.")
    if datetime.now(timezone.utc) > _active_nonces[nonce]["expires_at"]:
        del _active_nonces[nonce]
        raise HTTPException(status_code=400, detail="c_nonce expirado.")
    # Consume the nonce
    del _active_nonces[nonce]

    aud = proof_payload.get("aud")
    if isinstance(aud, list):
        if ISSUER_BASE_URL not in aud:
            raise HTTPException(status_code=400, detail=f"Audiência (aud) do proof JWT inválida. Esperado {ISSUER_BASE_URL}, obtido {aud}")
    elif aud != ISSUER_BASE_URL:
        raise HTTPException(status_code=400, detail=f"Audiência (aud) do proof JWT inválida. Esperado {ISSUER_BASE_URL}, obtido {aud}")

    try:
        # Agora sim, geramos a SD-JWT dinamicamente com o DID e a JWK revelados pela carteira
        credential_id = token_info["credential_id"]
        sd_jwt = generate_sd_jwt_vc(
            issuer_did=ISSUER_IDENTITY["did"],
            issuer_private_key_pem=ISSUER_IDENTITY["private_key_pem"],
            holder_did=holder_did,
            holder_jwk=jwk_header,
            age_over_18=token_info["age_over_18"],
            birthdate=token_info["birthdate"],
            credential_id=credential_id,
        )

        # Registrar status da credencial no VDR (somente agora ela de fato existe e tem um DID vinculado)
        await _register_credential_status(credential_id)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro na geração da credencial: {e}")
    # ---------------------------------------------------------

    # Gerar novo c_nonce para rotação (boa prática OID4VCI)
    new_c_nonce = str(uuid.uuid4())
    _active_nonces[new_c_nonce] = {
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=300),
    }

    print(f"[ISSUER] SD-JWT VC entregue ao Holder {holder_did}")

    return CredentialResponse(
        format="vc+sd-jwt",
        credential=sd_jwt,
        c_nonce=new_c_nonce,
        c_nonce_expires_in=300,
        # Formato batch (OID4VCI 1.0 final) para compatibilidade com a carteira walt.id "v2"
        # (waltid-openid4vci), que só lê o campo 'credentials' e ignora 'format'/'credential'.
        credentials=[{"credential": sd_jwt}],
    )


# =============================================================================
# Root
# =============================================================================

@app.get("/portal", summary="Portal Web TUI Cyberpunk do Titular")
@app.get("/", summary="Página Inicial do Issuer e Portal do Titular")
async def root():
    if os.path.exists(PORTAL_HTML_PATH):
        with open(PORTAL_HTML_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content)
    return {
        "service": "BraZKIL Issuer (Middleware)",
        "did": ISSUER_IDENTITY["did"],
        "docs": f"{ISSUER_BASE_URL}/docs",
        "metadata": f"{ISSUER_BASE_URL}/.well-known/openid-credential-issuer"
    }
