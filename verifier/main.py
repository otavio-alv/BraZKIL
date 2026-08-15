"""
    verifier/main.py — FastAPI App do Serviço Verificador BraZKIL (OID4VP)

    Porta: 8003
    Serve a loja de vinhos premium e implementa o fluxo OID4VP completo:

      GET   /                        → Serve a UI da loja de vinhos (wine_shop.html)
      GET   /verifier/challenge      → Gera nonce + Presentation Request (OID4VP)
      POST  /verifier/present        → Recebe VP Token e executa verificação completa
      GET   /verifier/session/{id}   → Consulta o resultado de uma sessão (polling)
      POST  /verifier/simulate       → End-to-end demo sem carteira real
      GET   /health                  → Health check
"""

import os
import sys
import uuid
import secrets
import hashlib
import base64
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt as jose_jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

from verifier.schema import (
    VerificationResult,
    VerificationStep,
    SessionState,
)
from verifier.verify import verify_presentation

# =============================================================================
# Configuração de URLs dos serviços BraZKIL
# =============================================================================

VDR_URL = os.getenv("VDR_URL", "http://127.0.0.1:8001")
ISSUER_URL = os.getenv("ISSUER_URL", os.getenv("ISSUER_BASE_URL", "http://127.0.0.1:8002")).strip().rstrip("/")
VERIFIER_BASE_URL = os.getenv("VERIFIER_BASE_URL", "http://127.0.0.1:8003").strip().rstrip("/")

# Deve casar com VC_TYPE_URL em issuer/sd_jwt.py (claim 'vct' das credenciais emitidas) —
# usado no dcql_query para restringir a busca ao tipo de credencial BraZKIL.
ISSUER_VC_TYPE_URL = f"{ISSUER_URL}/BraZKIL_AgeOver18"

WINE_SHOP_HTML_PATH = os.path.join(os.path.dirname(__file__), "wine_shop.html")
VERIFIER_ENV_FILE = os.path.join(os.path.dirname(__file__), ".verifier_identity.json")

# =============================================================================
# Estado em memória (sessões OID4VP)
# =============================================================================

# { session_id: SessionState }
_sessions: dict[str, SessionState] = {}


# =============================================================================
# Bootstrap: carrega ou cria a identidade do Verifier (para assinar Request Objects)
# =============================================================================

def _load_or_create_verifier_identity() -> dict:
    """
    Carteiras OID4VP 1.0 (como a walt.id) exigem que o Authorization Request resolvido
    via request_uri seja um JWT assinado (Request Object) e que o 'client_id' use um dos
    prefixos padronizados (RFC do OpenID4VP 1.0 §5.9.3) — 'redirect_uri:' é proibido para
    requests assinados, então usamos 'decentralized_identifier:<did>'. A carteira resolve
    esse DID com seu próprio serviço de DIDs (não o VDR do BraZKIL), que só sabe resolver
    métodos padrão como did:jwk — daí usarmos did:jwk aqui em vez do did:brazkil custom.
    O 'kid' é embutido na própria JWK (convenção que a walt.id também usa) e repetido no
    header do JWT para casar com o key lookup feito na verificação da assinatura.
    """
    import json
    import uuid as _uuid
    from shared.did import public_key_to_jwk
    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

    if os.path.exists(VERIFIER_ENV_FILE):
        with open(VERIFIER_ENV_FILE, "r") as f:
            identity = json.load(f)
        print(f"[VERIFIER] Identidade carregada: DID={identity['did']}")
        return identity

    print("[VERIFIER] Primeira execução — gerando novo did:jwk para assinatura de Request Objects...")
    private_key = generate_private_key(SECP256R1(), default_backend())
    public_key = private_key.public_key()

    kid = str(_uuid.uuid4())
    jwk = public_key_to_jwk(public_key)
    jwk["kid"] = kid

    jwk_json = json.dumps(jwk, separators=(",", ":"))
    did = "did:jwk:" + base64.urlsafe_b64encode(jwk_json.encode("utf-8")).rstrip(b"=").decode("ascii")

    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode()

    identity = {"did": did, "kid": kid, "jwk": jwk, "private_key_pem": private_key_pem}
    with open(VERIFIER_ENV_FILE, "w") as f:
        json.dump(identity, f, indent=2)
    print(f"[VERIFIER] DID gerado e persistido: {did}")
    return identity


VERIFIER_IDENTITY = _load_or_create_verifier_identity()

# client_id no formato prefixado exigido pelo OpenID4VP 1.0 (ver docstring acima)
VERIFIER_CLIENT_ID = f"decentralized_identifier:{VERIFIER_IDENTITY['did']}"


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="BraZKIL Verifier — Loja de Vinhos Premium",
    description=(
        "Serviço Verificador BraZKIL (OID4VP). Solicita, recebe e valida "
        "Verifiable Presentations com SD-JWT VC + Holder Binding JWT. "
        "Interface de demonstração: Loja de Vinhos Autentico."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Helpers internos
# =============================================================================

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _cleanup_expired_sessions():
    """Remove sessões com mais de 10 minutos (limpeza simples em memória)."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
    to_delete = [
        sid for sid, state in _sessions.items()
        if hasattr(state, "_created_at") and state._created_at < cutoff
    ]
    for sid in to_delete:
        del _sessions[sid]


# =============================================================================
# GET / — Serve a UI da Loja de Vinhos
# =============================================================================

@app.get("/", response_class=HTMLResponse, summary="Loja de Vinhos Premium (UI)")
async def wine_shop_ui():
    """Serve a interface HTML premium da loja de vinhos."""
    if os.path.exists(WINE_SHOP_HTML_PATH):
        with open(WINE_SHOP_HTML_PATH, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>wine_shop.html não encontrado</h1>", status_code=500)


# =============================================================================
# GET /health — Health Check
# =============================================================================

@app.get("/health", summary="Health check do Verifier")
async def health():
    return {"status": "online", "module": "verifier", "verifier_url": VERIFIER_BASE_URL}


# =============================================================================
# GET /verifier/challenge — Gera Presentation Request (OID4VP)
# =============================================================================

@app.get("/verifier/challenge", summary="Gera um desafio OID4VP (nonce + Presentation Definition)")
async def get_challenge():
    """
    Gera um novo desafio de apresentação conforme OID4VP.
    Retorna um session_id, nonce único e a Presentation Definition
    solicitando o claim 'age_over_18' via SD-JWT VC.
    """
    _cleanup_expired_sessions()

    session_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(32)

    # Registrar sessão como PENDING
    session = SessionState(session_id=session_id, nonce=nonce, status="PENDING")
    _sessions[session_id] = session

    print(f"[VERIFIER] Sessão {session_id} criada. Nonce: {nonce[:12]}...")

    # DCQL (OpenID4VP 1.0, Seção 6) — precisa casar com a query embutida no Authorization
    # Request que a UI monta a partir destes campos (ver wine_shop.html::startVerification).
    return JSONResponse({
        "session_id": session_id,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "client_id": VERIFIER_CLIENT_ID,
        "response_uri": f"{VERIFIER_BASE_URL}/verifier/present",
        "nonce": nonce,
        "dcql_query": {
            "credentials": [
                {
                    "id": "age_over_18_credential",
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": [ISSUER_VC_TYPE_URL]},
                    "claims": [
                        {"path": ["age_over_18"], "values": [True]}
                    ]
                }
            ]
        },
        "client_metadata": {
            "client_name": "Autentico Vini — Adega Fine Wines",
            "logo_uri": f"{VERIFIER_BASE_URL}/favicon.ico",
        }
    })


# =============================================================================
# GET /verifier/request/{session_id} — OID4VP Authorization Request
# =============================================================================

@app.get("/verifier/request/{session_id}", summary="Retorna o Authorization Request OID4VP (JWT assinado) para a Wallet")
async def get_authorization_request(session_id: str):
    """
    Endpoint acessado pela Wallet após escanear o QR Code (via request_uri).
    Retorna os parâmetros de autorização, incluindo a Presentation Definition,
    como um Request Object JWT assinado (RFC 9101) — carteiras OID4VP resolvem
    request_uri esperando um JWT compacto, não um JSON puro.
    """
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Sessão '{session_id}' não encontrada ou expirada.")

    if session.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail=f"Sessão '{session_id}' já processada."
        )

    claims = {
        "response_type": "vp_token",
        "client_id": VERIFIER_CLIENT_ID,
        "response_mode": "direct_post",
        "response_uri": f"{VERIFIER_BASE_URL}/verifier/present",
        "nonce": session.nonce,
        "state": session_id,
        # DCQL (OpenID4VP 1.0, Seção 6) — a carteira walt.id "v2" só casa credenciais
        # via dcql_query; presentation_definition (DIF PE) é ignorado nesse fluxo.
        "dcql_query": {
            "credentials": [
                {
                    "id": "age_over_18_credential",
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": [ISSUER_VC_TYPE_URL]},
                    "claims": [
                        {"path": ["age_over_18"], "values": [True]}
                    ]
                }
            ]
        },
        "client_metadata": {
            "client_name": "Autentico Vini — Adega Fine Wines",
            "logo_uri": f"{VERIFIER_BASE_URL}/favicon.ico",
            "client_purpose": "Precisamos verificar se você é maior de 18 anos para acesso à adega."
        }
    }

    verifier_private_key = load_pem_private_key(
        VERIFIER_IDENTITY["private_key_pem"].encode(),
        password=None,
        backend=default_backend(),
    )
    request_object_jwt = jose_jwt.encode(
        claims,
        verifier_private_key,
        algorithm="ES256",
        headers={"typ": "oauth-authz-req+jwt", "kid": VERIFIER_IDENTITY["kid"]},
    )

    return PlainTextResponse(content=request_object_jwt, media_type="application/oauth-authz-req+jwt")


# =============================================================================
# POST /verifier/present — Recebe e Verifica o VP Token
# =============================================================================

@app.post("/verifier/present", response_model=VerificationResult,
          summary="Recebe o VP Token (SD-JWT + KB-JWT) e executa verificação completa")
async def present_credential(request: Request):
    """
    Endpoint principal do fluxo OID4VP.
    Recebe o VP Token do Holder (ou da UI da loja) e executa o pipeline completo:
      1. Assinatura ES256 do Issuer via VDR
      2. Status de revogação no VDR
      3. Integridade dos disclosures (SHA-256)
      4. Holder Binding JWT (nonce + aud + cnf.jwk)
    """
    content_type = request.headers.get("Content-Type", "")
    if "application/json" in content_type:
        data = await request.json()
        session_id = data.get("session_id")
        vp_token = data.get("vp_token")
    elif "application/x-www-form-urlencoded" in content_type:
        body = await request.body()
        from urllib.parse import parse_qs
        form_data = parse_qs(body.decode("utf-8"))
        session_id = form_data.get("state", [None])[0]  # OID4VP usa state para correlacionar a sessão
        vp_token = form_data.get("vp_token", [None])[0]
    else:
        raise HTTPException(status_code=415, detail="Unsupported Media Type")
        
    if not session_id or not vp_token:
        raise HTTPException(status_code=400, detail="session_id/state e vp_token são obrigatórios.")

    # OID4VP com DCQL (usado por carteiras como a walt.id) envia o vp_token como um objeto
    # JSON mapeando cada credential_query_id (definido no nosso dcql_query) para um array de
    # apresentações: {"age_over_18_credential": ["<sd-jwt>~<disclosures>~<kb-jwt>"]}, em vez da
    # string de apresentação única esperada pelo pipeline (formato DIF PE / apresentação manual).
    if isinstance(vp_token, str) and vp_token.lstrip().startswith("{"):
        try:
            vp_token_obj = json.loads(vp_token)
            first_entry = next(iter(vp_token_obj.values()))
            vp_token = first_entry[0] if isinstance(first_entry, list) else first_entry
        except (json.JSONDecodeError, StopIteration, KeyError, IndexError, TypeError):
            pass  # Mantém vp_token original — o pipeline de verificação reportará o erro adequado.

    session = _sessions.get(session_id)

    if not session:
        raise HTTPException(status_code=404, detail=f"Sessão '{session_id}' não encontrada ou expirada.")

    if session.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail=f"Sessão '{session_id}' já foi processada (status: {session.status})."
        )

    print(f"[VERIFIER] Iniciando verificação para sessão {session_id}...")

    # Executar pipeline completo de verificação
    result = verify_presentation(
        vp_token=vp_token,
        expected_nonce=session.nonce,
        verifier_url=VERIFIER_BASE_URL,
        vdr_url=VDR_URL,
        expected_client_id=VERIFIER_CLIENT_ID,
    )

    # Injetar session_id no resultado
    result.session_id = session_id

    # Atualizar estado da sessão
    session.status = "APPROVED" if result.approved else "DENIED"
    session.result = result

    if result.approved:
        print(f"[VERIFIER] ✅ Sessão {session_id} APROVADA — titular maior de 18 anos confirmado.")
    else:
        print(f"[VERIFIER] ❌ Sessão {session_id} NEGADA — {result.reason}")

    return result


# =============================================================================
# GET /verifier/session/{session_id} — Consulta Resultado (Polling)
# =============================================================================

@app.get("/verifier/session/{session_id}", response_model=VerificationResult,
         summary="Consulta o resultado de uma sessão de verificação")
async def get_session_result(session_id: str):
    """
    Permite que a UI da loja de vinhos faça polling do resultado da verificação.
    Retorna o status PENDING, APPROVED ou DENIED com os detalhes completos.
    """
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Sessão '{session_id}' não encontrada.")

    if session.status == "PENDING":
        return VerificationResult(
            session_id=session_id,
            approved=False,
            reason="Aguardando apresentação da credencial...",
            steps=[VerificationStep(
                step="waiting",
                passed=False,
                detail="Nenhuma credencial foi apresentada ainda."
            )],
        )

    return session.result


# =============================================================================
# POST /verifier/simulate — Demonstração End-to-End sem Carteira Real
# =============================================================================

@app.post("/verifier/simulate", summary="Simula o fluxo completo OID4VP para demonstração")
async def simulate_full_flow(
    cpf: str = "25774435016",
    name: str = "Manuela Elisa da Mota",
    birth_date: str = "1975-06-04",
):
    """
    Endpoint de demonstração que executa o ciclo BraZKIL completo sem uma carteira real:

    1. Gera identidade efêmera do Holder (DID + keypair EC P-256)
    2. Chama /issuer/issue → obtém pre-authorized code
    3. Chama /issuer/token → obtém access token + c_nonce
    4. Constrói Proof of Possession JWT e chama /issuer/credential → recebe SD-JWT VC
    5. Chama /verifier/challenge → obtém nonce da sessão
    6. Constrói Key Binding JWT com o nonce da sessão
    7. Monta VP Token = SD-JWT VC + disclosure_age_over_18 + KB-JWT
    8. Chama /verifier/present → executa verificação completa
    9. Retorna resultado com todos os detalhes

    Args:
        cpf: CPF do titular (deve existir nos dados sintéticos do Datavalid)
        name: Nome completo do titular
        birth_date: Data de nascimento no formato YYYY-MM-DD
    """
    from shared.did import generate_brazkil_did
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.backends import default_backend
    from jose import jwt as jose_jwt
    import time

    simulation_log = []

    try:
        # -------------------------------------------------------------------
        # PASSO 1: Gerar identidade efêmera do Holder
        # -------------------------------------------------------------------
        simulation_log.append("🔑 [1/8] Gerando identidade efêmera do Holder (DID + EC P-256)...")
        holder_identity = generate_brazkil_did("Holder Demo BraZKIL")
        holder_did = holder_identity["did"]
        holder_pem = holder_identity["private_key_pem"]
        holder_jwk = holder_identity["did_document"]["verificationMethod"][0]["publicKeyJwk"]
        simulation_log.append(f"    → Holder DID: {holder_did}")

        # -------------------------------------------------------------------
        # PASSO 2: Solicitar emissão ao Issuer (OID4VCI /issuer/issue)
        # -------------------------------------------------------------------
        simulation_log.append("📋 [2/8] Solicitando emissão da credencial ao Issuer BraZKIL...")
        async with httpx.AsyncClient(timeout=30.0) as client:
            issue_resp = await client.post(
                f"{ISSUER_URL}/issuer/issue",
                json={"cpf": cpf, "name": name, "birth_date": birth_date}
            )

        if issue_resp.status_code != 201:
            return JSONResponse(status_code=502, content={
                "error": "Falha na emissão",
                "detail": issue_resp.text,
                "log": simulation_log
            })

        issue_data = issue_resp.json()
        pre_auth_code = issue_data["pre_authorized_code"]
        simulation_log.append(f"    → Pre-Authorized Code obtido: {pre_auth_code[:20]}...")

        # -------------------------------------------------------------------
        # PASSO 3: Trocar pre-auth code por Access Token + c_nonce
        # -------------------------------------------------------------------
        simulation_log.append("🔄 [3/8] Trocando Pre-Auth Code por Access Token + c_nonce...")
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_resp = await client.post(
                f"{ISSUER_URL}/issuer/token",
                json={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre_authorized_code": pre_auth_code,
                }
            )

        if token_resp.status_code != 200:
            return JSONResponse(status_code=502, content={
                "error": "Falha no token endpoint",
                "detail": token_resp.text,
                "log": simulation_log
            })

        token_data = token_resp.json()
        access_token = token_data["access_token"]
        c_nonce = token_data["c_nonce"]
        simulation_log.append(f"    → Access Token: {access_token[:20]}...")
        simulation_log.append(f"    → c_nonce: {c_nonce}")

        # -------------------------------------------------------------------
        # PASSO 4: Construir Proof of Possession JWT e buscar SD-JWT VC
        # -------------------------------------------------------------------
        simulation_log.append("🔐 [4/8] Construindo Proof of Possession JWT (Holder Binding)...")

        private_key = load_pem_private_key(
            holder_pem.encode(), password=None, backend=default_backend()
        )
        now_ts = int(time.time())

        proof_jwt = jose_jwt.encode(
            {
                "iss": holder_did,
                "aud": ISSUER_URL,
                "iat": now_ts,
                "exp": now_ts + 300,
                "nonce": c_nonce,
            },
            private_key,
            algorithm="ES256",
            headers={"typ": "openid4vci-proof+jwt", "jwk": holder_jwk},
        )

        simulation_log.append("📜 [5/8] Solicitando SD-JWT VC ao Issuer (Credential Endpoint)...")
        async with httpx.AsyncClient(timeout=10.0) as client:
            cred_resp = await client.post(
                f"{ISSUER_URL}/issuer/credential",
                json={
                    "format": "vc+sd-jwt",
                    "vct": "BraZKIL_AgeOver18",
                    "proof": {"proof_type": "jwt", "jwt": proof_jwt},
                },
                headers={"Authorization": f"Bearer {access_token}"},
            )

        if cred_resp.status_code != 200:
            return JSONResponse(status_code=502, content={
                "error": "Falha no credential endpoint",
                "detail": cred_resp.text,
                "log": simulation_log
            })

        cred_data = cred_resp.json()
        sd_jwt_full = cred_data["credential"]
        simulation_log.append(f"    → SD-JWT VC recebida ({len(sd_jwt_full)} chars)")

        # -------------------------------------------------------------------
        # PASSO 5: Gerar desafio OID4VP no Verifier
        # -------------------------------------------------------------------
        simulation_log.append("🎯 [6/8] Obtendo desafio OID4VP do Verifier (nonce)...")
        async with httpx.AsyncClient(timeout=10.0) as client:
            challenge_resp = await client.get(f"{VERIFIER_BASE_URL}/verifier/challenge")

        challenge = challenge_resp.json()
        session_id = challenge["session_id"]
        vp_nonce = challenge["nonce"]
        simulation_log.append(f"    → Session ID: {session_id}")
        simulation_log.append(f"    → VP Nonce: {vp_nonce[:16]}...")

        # -------------------------------------------------------------------
        # PASSO 6: Construir VP Token (SD-JWT VC + disclosure_age_over_18 + KB-JWT)
        # -------------------------------------------------------------------
        simulation_log.append("🏗️  [7/8] Construindo VP Token com Key Binding JWT...")

        # Separar partes do SD-JWT: jwt~disc_age~disc_birth
        sd_parts = sd_jwt_full.split("~")
        sd_jwt_token = sd_parts[0]
        # Divulgação Seletiva (Privacy by Design): Revelar estritamente o predicado age_over_18.
        # A data de nascimento (birthdate) PERMANECE OFUSCADA e NÃO é incluída na apresentação.
        disclosure_age = sd_parts[1] if len(sd_parts) > 1 else ""

        # Construir o prefixo do VP Token (SD-JWT + disclosure seletivo age_over_18 + trailing ~)
        selected_disclosures = [d for d in [disclosure_age] if d]
        vp_prefix = sd_jwt_token + "~" + "~".join(selected_disclosures) + "~"



        # Calcular sd_hash (SHA-256 do prefixo acima)
        sd_hash = _b64url_encode(hashlib.sha256(vp_prefix.encode("ascii")).digest())

        # Construir o Key Binding JWT
        kb_jwt = jose_jwt.encode(
            {
                "iss": holder_did,
                "aud": VERIFIER_BASE_URL,
                "iat": now_ts,
                "exp": now_ts + 300,
                "nonce": vp_nonce,
                "sd_hash": sd_hash,
            },
            private_key,
            algorithm="ES256",
            headers={"typ": "kb+jwt"},
        )

        # VP Token final: <SD-JWT>~<disc_age>~<disc_birth>~<KB-JWT>
        vp_token = vp_prefix + kb_jwt
        simulation_log.append(f"    → VP Token construído ({len(vp_token)} chars)")

        # -------------------------------------------------------------------
        # PASSO 7: Submeter VP Token ao Verifier
        # -------------------------------------------------------------------
        simulation_log.append("✅ [8/8] Submetendo VP Token ao Verifier para verificação completa...")
        async with httpx.AsyncClient(timeout=15.0) as client:
            verify_resp = await client.post(
                f"{VERIFIER_BASE_URL}/verifier/present",
                json={
                    "session_id": session_id,
                    "vp_token": vp_token,
                }
            )

        result = verify_resp.json()
        result["simulation_log"] = simulation_log
        result["holder_did"] = holder_did
        result["vp_token_preview"] = vp_token[:120] + "..."

        return JSONResponse(status_code=verify_resp.status_code, content=result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={
            "error": str(e),
            "log": simulation_log,
        })
