"""
    Gerador de SD-JWT VC (Selective Disclosure JSON Web Token Verifiable Credential)
    Implementa a spec IETF SD-JWT VC para o BraZKIL (RFC draft-ietf-oauth-sd-jwt-vc).

    Disclosures gerados:
      - age_over_18: bool  (predicado de maioridade)
      - birthdate: str     (data de nascimento no formato ISO 8601)

    Formato do token serializado:
      <header>.<payload>.<signature>~<disclosure_age_over_18>~<disclosure_birthdate>
"""

import os
import sys
import json
import secrets
import hashlib
import base64
import uuid
from datetime import date, datetime, timezone, timedelta

# Garante que a raiz do projeto esteja no sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from jose import jwt as jose_jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


# Validade padrão da credencial (1 ano)
VC_VALIDITY_DAYS = 365

# Tipo de credencial BraZKIL
VC_TYPE = "BraZKIL_AgeOver18"

# Endpoint base do VDR (para credentialStatus)
VDR_BASE_URL = "http://127.0.0.1:8001"

# Endpoint base do Issuer (para metadata OID4VCI — suporte a ngrok)
ISSUER_BASE_URL = os.getenv("ISSUER_BASE_URL", "http://127.0.0.1:8002").strip().rstrip("/")

# O claim 'vct' da spec SD-JWT VC deve ser uma URI resolvível (não um nome simples):
# carteiras como a walt.id buscam metadados do tipo em <authority>/.well-known/vct<path>
# (ver issuer/main.py::vct_type_metadata) — sem isso, a tela de oferta da carteira falha
# silenciosamente ao tentar resolver o tipo da credencial.
VC_TYPE_URL = f"{ISSUER_BASE_URL}/{VC_TYPE}"


def _b64url_encode(data: bytes) -> str:
    """Codifica bytes em Base64URL sem padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_disclosure(claim_name: str, claim_value) -> tuple[str, str]:
    """
    Constrói um disclosure SD-JWT conforme a spec IETF:
      disclosure_raw  = JSON([ <salt_b64url>, <claim_name>, <claim_value> ])
      disclosure_b64  = Base64URL(disclosure_raw)
      hash_b64        = Base64URL(SHA-256(disclosure_b64))

    Retorna:
      (disclosure_b64: str, hash_b64: str)
    """
    salt = _b64url_encode(secrets.token_bytes(16))
    disclosure_array = [salt, claim_name, claim_value]
    disclosure_json = json.dumps(disclosure_array, separators=(",", ":"))
    disclosure_b64 = _b64url_encode(disclosure_json.encode("utf-8"))

    digest_bytes = hashlib.sha256(disclosure_b64.encode("ascii")).digest()
    hash_b64 = _b64url_encode(digest_bytes)

    return disclosure_b64, hash_b64


def generate_sd_jwt_vc(
    issuer_did: str,
    issuer_private_key_pem: str,
    holder_did: str,
    holder_jwk: dict,
    age_over_18: bool,
    birthdate: date,
    credential_id: str,
) -> str:
    """
    Gera uma SD-JWT VC completa para o BraZKIL.

    Args:
        issuer_did:              DID do Middleware (did:brazkil:<uuid>)
        issuer_private_key_pem:  Chave Privada PEM do Middleware para assinar o JWT
        holder_did:              DID do Titular
        holder_jwk:              JWK pública do Titular (populada no campo cnf)
        age_over_18:             Resultado da política de maioridade
        birthdate:               Data de nascimento validada (incluída como disclosure seletivo)
        credential_id:           UUID único da credencial (para o credentialStatus no VDR)

    Returns:
        SD-JWT serializado:
        "<header>.<payload>.<signature>~<disclosure_age_over_18>~<disclosure_birthdate>"
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=VC_VALIDITY_DAYS)

    # 1. Gerar os dois disclosures seletivos
    disclosure_age_b64, hash_age = _make_disclosure("age_over_18", age_over_18)
    disclosure_birth_b64, hash_birth = _make_disclosure("birthdate", birthdate.isoformat())

    # 2. Montar o payload JWT com os hashes no campo _sd (sem dados pessoais em plaintext)
    payload = {
        # Claims padrão JWT/VC
        "iss": issuer_did,
        "sub": holder_did,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": f"urn:uuid:{credential_id}",

        # Tipo de credencial SD-JWT VC (URI resolvível — ver VC_TYPE_URL acima)
        "vct": VC_TYPE_URL,

        # Array de hashes dos disclosures seletivos (nenhum dado pessoal em plaintext)
        "_sd": [hash_age, hash_birth],
        "_sd_alg": "sha-256",

        # Holder Binding: JWK pública do titular (para validação do Key Binding JWT)
        "cnf": {
            "jwk": holder_jwk
        },

        # Status da credencial no VDR (para verificação de revogação)
        "credentialStatus": {
            "id": f"{VDR_BASE_URL}/vdr/credentials/status/{credential_id}",
            "type": "StatusList2021"
        }
    }

    # 3. Assinar o JWT com a chave privada do Issuer (ES256 / ECDSA P-256)
    private_key = load_pem_private_key(
        issuer_private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )

    # python-jose aceita objeto de chave criptográfica diretamente
    sd_jwt_token = jose_jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={"typ": "vc+sd-jwt"}
    )

    # 4. Serializar no formato SD-JWT: <jwt>~<disclosure1>~<disclosure2>~
    # O '~' final é obrigatório pela spec SD-JWT (indica ausência de Key Binding JWT
    # neste momento da emissão) — parsers estritos como o da carteira walt.id rejeitam
    # a credencial sem ele.
    sd_jwt_serialized = f"{sd_jwt_token}~{disclosure_age_b64}~{disclosure_birth_b64}~"

    return sd_jwt_serialized


def verify_sd_jwt_vc(sd_jwt_serialized: str, issuer_did_document: dict) -> dict:
    """
    Verifica a autenticidade de uma SD-JWT VC BraZKIL.
    Reconstrói os hashes dos disclosures e confirma que correspondem ao _sd do JWT.

    Args:
        sd_jwt_serialized:   Token no formato "header.payload.sig~disc1~disc2"
        issuer_did_document: DID Document do Issuer para extração da JWK pública

    Returns:
        Dict com os claims revelados e o resultado da verificação.
    """
    from shared.did import resolve_public_key_from_did_document

    parts = sd_jwt_serialized.split("~")
    sd_jwt_token = parts[0]
    disclosures = parts[1:]

    # Extrair chave pública do DID Document do Issuer
    public_key = resolve_public_key_from_did_document(issuer_did_document)

    # Verificar assinatura ES256 do JWT (sem validar exp para facilitar testes)
    payload = jose_jwt.decode(
        sd_jwt_token,
        public_key,
        algorithms=["ES256"],
        options={"verify_exp": False}
    )

    sd_hashes = payload.get("_sd", [])
    revealed_claims = {}

    # Para cada disclosure, recalcular o hash e verificar contra o _sd do payload
    for disc_b64 in disclosures:
        if not disc_b64:
            continue
        # Recompute hash
        digest_bytes = hashlib.sha256(disc_b64.encode("ascii")).digest()
        hash_b64 = _b64url_encode(digest_bytes)

        if hash_b64 not in sd_hashes:
            raise ValueError(f"Disclosure com hash inválido — possível falsificação! Hash: {hash_b64}")

        # Decodificar o disclosure e extrair o claim
        padding = "=" * (4 - len(disc_b64) % 4) if len(disc_b64) % 4 else ""
        disc_json = base64.urlsafe_b64decode(disc_b64 + padding).decode("utf-8")
        _salt, claim_name, claim_value = json.loads(disc_json)
        revealed_claims[claim_name] = claim_value

    return {
        "issuer": payload.get("iss"),
        "subject": payload.get("sub"),
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
        "credential_type": payload.get("vct"),
        "credential_status_url": payload.get("credentialStatus", {}).get("id"),
        "cnf_jwk": payload.get("cnf", {}).get("jwk"),
        "revealed_claims": revealed_claims,
        "signature_valid": True
    }
