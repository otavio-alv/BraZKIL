"""
    Script de Teste de Ponta a Ponta para o Fluxo OID4VCI do Issuer BraZKIL.
    
    Este script simula a interação entre:
    1. O Portal do Titular (POST /issuer/issue)
    2. A Carteira Digital / Holder (POST /issuer/token e POST /issuer/credential)
    
    Requisitos prévios:
    - VDR rodando na porta 8001 (python -m uvicorn vdr.main:app --port 8001)
    - Validador Datavalid rodando na porta 8000 (python -m uvicorn validator_datavalid.main:app --port 8000)
    - Issuer rodando na porta 8002 (python -m uvicorn issuer.main:app --port 8002)
"""

import sys
import os
import httpx
from datetime import datetime, timezone, date
from jose import jwt as jose_jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from shared.did import generate_brazkil_did
from issuer.sd_jwt import verify_sd_jwt_vc
from issuer.main import app as issuer_app

ISSUER_URL = "http://127.0.0.1:8002"
VDR_URL = "http://127.0.0.1:8001"


def test_full_oid4vci_flow():
    print("=" * 60)
    print("🚀 INICIANDO TESTE DO FLUXO COMPLETO OID4VCI (BraZKIL)")
    print("=" * 60)

    client = TestClient(issuer_app)

    # -------------------------------------------------------------------------
    # Passo 0: Gerar uma identidade temporária para o Holder (Carteira)
    # -------------------------------------------------------------------------
    print("\n[HOLDER] Gerando par de chaves e DID do Holder para a carteira...")
    holder_identity = generate_brazkil_did("Holder Teste")
    holder_did = holder_identity["did"]
    holder_pem = holder_identity["private_key_pem"]
    holder_jwk = holder_identity["did_document"]["verificationMethod"][0]["publicKeyJwk"]
    print(f" -> Holder DID: {holder_did}")

    # -------------------------------------------------------------------------
    # Passo 1: Portal do Titular solicita a emissão (POST /issuer/issue)
    # -------------------------------------------------------------------------
    print("\n[PORTAL] 1. Solicitando emissão da credencial (dados cadastrais)...")
    issue_payload = {
        "cpf": "25774435016",
        "name": "Manuela Elisa da Mota",
        "birth_date": "1975-06-04"
    }

    resp = client.post("/issuer/issue", json=issue_payload)

    if resp.status_code != 201:
        print(f"❌ ERA ESPERADO HTTP 201 no /issuer/issue, MAS FOI {resp.status_code}: {resp.text}")
        return

    issue_data = resp.json()
    pre_auth_code = issue_data["pre_authorized_code"]
    offer_uri = issue_data["credential_offer_uri"]
    print(" ✅ Oferta gerada com sucesso!")
    print(f" -> Credential Offer URI: {offer_uri}")
    print(f" -> Pre-Authorized Code: {pre_auth_code}")

    # -------------------------------------------------------------------------
    # Passo 2: Carteira troca pre-authorized code por Access Token (POST /issuer/token)
    # -------------------------------------------------------------------------
    print("\n[WALLET] 2. Trocando Pre-Authorized Code por Access Token...")
    token_payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre_authorized_code": pre_auth_code
    }

    resp = client.post("/issuer/token", json=token_payload)

    if resp.status_code != 200:
        print(f"❌ FALHA NO /issuer/token (HTTP {resp.status_code}): {resp.text}")
        return

    token_data = resp.json()
    access_token = token_data["access_token"]
    c_nonce = token_data["c_nonce"]
    print(" ✅ Access Token e c_nonce obtidos!")
    print(f" -> Access Token: {access_token[:20]}...")
    print(f" -> c_nonce: {c_nonce}")

    # -------------------------------------------------------------------------
    # Passo 3: Carteira assina o Proof of Possession (JWT) com c_nonce
    # -------------------------------------------------------------------------
    print("\n[WALLET] 3. Construindo e assinando o Proof of Possession JWT (Holder Binding)...")
    private_key = load_pem_private_key(
        holder_pem.encode(),
        password=None,
        backend=default_backend()
    )

    proof_payload = {
        "iss": holder_did,
        "aud": ISSUER_URL,
        "nonce": c_nonce,
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }

    proof_jwt = jose_jwt.encode(
        proof_payload,
        private_key,
        algorithm="ES256",
        headers={
            "typ": "openid4vci-proof+jwt",
            "jwk": holder_jwk
        }
    )
    print(" ✅ Proof JWT assinado com a chave privada do Holder!")

    # -------------------------------------------------------------------------
    # Passo 4: Carteira solicita a SD-JWT VC (POST /issuer/credential)
    # -------------------------------------------------------------------------
    print("\n[WALLET] 4. Reclamando a SD-JWT VC no Credential Endpoint...")
    cred_request = {
        "format": "vc+sd-jwt",
        "credential_configuration_id": "BraZKIL_AgeOver18",
        "proof": {
            "proof_type": "jwt",
            "jwt": proof_jwt
        }
    }

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    resp = client.post("/issuer/credential", json=cred_request, headers=headers)

    if resp.status_code != 200:
        print(f"❌ FALHA NO /issuer/credential (HTTP {resp.status_code}): {resp.text}")
        return

    cred_data = resp.json()
    sd_jwt_vc = cred_data["credential"]
    print(" 🎉 SD-JWT VC ENTREGUE COM SUCESSO PELA CARTEIRA!")
    print(f" -> SD-JWT Serializado: {sd_jwt_vc[:60]}...")

    # -------------------------------------------------------------------------
    # Passo 5: Verificação offline da SD-JWT VC recebida
    # -------------------------------------------------------------------------
    print("\n[VERIFIER SIMULATION] 5. Validando a SD-JWT VC recebida...")
    # Resolver DID do Issuer para obter a chave pública de validação
    issuer_meta = client.get("/.well-known/openid-credential-issuer").json()
    issuer_did = issuer_meta["issuer_did"]

    with httpx.Client() as http_client:
        vdr_resp = http_client.get(f"{VDR_URL}/vdr/did/{issuer_did}")
        if vdr_resp.status_code != 200:
            print(" ⚠️ Não foi possível resolver o DID do Issuer no VDR (certifique-se de que o VDR está rodando)")
            return
        issuer_did_doc = vdr_resp.json()

    verification = verify_sd_jwt_vc(sd_jwt_vc, issuer_did_doc)
    print(" ✅ Assinatura Criptográfica do Issuer: VÁLIDA")
    print(f" -> Emissor (iss): {verification['issuer']}")
    print(f" -> Titular (sub): {verification['subject']}")
    print(f" -> Claims Revelados no SD-JWT: {verification['revealed_claims']}")

    print("\n" + "=" * 60)
    print(" SUCCESS: FLUXO COMPLETO OID4VCI VALIDADO COM SUCESSO!")
    print("=" * 60)


if __name__ == "__main__":
    test_full_oid4vci_flow()
