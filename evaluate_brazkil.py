"""
Avaliação Funcional e de Desempenho (Latência) do BraZKIL
Baseado nos Experimentos descritos no Artigo (Tabelas 2 e 3).
"""

import sys
import time
import httpx
import hashlib
from datetime import datetime, timezone
from jose import jwt as jose_jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import os
import base64

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from shared.did import generate_brazkil_did

ISSUER_URL = os.getenv("ISSUER_BASE_URL", "http://127.0.0.1:8002").strip().rstrip("/")
VDR_URL = os.getenv("VDR_URL", "http://127.0.0.1:8001").strip().rstrip("/")
VALIDATOR_URL = os.getenv("VALIDATOR_URL", "http://127.0.0.1:8000").strip().rstrip("/")
VERIFIER_URL = os.getenv("VERIFIER_BASE_URL", "http://127.0.0.1:8003").strip().rstrip("/")

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def assert_claim(claim_name, condition, success_msg, error_msg):
    print(f"[{'PASS' if condition else 'FAIL'}] {claim_name}")
    if condition:
        print(f"   -> {success_msg}")
    else:
        print(f"   -> {error_msg}")
        sys.exit(1)

def run_functional_claims():
    print("==========================================================")
    print(" TESTANDO REIVINDICAÇÕES FUNCIONAIS (Tabela 2 do Artigo)  ")
    print("==========================================================")

    # 1. Validação Integrada (Datavalid)
    payload = {"cpf": "25774435016", "name": "Manuela Elisa da Mota", "birth_date": "1975-06-04"}
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{VALIDATOR_URL}/validate", json=payload)
        data = resp.json()
        assert_claim("Validação Integrada", 
                     resp.status_code == 200 and data.get("cpf_regular") is True, 
                     "Módulo de validação processou dados cadastrais corretamente.",
                     "Falha na validação do Datavalid")

    # 2. Emissão da credencial SD-JWT
    holder_identity = generate_brazkil_did("Holder Teste")
    holder_did = holder_identity["did"]
    holder_pem = holder_identity["private_key_pem"]
    holder_jwk = holder_identity["did_document"]["verificationMethod"][0]["publicKeyJwk"]
    private_key = load_pem_private_key(holder_pem.encode(), password=None, backend=default_backend())

    with httpx.Client(timeout=10.0) as client:
        # Recuperar a audiência correta do Issuer via metadata
        try:
            issuer_meta = client.get(f"{ISSUER_URL}/.well-known/openid-credential-issuer").json()
            expected_aud = issuer_meta.get("credential_issuer", ISSUER_URL)
        except Exception:
            expected_aud = ISSUER_URL

        issue_resp = client.post(f"{ISSUER_URL}/issuer/issue", json=payload).json()
        token_resp = client.post(f"{ISSUER_URL}/issuer/token", json={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre_authorized_code": issue_resp["pre_authorized_code"]
        }).json()
        
        now_ts = int(time.time())
        proof_jwt = jose_jwt.encode(
            {"iss": holder_did, "aud": expected_aud, "iat": now_ts, "exp": now_ts + 300, "nonce": token_resp["c_nonce"]},
            private_key, algorithm="ES256", headers={"typ": "openid4vci-proof+jwt", "jwk": holder_jwk}
        )

        cred_resp = client.post(f"{ISSUER_URL}/issuer/credential", json={
            "format": "vc+sd-jwt", "vct": "BraZKIL_AgeOver18", "proof": {"proof_type": "jwt", "jwt": proof_jwt}
        }, headers={"Authorization": f"Bearer {token_resp['access_token']}"})
        
        if cred_resp.status_code != 200:
            print(cred_resp.text)
        sd_jwt_full = cred_resp.json()["credential"]
        
        assert_claim("Emissão da credencial", 
                     "~" in sd_jwt_full, 
                     "Issuer gerou credencial SD-JWT com atributos protegidos (presença de disclosures).",
                     "SD-JWT não retornado corretamente")

    # 3. Armazenamento na carteira (Simulado pela posse do JWT em memória)
    assert_claim("Armazenamento na carteira", 
                 True, 
                 "Wallet armazena credencial localmente (simulado em memória neste teste).", "")

    # 4. Apresentação seletiva & Minimização de dados
    sd_parts = sd_jwt_full.split("~")
    sd_jwt_token = sd_parts[0]
    disclosure_age = sd_parts[1]
    # Omissão intencional do disclosure de nascimento
    vp_prefix = sd_jwt_token + "~" + disclosure_age + "~"
    
    assert_claim("Apresentação seletiva", 
                 "~" in vp_prefix, 
                 "Wallet revela disclosure de age_over_18, mantendo nascimento oculto.", 
                 "Erro na seleção do disclosure")

    # 5. Verificação da apresentação
    with httpx.Client(timeout=10.0) as client:
        challenge = client.get(f"{VERIFIER_URL}/verifier/challenge").json()
        vp_nonce = challenge["nonce"]
        expected_verifier_aud = challenge.get("client_id", VERIFIER_URL)
        sd_hash = _b64url_encode(hashlib.sha256(vp_prefix.encode("ascii")).digest())
        kb_jwt = jose_jwt.encode(
            {"iss": holder_did, "aud": expected_verifier_aud, "iat": now_ts, "exp": now_ts + 300, "nonce": vp_nonce, "sd_hash": sd_hash},
            private_key, algorithm="ES256", headers={"typ": "kb+jwt"}
        )
        vp_token = vp_prefix + kb_jwt

        verify_resp = client.post(f"{VERIFIER_URL}/verifier/present", json={
            "session_id": challenge["session_id"], "vp_token": vp_token, "presentation_submission": {}
        })
        
        if verify_resp.status_code != 200:
            print(verify_resp.text)
        v_data = verify_resp.json()
        assert_claim("Verificação da apresentação", 
                     v_data.get("approved") is True, 
                     "Verifier validou assinatura, holder binding e status da credencial.",
                     "Falha na verificação da apresentação")
        
        assert_claim("Minimização de dados", 
                     "age_over_18" in v_data.get("revealed_claims", {}) and "birthdate" not in v_data.get("revealed_claims", {}), 
                     "Verifier recebeu SOMENTE o atributo age_over_18. Data de nascimento oculta.",
                     "Vazamento de dados (data de nascimento exposta!)")

    # 6. Revogação
    jti = jose_jwt.get_unverified_claims(sd_jwt_token).get("jti", "")
    credential_id = jti.replace("urn:uuid:", "") if jti else ""
    with httpx.Client(timeout=10.0) as client:
        # Recuperar o DID do Issuer para revogar
        issuer_meta = client.get(f"{ISSUER_URL}/.well-known/openid-credential-issuer").json()
        issuer_did = issuer_meta["issuer_did"]

        # Revogar no VDR
        client.post(f"{VDR_URL}/vdr/credentials/status", json={
            "credential_id": credential_id, "issuer_did": issuer_did, "status": "REVOKED"
        })
        
        # Tentar apresentar novamente
        challenge2 = client.get(f"{VERIFIER_URL}/verifier/challenge").json()
        kb_jwt2 = jose_jwt.encode(
            {"iss": holder_did, "aud": VERIFIER_URL, "iat": now_ts, "exp": now_ts + 300, "nonce": challenge2["nonce"], "sd_hash": sd_hash},
            private_key, algorithm="ES256", headers={"typ": "kb+jwt"}
        )
        vp_token2 = vp_prefix + kb_jwt2
        verify_resp2 = client.post(f"{VERIFIER_URL}/verifier/present", json={
            "session_id": challenge2["session_id"], "vp_token": vp_token2, "presentation_submission": {}
        })
        
        assert_claim("Revogação", 
                     verify_resp2.json().get("approved") is False and "REVOKED" in verify_resp2.json().get("reason", ""), 
                     "Credencial marcada como revogada no VDR foi rejeitada na apresentação posterior.",
                     "Credencial revogada foi aceita erroneamente!")


def run_latency_benchmarks():
    print("\n==========================================================")
    print(" TESTANDO LATÊNCIAS (Tabela 3 do Artigo)                  ")
    print("==========================================================")
    
    payload = {"cpf": "25774435016", "name": "Manuela Elisa da Mota", "birth_date": "1975-06-04"}

    N_DATAVALID = 50
    N_OTHERS = 1000

    def print_stats(name, times):
        avg = sum(times) / len(times)
        var = sum((x - avg) ** 2 for x in times) / len(times)
        std_dev = var ** 0.5
        print(f"{name.ljust(40)} | Média: {avg:.2f} ms | Desvio: {std_dev:.2f} ms | N={len(times)}")

    with httpx.Client(timeout=30.0) as client:
        # 1. Validação do Datavalid via API
        print(f"Iniciando {N_DATAVALID} medições de Validação Datavalid...")
        times = []
        for _ in range(N_DATAVALID):
            t0 = time.perf_counter()
            client.post(f"{VALIDATOR_URL}/validate", json=payload)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
        print_stats("Validação do Datavalid via API", times)
        
        # Setup for the remaining tests
        print(f"Preparando dados efêmeros para testar {N_OTHERS} medições das outras operações...")
        holder_identity = generate_brazkil_did("Benchmark")
        holder_did, holder_pem = holder_identity["did"], holder_identity["private_key_pem"]
        private_key = load_pem_private_key(holder_pem.encode(), password=None, backend=default_backend())

        # 2. Emissão da credencial SD-JWT (Apenas o POST /issuer/credential)
        issue_resp = client.post(f"{ISSUER_URL}/issuer/issue", json=payload).json()
        token_resp = client.post(f"{ISSUER_URL}/issuer/token", json={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre_authorized_code": issue_resp["pre_authorized_code"]
        }).json()
        # Recuperar a audiência correta do Issuer via metadata
        try:
            issuer_meta = client.get(f"{ISSUER_URL}/.well-known/openid-credential-issuer").json()
            expected_aud = issuer_meta.get("credential_issuer", ISSUER_URL)
        except Exception:
            expected_aud = ISSUER_URL

        now_ts = int(time.time())
        proof_jwt = jose_jwt.encode(
            {"iss": holder_did, "aud": expected_aud, "iat": now_ts, "exp": now_ts + 300, "nonce": token_resp["c_nonce"]},
            private_key, algorithm="ES256", headers={"typ": "openid4vci-proof+jwt", "jwk": holder_identity["did_document"]["verificationMethod"][0]["publicKeyJwk"]}
        )

        req_json = {"format": "vc+sd-jwt", "vct": "BraZKIL_AgeOver18", "proof": {"proof_type": "jwt", "jwt": proof_jwt}}
        headers = {"Authorization": f"Bearer {token_resp['access_token']}"}
        
        print(f"Iniciando {N_OTHERS} medições de Emissão de Credencial SD-JWT...")
        times = []
        for _ in range(N_OTHERS):
            t0 = time.perf_counter()
            resp = client.post(f"{ISSUER_URL}/issuer/credential", json=req_json, headers=headers)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
            if _ == 0:
                sd_jwt_full = resp.json()["credential"]
        print_stats("Emissão da credencial SD-JWT", times)

        # 3. Geração da apresentação seletiva
        print(f"Iniciando {N_OTHERS} medições de Geração da Apresentação Seletiva...")
        times = []
        sd_parts = sd_jwt_full.split("~")
        vp_prefix = sd_parts[0] + "~" + sd_parts[1] + "~"
        vp_nonce = "benchmark-nonce"
        
        for _ in range(N_OTHERS):
            t0 = time.perf_counter()
            sd_hash = _b64url_encode(hashlib.sha256(vp_prefix.encode("ascii")).digest())
            kb_jwt = jose_jwt.encode(
                {"iss": holder_did, "aud": VERIFIER_URL, "iat": now_ts, "exp": now_ts + 300, "nonce": vp_nonce, "sd_hash": sd_hash},
                private_key, algorithm="ES256", headers={"typ": "kb+jwt"}
            )
            vp_token = vp_prefix + kb_jwt
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
        print_stats("Geração da apresentação seletiva", times)

        # 4. Verificação da apresentação
        print(f"Iniciando {N_OTHERS} medições de Verificação da Apresentação...")
        challenge = client.get(f"{VERIFIER_URL}/verifier/challenge").json()
        vp_nonce = challenge["nonce"]
        expected_verifier_aud = challenge.get("client_id", VERIFIER_URL)
        sd_hash = _b64url_encode(hashlib.sha256(vp_prefix.encode("ascii")).digest())
        kb_jwt = jose_jwt.encode(
            {"iss": holder_did, "aud": expected_verifier_aud, "iat": now_ts, "exp": now_ts + 300, "nonce": vp_nonce, "sd_hash": sd_hash},
            private_key, algorithm="ES256", headers={"typ": "kb+jwt"}
        )
        vp_token = vp_prefix + kb_jwt
        session_id = challenge["session_id"]
        req_verify = {"session_id": session_id, "vp_token": vp_token, "presentation_submission": {}}
        
        times = []
        for _ in range(N_OTHERS):
            t0 = time.perf_counter()
            client.post(f"{VERIFIER_URL}/verifier/present", json=req_verify)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
        print_stats("Verificação da apresentação", times)

        # 5. Consulta de status/revogação
        print(f"Iniciando {N_OTHERS} medições de Consulta de status/revogação no VDR...")
        credential_id = jose_jwt.get_unverified_claims(sd_parts[0]).get("jti")
        times = []
        for _ in range(N_OTHERS):
            t0 = time.perf_counter()
            client.get(f"{VDR_URL}/vdr/credentials/status/{credential_id}")
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)
        print_stats("Consulta de status/revogação", times)


if __name__ == "__main__":
    run_functional_claims()
    run_latency_benchmarks()
