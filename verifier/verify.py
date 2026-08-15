"""
    verifier/verify.py — Núcleo Criptográfico de Verificação BraZKIL (OID4VP)

    Implementa o pipeline completo de verificação de uma Verifiable Presentation
    no formato SD-JWT VC + Key Binding JWT, conforme o modelo de ameaças do artigo.

    Pipeline de validação (4 etapas obrigatórias):
      1. Integridade e Origem: ES256 do Issuer via DID Document do VDR
      2. Status de Revogação: consulta ao VDR /vdr/credentials/status/{id}
      3. Integridade dos Disclosures: SHA-256 recalculado vs _sd do JWT
      4. Holder Binding JWT: ES256 com cnf.jwk + nonce + aud + exp

    Ameaças mitigadas (conforme Tabela 4 do artigo):
      - Credencial forjada → validação #1
      - Credencial revogada → validação #2
      - Disclosure falsificado → validação #3
      - Replay/Interceptação → validação #4
"""

import os
import sys
import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import httpx
from jose import jwt as jose_jwt
from jose.exceptions import JWTError
from jose import jwk as jose_jwk

from verifier.schema import VerificationResult, VerificationStep


# =============================================================================
# Helpers de decodificação Base64URL
# =============================================================================

def _b64url_decode(s: str) -> bytes:
    """Decodifica Base64URL com padding automático."""
    padding = "=" * (4 - len(s) % 4) if len(s) % 4 else ""
    return base64.urlsafe_b64decode(s + padding)


def _b64url_encode(data: bytes) -> str:
    """Codifica bytes em Base64URL sem padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _is_kb_jwt(segment: str) -> bool:
    """
    Determina se um segmento é um Key Binding JWT (3 partes separadas por ponto)
    ao invés de um disclosure (base64url puro sem pontos).
    """
    return segment.count(".") == 2


# =============================================================================
# Verificação Principal
# =============================================================================

def verify_presentation(
    vp_token: str,
    expected_nonce: str,
    verifier_url: str,
    vdr_url: str,
    expected_client_id: Optional[str] = None,
) -> VerificationResult:
    """
    Executa o pipeline completo de verificação de uma Verifiable Presentation.

    Args:
        vp_token:       SD-JWT serializado: <jwt>~<disc1>~...~<KB-JWT>
        expected_nonce: Nonce gerado pelo Verifier para esta sessão (anti-replay)
        verifier_url:   URL do Verifier (audiência esperada no Key Binding JWT do fluxo
                         /verifier/simulate, que constrói o KB-JWT manualmente)
        vdr_url:        URL base do VDR para resolver DIDs e consultar status
        expected_client_id: client_id (possivelmente prefixado, ex: 'decentralized_identifier:did:...')
                         enviado no Authorization Request OID4VP — carteiras reais usam esse valor
                         como audiência do KB-JWT, conforme a spec, em vez da URL simples.

    Returns:
        VerificationResult com o resultado de cada etapa e os claims revelados
    """
    steps: list[VerificationStep] = []
    revealed_claims: dict = {}
    holder_did: Optional[str] = None
    issuer_did: Optional[str] = None
    credential_id: Optional[str] = None

    # -------------------------------------------------------------------------
    # Fase 0: Parsing do VP Token
    # Formato: <SD-JWT>~<disclosure_1>~...~<KB-JWT>
    # O Key Binding JWT é sempre o ÚLTIMO segmento (se presente) e tem 3 partes.
    # -------------------------------------------------------------------------
    parts = vp_token.split("~")
    if len(parts) < 2:
        return VerificationResult(
            session_id="",
            approved=False,
            reason="VP Token malformado: não contém separador '~' esperado.",
            steps=[VerificationStep(step="parsing", passed=False,
                                    detail="VP Token deve ter formato: <SD-JWT>~<disclosures>~<KB-JWT>")],
        )

    sd_jwt_token = parts[0]
    remaining = parts[1:]

    # Identifica o Key Binding JWT (último segmento com 2 pontos)
    kb_jwt: Optional[str] = None
    disclosures: list[str] = []

    for seg in remaining:
        if seg and _is_kb_jwt(seg):
            kb_jwt = seg
        elif seg:
            disclosures.append(seg)

    # =========================================================================
    # ETAPA 1: Assinatura do Issuer (ES256 via VDR)
    # =========================================================================
    try:
        # 1a. Extrair issuer DID do JWT sem verificar (para resolver o DID no VDR)
        unverified = jose_jwt.get_unverified_claims(sd_jwt_token)
        issuer_did = unverified.get("iss")
        holder_did = unverified.get("sub")
        jti = unverified.get("jti", "")
        # jti formato: "urn:uuid:<credential_id>"
        credential_id = jti.replace("urn:uuid:", "") if jti.startswith("urn:uuid:") else jti

        if not issuer_did:
            steps.append(VerificationStep(
                step="1_issuer_signature",
                passed=False,
                detail="Campo 'iss' (DID do Issuer) ausente no JWT."
            ))
            return _fail(steps, "JWT sem claim 'iss'.", revealed_claims, holder_did, issuer_did, credential_id)

        # 1b. Resolver DID Document do Issuer no VDR
        with httpx.Client(timeout=5.0) as client:
            vdr_resp = client.get(f"{vdr_url}/vdr/did/{issuer_did}")

        if vdr_resp.status_code != 200:
            steps.append(VerificationStep(
                step="1_issuer_signature",
                passed=False,
                detail=f"DID do Issuer '{issuer_did}' não encontrado no VDR (HTTP {vdr_resp.status_code}). "
                       "O emissor pode não estar no Registro de Confiança."
            ))
            return _fail(steps, "Issuer DID não encontrado no VDR.", revealed_claims, holder_did, issuer_did, credential_id)

        did_document = vdr_resp.json().get("did_document", vdr_resp.json())

        # 1c. Extrair JWK pública do DID Document
        vm_list = did_document.get("verificationMethod", [])
        if not vm_list or not vm_list[0].get("publicKeyJwk"):
            steps.append(VerificationStep(
                step="1_issuer_signature",
                passed=False,
                detail="DID Document do Issuer não contém 'publicKeyJwk' no verificationMethod."
            ))
            return _fail(steps, "Chave pública do Issuer não encontrada no DID Document.", revealed_claims, holder_did, issuer_did, credential_id)

        issuer_jwk = vm_list[0]["publicKeyJwk"]
        issuer_public_key = jose_jwk.construct(issuer_jwk, algorithm="ES256")

        # 1d. Verificar assinatura ES256
        payload = jose_jwt.decode(
            sd_jwt_token,
            issuer_public_key,
            algorithms=["ES256"],
            options={"verify_exp": True, "verify_aud": False}
        )

        steps.append(VerificationStep(
            step="1_issuer_signature",
            passed=True,
            detail=f"Assinatura ES256 do Issuer '{issuer_did}' verificada com sucesso via DID Document do VDR."
        ))

    except JWTError as e:
        steps.append(VerificationStep(
            step="1_issuer_signature",
            passed=False,
            detail=f"Assinatura ES256 inválida ou JWT corrompido: {e}"
        ))
        return _fail(steps, f"Assinatura do Issuer inválida: {e}", revealed_claims, holder_did, issuer_did, credential_id)
    except Exception as e:
        steps.append(VerificationStep(
            step="1_issuer_signature",
            passed=False,
            detail=f"Erro ao verificar assinatura do Issuer: {e}"
        ))
        return _fail(steps, f"Erro na verificação do Issuer: {e}", revealed_claims, holder_did, issuer_did, credential_id)

    # =========================================================================
    # ETAPA 2: Status de Revogação (VDR Status List)
    # =========================================================================
    try:
        with httpx.Client(timeout=5.0) as client:
            status_resp = client.get(f"{vdr_url}/vdr/credentials/status/{credential_id}")

        if status_resp.status_code == 200:
            status_data = status_resp.json()
            cred_status = status_data.get("status", "NOT_FOUND")
            is_valid = status_data.get("is_valid", False)

            if not is_valid or cred_status not in ("ACTIVE",):
                steps.append(VerificationStep(
                    step="2_revocation_status",
                    passed=False,
                    detail=f"Credencial '{credential_id}' com status '{cred_status}' — não está ACTIVE no VDR."
                ))
                return _fail(steps, f"Credencial inválida no VDR (status: {cred_status}).", revealed_claims, holder_did, issuer_did, credential_id)

            steps.append(VerificationStep(
                step="2_revocation_status",
                passed=True,
                detail=f"Credencial '{credential_id}' está ACTIVE no VDR. Emissor qualificado e ativo."
            ))
        else:
            # Credencial não registrada no VDR — pode ser uma credencial forjada
            steps.append(VerificationStep(
                step="2_revocation_status",
                passed=False,
                detail=f"Credencial '{credential_id}' não encontrada na Status List do VDR (HTTP {status_resp.status_code}). "
                       "A credencial pode não ter sido emitida por este sistema ou já foi removida."
            ))
            return _fail(steps, "Credencial não encontrada no VDR.", revealed_claims, holder_did, issuer_did, credential_id)

    except Exception as e:
        steps.append(VerificationStep(
            step="2_revocation_status",
            passed=False,
            detail=f"VDR indisponível para consulta de status: {e}"
        ))
        return _fail(steps, f"Erro ao consultar status no VDR: {e}", revealed_claims, holder_did, issuer_did, credential_id)

    # =========================================================================
    # ETAPA 3: Integridade dos Disclosures (SHA-256 vs _sd)
    # =========================================================================
    try:
        sd_hashes = payload.get("_sd", [])
        if not sd_hashes:
            steps.append(VerificationStep(
                step="3_disclosure_integrity",
                passed=False,
                detail="JWT não contém campo '_sd'. Não é uma SD-JWT VC válida."
            ))
            return _fail(steps, "SD-JWT sem campo '_sd'.", revealed_claims, holder_did, issuer_did, credential_id)

        if not disclosures:
            steps.append(VerificationStep(
                step="3_disclosure_integrity",
                passed=False,
                detail="Nenhum disclosure foi apresentado. O claim 'age_over_18' é obrigatório."
            ))
            return _fail(steps, "Nenhum disclosure apresentado.", revealed_claims, holder_did, issuer_did, credential_id)

        for disc_b64 in disclosures:
            # Recalcular hash SHA-256 do disclosure e verificar contra o _sd
            digest_bytes = hashlib.sha256(disc_b64.encode("ascii")).digest()
            hash_b64 = _b64url_encode(digest_bytes)

            if hash_b64 not in sd_hashes:
                steps.append(VerificationStep(
                    step="3_disclosure_integrity",
                    passed=False,
                    detail=f"Disclosure com hash '{hash_b64}' não encontrado no '_sd' do JWT. "
                           "Possível falsificação de disclosure!"
                ))
                return _fail(steps, "Disclosure com hash inválido — possível falsificação!", revealed_claims, holder_did, issuer_did, credential_id)

            # Decodificar e extrair o claim revelado
            disc_json = _b64url_decode(disc_b64).decode("utf-8")
            _salt, claim_name, claim_value = json.loads(disc_json)
            revealed_claims[claim_name] = claim_value

        steps.append(VerificationStep(
            step="3_disclosure_integrity",
            passed=True,
            detail=f"Todos os {len(disclosures)} disclosure(s) verificados com sucesso. "
                   f"Claims revelados: {list(revealed_claims.keys())}."
        ))

        # Verificar o predicado de maioridade
        age_over_18 = revealed_claims.get("age_over_18")
        if age_over_18 is not True:
            steps.append(VerificationStep(
                step="3_disclosure_integrity",
                passed=False,
                detail=f"Claim 'age_over_18' é '{age_over_18}' — acesso negado (requer True)."
            ))
            return _fail(steps, "Titular não é maior de 18 anos.", revealed_claims, holder_did, issuer_did, credential_id)

    except Exception as e:
        steps.append(VerificationStep(
            step="3_disclosure_integrity",
            passed=False,
            detail=f"Erro ao processar disclosures: {e}"
        ))
        return _fail(steps, f"Erro ao verificar disclosures: {e}", revealed_claims, holder_did, issuer_did, credential_id)

    # =========================================================================
    # ETAPA 4: Key Binding JWT — Prova de Posse (Holder Binding)
    # Mitigação de Replay Attack e Interceptação
    # =========================================================================
    if not kb_jwt:
        steps.append(VerificationStep(
            step="4_holder_binding",
            passed=False,
            detail="Key Binding JWT ausente no VP Token. A prova de posse da chave é obrigatória "
                   "para mitigar ataques de replay e interceptação (conforme modelo de ameaças BraZKIL)."
        ))
        return _fail(steps, "Key Binding JWT ausente — replay attack possível!", revealed_claims, holder_did, issuer_did, credential_id)

    try:
        # 4a. Extrair JWK pública do claim 'cnf' do SD-JWT (vinculada pelo Issuer no momento da emissão)
        cnf = payload.get("cnf", {})
        holder_jwk_dict = cnf.get("jwk")
        if not holder_jwk_dict:
            steps.append(VerificationStep(
                step="4_holder_binding",
                passed=False,
                detail="Campo 'cnf.jwk' ausente no SD-JWT — Holder Binding não pode ser verificado."
            ))
            return _fail(steps, "cnf.jwk ausente no SD-JWT.", revealed_claims, holder_did, issuer_did, credential_id)

        # 4b. Construir chave pública do Holder a partir da JWK do cnf
        holder_public_key = jose_jwk.construct(holder_jwk_dict, algorithm="ES256")

        # 4c. Verificar assinatura ES256 do Key Binding JWT com a chave do Holder
        kb_payload = jose_jwt.decode(
            kb_jwt,
            holder_public_key,
            algorithms=["ES256"],
            options={"verify_exp": True, "verify_aud": False}
        )

        # 4d. Verificar nonce (anti-replay — o nonce deve corresponder ao desafio desta sessão)
        kb_nonce = kb_payload.get("nonce")
        if kb_nonce != expected_nonce:
            steps.append(VerificationStep(
                step="4_holder_binding",
                passed=False,
                detail=f"Nonce do Key Binding JWT ('{kb_nonce}') não corresponde ao desafio "
                       f"da sessão ('{expected_nonce}'). Possível ataque de replay!"
            ))
            return _fail(steps, "Nonce inválido — possível replay attack!", revealed_claims, holder_did, issuer_did, credential_id)

        # 4e. Verificar audiência (aud) — deve ser este Verifier: aceita tanto a URL simples
        # (usada pelo fluxo /verifier/simulate, que monta o KB-JWT manualmente) quanto o
        # client_id (possivelmente prefixado) enviado no Authorization Request OID4VP, que é
        # o valor que carteiras reais (ex: walt.id) usam como audiência conforme a spec.
        kb_aud = kb_payload.get("aud")
        valid_audiences = {verifier_url}
        if expected_client_id:
            valid_audiences.add(expected_client_id)
        if kb_aud not in valid_audiences:
            steps.append(VerificationStep(
                step="4_holder_binding",
                passed=False,
                detail=f"Audiência do Key Binding JWT ('{kb_aud}') não corresponde a este "
                       f"Verifier ({sorted(valid_audiences)}). Possível credential redirect!"
            ))
            return _fail(steps, "Audiência (aud) do KB-JWT inválida!", revealed_claims, holder_did, issuer_did, credential_id)

        # 4f. Verificar hash do SD-JWT no kb_jwt (sd_hash — binding criptográfico ao SD-JWT apresentado)
        # O kb_payload deve conter "sd_hash" = base64url(sha256(SD-JWT sem KB-JWT))
        expected_sd_hash = _b64url_encode(
            hashlib.sha256(
                # O hash cobre tudo até e incluindo o último "~" antes do KB-JWT
                (sd_jwt_token + "~" + "~".join(disclosures) + "~").encode("ascii")
            ).digest()
        )
        kb_sd_hash = kb_payload.get("sd_hash")
        if kb_sd_hash and kb_sd_hash != expected_sd_hash:
            steps.append(VerificationStep(
                step="4_holder_binding",
                passed=False,
                detail="sd_hash do Key Binding JWT não corresponde ao SD-JWT apresentado. "
                       "Possível substituição de credencial!"
            ))
            return _fail(steps, "sd_hash inválido no KB-JWT!", revealed_claims, holder_did, issuer_did, credential_id)

        steps.append(VerificationStep(
            step="4_holder_binding",
            passed=True,
            detail=f"Key Binding JWT verificado com sucesso. Nonce '{kb_nonce}' e audiência '{kb_aud}' válidos. "
                   "Prova de posse da chave confirmada — nenhum replay attack detectado."
        ))

    except JWTError as e:
        steps.append(VerificationStep(
            step="4_holder_binding",
            passed=False,
            detail=f"Assinatura do Key Binding JWT inválida (ES256): {e}"
        ))
        return _fail(steps, f"Key Binding JWT com assinatura inválida: {e}", revealed_claims, holder_did, issuer_did, credential_id)
    except Exception as e:
        steps.append(VerificationStep(
            step="4_holder_binding",
            passed=False,
            detail=f"Erro ao verificar Key Binding JWT: {e}"
        ))
        return _fail(steps, f"Erro no Holder Binding: {e}", revealed_claims, holder_did, issuer_did, credential_id)

    # =========================================================================
    # TODAS AS ETAPAS PASSARAM — Acesso Aprovado
    # =========================================================================
    return VerificationResult(
        session_id="",
        approved=True,
        reason="Verificação completa com sucesso. Titular confirmado como maior de 18 anos.",
        steps=steps,
        revealed_claims=revealed_claims,
        holder_did=holder_did,
        issuer_did=issuer_did,
        credential_id=credential_id,
    )


# =============================================================================
# Helper: Retorno de Falha com Steps Acumulados
# =============================================================================

def _fail(
    steps: list,
    reason: str,
    revealed_claims: dict,
    holder_did: Optional[str],
    issuer_did: Optional[str],
    credential_id: Optional[str],
) -> VerificationResult:
    """Monta um VerificationResult de falha com os steps já executados."""
    return VerificationResult(
        session_id="",
        approved=False,
        reason=reason,
        steps=steps,
        revealed_claims=revealed_claims if revealed_claims else None,
        holder_did=holder_did,
        issuer_did=issuer_did,
        credential_id=credential_id,
    )
