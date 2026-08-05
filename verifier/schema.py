"""
    verifier/schema.py — Modelos Pydantic do Serviço Verificador BraZKIL (OID4VP)

    Define os contratos de entrada/saída para:
      - Desafio de Apresentação (Presentation Request) enviado pelo Verifier ao Holder
      - VP Token recebido do Holder
      - Resultado da verificação com detalhes de cada etapa de validação
"""

from typing import Optional, List, Any
from pydantic import BaseModel


# =============================================================================
# 1. Apresentação OID4VP — Desafio (Challenge)
# =============================================================================

class PresentationDefinitionField(BaseModel):
    """Descreve um campo solicitado na Presentation Definition (OID4VP)."""
    path: List[str]
    filter: Optional[dict] = None


class PresentationDefinitionConstraint(BaseModel):
    fields: List[PresentationDefinitionField]


class PresentationDefinitionDescriptor(BaseModel):
    id: str
    format: str
    constraints: PresentationDefinitionConstraint


class PresentationDefinition(BaseModel):
    """Presentation Definition conforme DIF PE Spec v2."""
    id: str
    input_descriptors: List[PresentationDefinitionDescriptor]


class PresentationRequest(BaseModel):
    """
    Desafio gerado pelo Verifier para o Holder.
    Conforme OID4VP (draft-ietf-oauth-v2-1-11 + DIF Presentation Exchange).
    """
    session_id: str
    response_type: str = "vp_token"
    response_mode: str = "direct_post"
    client_id: str           # URL do Verifier (aud esperado no KB-JWT)
    nonce: str               # Desafio único (anti-replay)
    presentation_definition: PresentationDefinition


# =============================================================================
# 2. Resposta do Holder — VP Token (Verifiable Presentation)
# =============================================================================

class PresentationDescriptorMap(BaseModel):
    """Mapeia um Verifiable Credential dentro do VP Token (Presentation Submission)."""
    id: str
    format: str
    path: str


class PresentationSubmission(BaseModel):
    """Metadados da apresentação conforme DIF PE v2."""
    id: str
    definition_id: str
    descriptor_map: List[PresentationDescriptorMap]


class VerifierPresentationPayload(BaseModel):
    """
    Payload enviado pelo Holder (ou pela UI da loja) ao endpoint POST /verifier/present.
    O vp_token deve ser um SD-JWT serializado no formato:
        <header>.<payload>.<sig>~<disclosure_age_over_18>~<KB-JWT>
    """
    session_id: str
    vp_token: str                                     # SD-JWT VC + KB-JWT serializado
    presentation_submission: Optional[Any] = None     # Metadados DIF PE (opcional na PoC)


# =============================================================================
# 3. Resultado da Verificação
# =============================================================================

class VerificationStep(BaseModel):
    """Detalha uma etapa individual da pipeline de verificação."""
    step: str
    passed: bool
    detail: str


class VerificationResult(BaseModel):
    """
    Resultado completo da verificação de uma Verifiable Presentation.
    Retornado pelo endpoint POST /verifier/present e consultável via GET /verifier/session/{id}.
    """
    session_id: str
    approved: bool
    reason: str
    steps: List[VerificationStep]
    revealed_claims: Optional[dict] = None   # Claims revelados (age_over_18, etc.)
    holder_did: Optional[str] = None
    issuer_did: Optional[str] = None
    credential_id: Optional[str] = None


# =============================================================================
# 4. Modelos de Estado de Sessão (em memória)
# =============================================================================

class SessionState(BaseModel):
    """Estado em memória de uma sessão de verificação OID4VP."""
    session_id: str
    nonce: str
    status: str = "PENDING"      # PENDING | APPROVED | DENIED
    result: Optional[VerificationResult] = None
