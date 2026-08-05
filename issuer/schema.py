"""
    Schemas Pydantic do Issuer (Middleware BraZKIL)
    Define os modelos de entrada/saída dos endpoints OID4VCI.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import date


# -----------------------------------------------------------------------------
# 1. Requisição de Emissão (POST /issuer/issue)
# -----------------------------------------------------------------------------

class IssuanceRequest(BaseModel):
    """
    Dados enviados pelo app do titular para solicitar a emissão da credencial.
    O Middleware usa esses dados para chamar o Validador e gerar a SD-JWT VC.
    """
    cpf: str = Field(
        ...,
        description="CPF do titular (11 dígitos sem pontuação)",
        example="25774435016"
    )
    name: str = Field(
        ...,
        description="Nome completo do titular conforme Receita Federal",
        example="Manuela Elisa da Mota"
    )
    birth_date: date = Field(
        ...,
        description="Data de nascimento (YYYY-MM-DD) para cálculo de maioridade",
        example="1975-06-04"
    )


class IssuanceResponse(BaseModel):
    """
    Resposta da solicitação de emissão com o Credential Offer URI (OID4VCI Pre-Auth Flow).
    """
    credential_offer_uri: str = Field(
        ...,
        description="URI do Credential Offer compatível com OID4VCI (openid-credential-offer://...)",
        example="openid-credential-offer://?credential_offer_uri=http://127.0.0.1:8002/issuer/offers/abc123"
    )
    pre_authorized_code: str = Field(
        ...,
        description="Código pré-autorizado de uso único para troca por Access Token"
    )
    expires_in: int = Field(
        default=300,
        description="Validade do código pré-autorizado em segundos"
    )


# -----------------------------------------------------------------------------
# 2. Token Endpoint (POST /issuer/token) — Pre-Authorized Code Flow
# -----------------------------------------------------------------------------

class TokenRequest(BaseModel):
    """
    Requisição de troca do pre-authorized code por Access Token.
    Compatível com OID4VCI Pre-Authorized Code Flow.
    """
    grant_type: str = Field(
        default="urn:ietf:params:oauth:grant-type:pre-authorized_code",
        description="Tipo de concessão OAuth2 para Pre-Authorized Code Flow"
    )
    pre_authorized_code: str = Field(
        ...,
        description="Código pré-autorizado recebido no Credential Offer"
    )


class TokenResponse(BaseModel):
    """Resposta com o Access Token para ser usado no Credential Endpoint."""
    access_token: str = Field(..., description="Bearer token de acesso à credencial")
    token_type: str = Field(default="Bearer")
    expires_in: int = Field(default=300, description="Validade do Access Token em segundos")
    c_nonce: str = Field(..., description="Challenge nonce para a Proof of Possession JWT")
    c_nonce_expires_in: int = Field(default=300)


# -----------------------------------------------------------------------------
# 3. Credential Endpoint (POST /issuer/credential)
# -----------------------------------------------------------------------------

class Proof(BaseModel):
    """Objeto de prova de posse (Proof of Possession) exigido no Credential Endpoint."""
    proof_type: str = Field(
        default="jwt",
        description="Tipo de prova de posse (ex: jwt)"
    )
    jwt: str = Field(
        ...,
        description="JWT assinado pelo Holder contendo o c_nonce emitido pelo Issuer"
    )


class CredentialRequest(BaseModel):
    """
    Requisição final de credencial. A carteira envia o formato desejado e a prova de posse.
    """
    format: str = Field(
        default="vc+sd-jwt",
        description="Formato da credencial solicitada"
    )
    credential_configuration_id: str = Field(
        default="BraZKIL_AgeOver18",
        description="Identificador do tipo de credencial"
    )
    proof: Proof = Field(
        ...,
        description="Prova de posse obrigatória provando controle da chave associada ao DID"
    )


class CredentialResponse(BaseModel):
    """Resposta com a SD-JWT VC serializada e as disclosures em plaintext."""
    format: str = Field(default="vc+sd-jwt")
    credential: str = Field(
        ...,
        description="SD-JWT VC completa serializada no formato: header.payload.signature~disclosure1~disclosure2"
    )
    c_nonce: Optional[str] = Field(None, description="Novo c_nonce para rotação de chaves")
    c_nonce_expires_in: Optional[int] = Field(None)


# -----------------------------------------------------------------------------
# 4. Nonce Endpoint (GET /issuer/nonce)
# -----------------------------------------------------------------------------

class NonceResponse(BaseModel):
    """Resposta com um c_nonce fresco para a carteira incluir no proof JWT."""
    c_nonce: str = Field(..., description="Challenge nonce único e efêmero (UUID)")
    c_nonce_expires_in: int = Field(default=300, description="Validade em segundos")
