"""
    Schemas Pydantic para a API do VDR
    Define as estruturas de validação de dados de entrada e saída para DIDs, DID Documents e Status List.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


# -----------------------------------------------------------------------------
# 1. Schemas para Gerenciamento de Emissores Autorizados (DIDs)
# -----------------------------------------------------------------------------

class IssuerRegisterRequest(BaseModel):
    """Schema para o cadastro de um novo Emissor no VDR."""
    name: str = Field(
        ...,
        description="Nome legível do Emissor (ex: 'Middleware Governamental BraZKIL')",
        example="Middleware Governamental BraZKIL"
    )
    did_document: Dict[str, Any] = Field(
        ...,
        description="DID Document completo em formato padrão W3C JSON-LD"
    )


class IssuerResponse(BaseModel):
    """Schema de retorno contendo as informações completas do Emissor cadastrado."""
    did_document: Dict[str, Any] = Field(..., description="DID Document W3C oficial")
    is_active: bool = Field(True, description="Indica se o Emissor está ativo e qualificado")

    class Config:
        from_attributes = True


# -----------------------------------------------------------------------------
# 2. Schemas para a Status List de Credenciais (Ciclo de Vida / Revogação)
# -----------------------------------------------------------------------------

class CredentialStatusUpdateRequest(BaseModel):
    """Schema enviado pelo Emissor para registrar ou alterar o status de uma credencial."""
    credential_id: str = Field(
        ...,
        description="ID único/UUID da credencial",
        example="c6af275f-9b67-49ca-98a0-c703a8a485b9"
    )
    issuer_did: str = Field(
        ...,
        description="DID do Emissor responsável pela credencial",
        example="did:brazkil:550e8400-e29b-41d4-a716-446655440000"
    )
    status: str = Field(
        "ACTIVE",
        description="Status atual da credencial: 'ACTIVE', 'SUSPENDED', ou 'REVOKED'",
        example="ACTIVE"
    )


class CredentialStatusResponse(BaseModel):
    """Schema retornado para consulta de status por Verificadores ou Validador."""
    credential_id: str = Field(..., description="UUID único da credencial")
    issuer_did: str = Field(..., description="DID do Emissor que gerou a credencial")
    status: str = Field(..., description="Status atual ('ACTIVE', 'SUSPENDED', 'REVOKED')")
    is_valid: bool = Field(..., description="True se a credencial estiver 'ACTIVE' e o emissor qualificado")

    class Config:
        from_attributes = True


# -----------------------------------------------------------------------------
# 3. Schemas para Auditoria de Validações Efêmeras (Datavalid Audit Log)
# -----------------------------------------------------------------------------

class ValidationAuditCreateRequest(BaseModel):
    """Schema enviado pelo Módulo Validador para registrar um evento de auditoria no VDR."""
    validation_id: str = Field(
        ...,
        description="UUID efêmero da validação cadastral",
        example="962a710c-09e7-4c7f-bdf6-44ff6207212a"
    )
    is_valid: bool = Field(
        ...,
        description="Resultado booleano da validação na Fonte Autoritativa",
        example=True
    )
    created_at: Optional[datetime] = Field(
        None,
        description="Timestamp exato da verificação gerado pelo Validador (ISO 8601 UTC)"
    )


class ValidationAuditResponse(BaseModel):
    """Schema de retorno contendo o registro de auditoria efêmera persistido no VDR."""
    validation_id: str = Field(..., description="UUID efêmero da validação")
    is_valid: bool = Field(..., description="Resultado booleano da validação")
    created_at: datetime = Field(..., description="Timestamp da realização da validação")

    class Config:
        from_attributes = True

