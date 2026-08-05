"""
    Schemas Pydantic para o Módulo Datavalid (Entrada e Saída Higienizada)
"""

from typing import Optional
from pydantic import BaseModel, Field


# Schema de Entrada: Dados enviados pelo Middleware para o Módulo Datavalid
class DatavalidValidationRequest(BaseModel):
    cpf: str = Field(
        ..., description="CPF do cidadão (somente números)"
    )
    name: str = Field(..., description="Nome completo declarativo")
    birth_date: str = Field(
        ..., description="Data de nascimento no formato DD-MM-YYYY"
    )
    facial_biometric: Optional[str] = Field(
        None, description="String Base64 da imagem facial (opcional)"
    )


# Schema de leitura da resposta bruta da API do Datavalid
class DatavalidRawRFBResponse(BaseModel):
    nome_similaridade: float
    situacao_cpf: bool
    data_nascimento: bool

class DatavalidRawResponse(BaseModel):
    rfb_existe: bool
    cnh_existe: Optional[bool] = False
    rfb: Optional[DatavalidRawRFBResponse] = None


# Schema de Saída Higienizado devolvido para o Middleware
class DatavalidValidationResult(BaseModel):
    rfb_exists: bool = Field(
        ..., description="Indica se o CPF existe na base da Receita Federal"
    )
    cpf_regular: bool = Field(
        ..., description="Indica se a situação do CPF está regular"
    )
    name_similarity: float = Field(
        ..., description="Índice de similaridade do nome (1.0 = 100% de correspondência)"
    )
    birth_date_valid: bool = Field(
        ..., description="Indica se a data de nascimento confere na Receita Federal"
    )
    validation_id: str = Field(
        ..., description="UUID efêmero para rastreabilidade de auditoria (sem dados pessoais)"
    )


    
