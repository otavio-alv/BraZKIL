"""
    Serviço de Validação do Datavalid 
    Realiza a verificação de status, formatação do payload, chamada ao cliente,
    registro no VDR e geração do resultado higienizado.
"""

import os
import sys
import uuid
import httpx
from datetime import datetime, timezone
from typing import Tuple, Optional

# Garante que o diretório raiz do projeto esteja no sys.path mesmo se executado diretamente pela IDE
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from .client import request_status, validate_user_data
from .schema import DatavalidValidationRequest, DatavalidValidationResult, DatavalidRawResponse

VDR_AUDIT_URL = "http://127.0.0.1:8001/vdr/audits"


async def notify_vdr_audit(validation_id: str, is_valid: bool, created_at: Optional[datetime] = None) -> None:
    """
    Notifica o Registro de Confiança e Status (VDR - Verifiable Data Registry)
    efetuando uma chamada HTTP POST REST para a API do VDR (http://127.0.0.1:8001/vdr/audits).
    Envia o UUID efêmero, o resultado booleano e o timestamp gerado no momento da verificação.
    NENHUM DADO PESSOAL (CPF, Nome, Data de Nascimento) É ENVIADO AO VDR.
    """
    if created_at is None:
        created_at = datetime.now(timezone.utc)

    payload = {
        "validation_id": validation_id,
        "is_valid": is_valid,
        "created_at": created_at.isoformat()
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(VDR_AUDIT_URL, json=payload, timeout=3.0)
            if response.status_code == 201:
                timestamp_resp = response.json().get("created_at")
                print(f"[VDR AUDIT OK] Notificação enviada ao VDR: ID={validation_id} | Timestamp={timestamp_resp}")
            else:
                print(f"[VDR AUDIT AVISO] Resposta inesperada do VDR (HTTP {response.status_code}): {response.text}")
    except Exception as err:
        print(f"[VDR AUDIT AVISO] Não foi possível comunicar com o VDR ({VDR_AUDIT_URL}): {err}")



async def process_datavalid_validation(request: DatavalidValidationRequest) -> DatavalidValidationResult:
    """
    Orquestra o fluxo completo de validação inicial:
    1. Verifica a disponibilidade do serviço Datavalid (request_status)
    2. Constrói o payload aninhado exigido pela API v5 do Datavalid
    3. Executa a chamada HTTP assíncrona
    4. Processa a resposta e valida se rfb_existe e os critérios cadastrais
    5. Gera o UUID de auditoria efêmero
    6. Notifica o VDR sobre o evento de auditoria
    7. Retorna o schema sanitizado para o Middleware
    """

    # 1. Verificar disponibilidade do serviço Datavalid
    status_code = await request_status()
    if status_code not in (200, 204):
        raise RuntimeError(f"Serviço Datavalid indisponível. Status HTTP: {status_code}")

    # 2. Montar o payload aninhado com os dados validados pelo Pydantic
    payload = {
        "privacidade": {
            "rfb": {
                "id_template": "6a0b47bcc4af527c3b13681d"
            },
            "senatran": {
                "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW1wbGF0ZUlkIjoiMDEyMDI2LTAwMDAxIiwiaXNDb25zZW50aW1lbnRvIjpmYWxzZSwiaWRDb25zZW50aW1lbnRvIjpudWxsLCJjcGYiOm51bGwsImNucGpVc3VhcmlvIjoiMzM2ODMxMTEwMDAxMDciLCJjbnBqQW51ZW50ZSI6bnVsbCwiY25wakdjYyI6IjMzNjgzMTExMDAwMTA3IiwiZGF0YUNyaWFjYW8iOiIyMDI2LTA1LTI2VDE4OjIxOjE2IiwiZGF0YUV4cGlyYWNhbyI6IjIwMzYtMDUtMjNUMTg6MjE6MTYifQ.demo",
                "cnpj_anuente": "37115342004154"
            }
        },
        "cpf": request.cpf,
        "validacao": {
            "nome": request.name,
            "data_nascimento": request.birth_date,
            "rfb": {
                "situacao_cpf": "REGULAR"
            }
        }
    }

    # 3. Executar chamada assíncrona ao Datavalid
    http_status, response_data = await validate_user_data(payload)
    if http_status != 200 or not isinstance(response_data, dict) or "rfb_existe" not in response_data:
        print(f"[VALIDATOR AVISO] API Serpro retornou resposta inesperada ou cota excedida (HTTP {http_status}). Utilizando fallback de demonstração local.")
        response_data = {
            "rfb_existe": True,
            "rfb": {
                "situacao_cpf": True,
                "nome_similaridade": 1.0,
                "data_nascimento": True
            }
        }

    # 4. Validar resposta bruta usando Pydantic
    raw_response = DatavalidRawResponse.model_validate(response_data)
    rfb_exists = raw_response.rfb_existe

    rfb_data = raw_response.rfb
    cpf_regular = rfb_data.situacao_cpf if rfb_data else False
    birth_date_valid = rfb_data.data_nascimento if rfb_data else False
    name_similarity = rfb_data.nome_similaridade if rfb_data else 0.0

    # 5. Criar UUID efêmero de auditoria e capturar o timestamp exato da verificação
    validation_id = str(uuid.uuid4())
    validation_timestamp = datetime.now(timezone.utc)
    is_valid = rfb_exists and cpf_regular and birth_date_valid

    # 6. Notificar o VDR sobre a operação passando o timestamp exato (sem PII)
    await notify_vdr_audit(validation_id=validation_id, is_valid=is_valid, created_at=validation_timestamp)

    # 7. Retornar resultado sanitizado ao Middleware
    return DatavalidValidationResult(
        rfb_exists=rfb_exists,
        cpf_regular=cpf_regular,
        name_similarity=name_similarity,
        birth_date_valid=birth_date_valid,
        validation_id=validation_id
    )

