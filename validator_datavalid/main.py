"""
    Aplicação FastAPI para a interface do Validator 
    Expõe o endpoint REST HTTP consumido pelo Middleware do BraZKIL.
"""

import os
import sys

# Garante que o diretório raiz do projeto esteja no sys.path mesmo se executado diretamente pela IDE
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, HTTPException, status
from validator_datavalid.schema import DatavalidValidationRequest, DatavalidValidationResult
from validator_datavalid.service import process_datavalid_validation

app = FastAPI(
    title="BraZKIL - Módulo de Validação Datavalid",
    description="Interface REST para verificação cadastral com Datavalid / SERPRO",
    version="1.0.0"
)

@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {"status": "online", "module": "validator_datavalid"}

@app.post(
    "/validate",
    response_model=DatavalidValidationResult,
    status_code=status.HTTP_200_OK,
    summary="Valida os dados cadastrais do cidadão no Datavalid",
    description="Recebe a requisição do Middleware, consulta o Datavalid v5 e retorna apenas a validação sanitizada."
)
async def validate_identity(request: DatavalidValidationRequest):
    """
    Endpoint HTTP consumido pelo Middleware BraZKIL:
    - O FastAPI valida automaticamente o JSON de entrada contra o DatavalidValidationRequest.
    - Repassa para a camada de serviço (process_datavalid_validation).
    - Retorna o DatavalidValidationResult higienizado.
    """
    try:
        result = await process_datavalid_validation(request)
        return result
    except RuntimeError as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(err)
        )
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro interno no módulo Datavalid: {str(err)}"
        )
