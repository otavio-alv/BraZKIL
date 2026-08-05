"""
    Aplicação FastAPI para a Interface do Registro de Confiança e Status (VDR - Trust Registry)
    Expõe o serviço de DID Resolver W3C, cadastro de Emissores, auditoria de validação e Status List.
"""

import os
import sys
from typing import List, Dict, Any

# Garante que o diretório raiz do projeto esteja no sys.path mesmo se executado diretamente pela IDE
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vdr.models import SessionLocal, init_db
from vdr.schema import (
    IssuerRegisterRequest,
    IssuerResponse,
    CredentialStatusUpdateRequest,
    CredentialStatusResponse,
    ValidationAuditCreateRequest,
    ValidationAuditResponse
)
from vdr.service import (
    register_issuer_service,
    resolve_did_service,
    record_validation_audit_service,
    get_validation_audit_service,
    update_credential_status_service,
    check_credential_status_service,
    list_all_issuers_service,
    list_all_audits_service,
    list_all_credential_statuses_service,
    print_database_summary_service,
    delete_issuer_service,
    delete_validation_audit_service,
    delete_credential_status_service
)

# Inicializa as tabelas SQLite na subida do servidor
init_db()

app = FastAPI(
    title="BraZKIL - Registro de Confiança e Status (VDR)",
    description="Serviço de Registro de Confiança, DID Resolver W3C, Auditoria Efêmera e Status List de Credenciais",
    version="1.0.0"
)


def get_db():
    """Injeta a sessão do SQLAlchemy por requisição e a fecha ao finalizar."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/health", status_code=status.HTTP_200_OK, summary="Verificação de saúde do VDR")
async def health_check():
    """Endpoint de verificação de saúde da aplicação VDR."""
    return {"status": "online", "module": "vdr"}


# -----------------------------------------------------------------------------
# 1. Rotas de Gerenciamento de Emissores e DID Resolver W3C
# -----------------------------------------------------------------------------

@app.post(
    "/vdr/issuers",
    response_model=IssuerResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastra um novo Emissor qualificado no VDR",
    description="Recebe o DID Document W3C e registra o Emissor na lista de autoridades confiáveis."
)
async def register_issuer(request: IssuerRegisterRequest, db: Session = Depends(get_db)):
    try:
        issuer = register_issuer_service(db, request)
        return issuer
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro no VDR: {str(err)}")


@app.get(
    "/vdr/did/{did:path}",
    summary="DID Resolver W3C",
    description="Resolve um DID do método 'brazkil', retornando o DID Document W3C oficial em JSON-LD."
)
async def resolve_did(did: str, db: Session = Depends(get_db)):
    try:
        did_document = resolve_did_service(db, did)
        return did_document
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_444_NOT_FOUND if "não encontrado" in str(err) else status.HTTP_404_NOT_FOUND, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro ao resolver DID: {str(err)}")


@app.get(
    "/vdr/issuers",
    response_model=List[IssuerResponse],
    summary="Lista todos os Emissores cadastrados"
)
async def list_issuers(db: Session = Depends(get_db)):
    return list_all_issuers_service(db)


@app.delete(
    "/vdr/issuers/{did:path}",
    status_code=status.HTTP_200_OK,
    summary="Remove um Emissor do VDR"
)
async def delete_issuer(did: str, db: Session = Depends(get_db)):
    deleted = delete_issuer_service(db, did)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Emissor com DID '{did}' não encontrado.")
    return {"message": f"Emissor '{did}' removido com sucesso."}


# -----------------------------------------------------------------------------
# 2. Rotas de Auditoria de Validações Efêmeras (Datavalid Audit)
# -----------------------------------------------------------------------------

@app.post(
    "/vdr/audits",
    response_model=ValidationAuditResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registra uma auditoria de validação efêmera",
    description="Chamado pelo Módulo Validador (Datavalid) para registrar o validation_id e o resultado booleano (sem PII)."
)
async def record_audit(request: ValidationAuditCreateRequest, db: Session = Depends(get_db)):
    try:
        audit = record_validation_audit_service(db, request)
        return audit
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro ao registrar auditoria: {str(err)}")


@app.get(
    "/vdr/audits/{validation_id}",
    response_model=ValidationAuditResponse,
    summary="Busca uma auditoria pelo validation_id"
)
async def get_audit(validation_id: str, db: Session = Depends(get_db)):
    audit = get_validation_audit_service(db, validation_id)
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Auditoria '{validation_id}' não encontrada.")
    return audit


@app.get(
    "/vdr/audits",
    response_model=List[ValidationAuditResponse],
    summary="Lista todos os registros de auditoria de validação"
)
async def list_audits(db: Session = Depends(get_db)):
    return list_all_audits_service(db)


# -----------------------------------------------------------------------------
# 3. Rotas da Status List de Credenciais (Revogação / Ciclo de Vida)
# -----------------------------------------------------------------------------

@app.post(
    "/vdr/credentials/status",
    response_model=CredentialStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Atualiza o status de uma credencial na Status List",
    description="Chamado pelo Emissor para definir a credencial como ACTIVE, SUSPENDED ou REVOKED."
)
async def update_credential_status(request: CredentialStatusUpdateRequest, db: Session = Depends(get_db)):
    try:
        cred_status = update_credential_status_service(db, request)
        status_check = check_credential_status_service(db, cred_status.credential_id)
        return status_check
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro ao atualizar status: {str(err)}")


@app.get(
    "/vdr/credentials/status/{credential_id}",
    response_model=CredentialStatusResponse,
    summary="Consulta o status de uma credencial",
    description="Chamado por Verificadores para checar se a credencial está ativa e se o emissor continua qualificado."
)
async def get_credential_status(credential_id: str, db: Session = Depends(get_db)):
    status_check = check_credential_status_service(db, credential_id)
    return status_check


# -----------------------------------------------------------------------------
# 4. Rota Especial de Inspeção e Impressão Visual no Terminal
# -----------------------------------------------------------------------------

@app.get(
    "/vdr/summary",
    summary="Imprime a tabela formatada do banco de dados no terminal e retorna o resumo em JSON"
)
async def database_summary(db: Session = Depends(get_db)):
    # Imprime no terminal do servidor Uvicorn
    print_database_summary_service(db)
    
    # Retorna também uma resposta limpa em JSON
    return {
        "issuers_count": len(list_all_issuers_service(db)),
        "audits_count": len(list_all_audits_service(db)),
        "credential_statuses_count": len(list_all_credential_statuses_service(db))
    }
