"""
    Camada de Serviço do Registro de Confiança e Status (VDR - Trust Registry)
    Contém a lógica de negócio para gerenciamento de DIDs, resolução de DID Documents W3C,
    registro de auditoria de validações efêmeras e controle da Status List de credenciais.
"""

from datetime import datetime
import os
import sys
from typing import Optional, Dict, Any

# Garante que o diretório raiz do projeto esteja no sys.path mesmo se executado diretamente pela IDE
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy.orm import Session
from vdr.models import AuthorizedIssuerModel, CredentialStatusModel, ValidationAuditModel
from vdr.schema import (
    IssuerRegisterRequest,
    CredentialStatusUpdateRequest,
    ValidationAuditCreateRequest
)


# -----------------------------------------------------------------------------
# 1. Serviço de Gerenciamento de Emissores (DIDs)
# -----------------------------------------------------------------------------

def register_issuer_service(db: Session, request: IssuerRegisterRequest) -> AuthorizedIssuerModel:
    """
    Registra ou atualiza um Emissor qualificado no VDR.
    Extrai o DID oficial a partir do campo 'id' do DID Document W3C.
    """
    did_doc = request.did_document
    did = did_doc.get("id")
    if not did:
        raise ValueError("O DID Document fornecido não possui o campo obrigatório 'id'.")

    # Verificar se o emissor já está cadastrado
    existing_issuer = db.query(AuthorizedIssuerModel).filter(AuthorizedIssuerModel.did == did).first()

    if existing_issuer:
        # Atualiza os dados do emissor existente
        existing_issuer.name = request.name
        existing_issuer.did_document = did_doc
        existing_issuer.is_active = True
        db.commit()
        db.refresh(existing_issuer)
        return existing_issuer
    else:
        # Cria um novo registro de emissor autorizado
        new_issuer = AuthorizedIssuerModel(
            did=did,
            name=request.name,
            did_document=did_doc,
            is_active=True
        )
        db.add(new_issuer)
        db.commit()
        db.refresh(new_issuer)
        return new_issuer


def resolve_did_service(db: Session, did: str) -> Dict[str, Any]:
    """
    Resolve um DID no padrão W3C, buscando o DID Document oficial armazenado no VDR.
    Usado por Verificadores e Validador para obter a chave pública e metadados do Emissor.
    """
    issuer = db.query(AuthorizedIssuerModel).filter(AuthorizedIssuerModel.did == did).first()
    if not issuer:
        raise ValueError(f"DID '{did}' não encontrado no Registro de Confiança.")
    
    if not issuer.is_active:
        raise ValueError(f"O Emissor correspondente ao DID '{did}' está inativo ou revogado.")

    return issuer.did_document


def get_issuer_service(db: Session, did: str) -> Optional[AuthorizedIssuerModel]:
    """Busca um emissor pelo DID e retorna o modelo completo do banco."""
    return db.query(AuthorizedIssuerModel).filter(AuthorizedIssuerModel.did == did).first()


# -----------------------------------------------------------------------------
# 2. Serviço de Auditoria de Validações Efêmeras (Datavalid Audit Log)
# -----------------------------------------------------------------------------

def record_validation_audit_service(db: Session, request: ValidationAuditCreateRequest) -> ValidationAuditModel:
    """
    Registra um evento de auditoria de validação efêmera efetuada pela Fonte Autoritativa (Datavalid).
    Persiste o validation_id, o resultado booleano e o timestamp exato enviado pelo Validador.
    """
    existing_audit = db.query(ValidationAuditModel).filter(ValidationAuditModel.validation_id == request.validation_id).first()
    if existing_audit:
        return existing_audit

    audit_entry = ValidationAuditModel(
        validation_id=request.validation_id,
        is_valid=request.is_valid,
        created_at=request.created_at if request.created_at else datetime.utcnow()
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry


def get_validation_audit_service(db: Session, validation_id: str) -> Optional[ValidationAuditModel]:
    """Busca um registro de auditoria efêmera pelo validation_id."""
    return db.query(ValidationAuditModel).filter(ValidationAuditModel.validation_id == validation_id).first()


# -----------------------------------------------------------------------------
# 3. Serviço de Status List de Credenciais (Revogação / Ciclo de Vida)
# -----------------------------------------------------------------------------

def update_credential_status_service(db: Session, request: CredentialStatusUpdateRequest) -> CredentialStatusModel:
    """
    Atualiza ou cria o status de uma credencial na Status List do VDR.
    Garante que apenas DIDs de Emissores ativos possam emitir/alterar status.
    """
    # 1. Verificar se o Emissor existe e está ativo no VDR
    issuer = db.query(AuthorizedIssuerModel).filter(AuthorizedIssuerModel.did == request.issuer_did).first()
    if not issuer or not issuer.is_active:
        raise ValueError(f"Emissor com DID '{request.issuer_did}' não está autorizado ou está inativo no VDR.")

    # 2. Atualizar ou criar o registro de status da credencial
    cred_status = db.query(CredentialStatusModel).filter(CredentialStatusModel.credential_id == request.credential_id).first()
    if cred_status:
        cred_status.status = request.status.upper()
        cred_status.issuer_did = request.issuer_did
        db.commit()
        db.refresh(cred_status)
        return cred_status
    else:
        new_cred_status = CredentialStatusModel(
            credential_id=request.credential_id,
            issuer_did=request.issuer_did,
            status=request.status.upper()
        )
        db.add(new_cred_status)
        db.commit()
        db.refresh(new_cred_status)
        return new_cred_status


def check_credential_status_service(db: Session, credential_id: str) -> Dict[str, Any]:
    """
    Consulta o status de uma credencial para Verificadores.
    Retorna o status ('ACTIVE', 'SUSPENDED', 'REVOKED') e o booleano de validade 'is_valid'.
    """
    cred_status = db.query(CredentialStatusModel).filter(CredentialStatusModel.credential_id == credential_id).first()
    if not cred_status:
        return {
            "credential_id": credential_id,
            "issuer_did": "UNKNOWN",
            "status": "NOT_FOUND",
            "is_valid": False
        }

    # Verificar se o emissor responsável continua ativo
    issuer = db.query(AuthorizedIssuerModel).filter(AuthorizedIssuerModel.did == cred_status.issuer_did).first()
    issuer_active = issuer.is_active if issuer else False

    is_valid = (cred_status.status == "ACTIVE") and issuer_active

    return {
        "credential_id": cred_status.credential_id,
        "issuer_did": cred_status.issuer_did,
        "status": cred_status.status,
        "is_valid": is_valid
    }


# -----------------------------------------------------------------------------
# 4. Serviços de Listagem e Visualização no Terminal
# -----------------------------------------------------------------------------

def list_all_issuers_service(db: Session):
    """Retorna a lista de todos os Emissores cadastrados no banco."""
    return db.query(AuthorizedIssuerModel).all()


def list_all_audits_service(db: Session):
    """Retorna a lista de todas as auditorias de validação efêmera registradas."""
    return db.query(ValidationAuditModel).order_by(ValidationAuditModel.created_at.desc()).all()


def list_all_credential_statuses_service(db: Session):
    """Retorna a lista de todas as credenciais e seus status."""
    return db.query(CredentialStatusModel).order_by(CredentialStatusModel.updated_at.desc()).all()


def print_database_summary_service(db: Session) -> None:
    """
    Imprime um resumo formatado e amigável de todas as tabelas do VDR no terminal,
    permitindo ao desenvolvedor visualizar o estado completo do banco de dados SQLite.
    """
    issuers = list_all_issuers_service(db)
    audits = list_all_audits_service(db)
    cred_statuses = list_all_credential_statuses_service(db)

    print("\n" + "=" * 80)
    print(" 🏛️  BANCO DE DADOS DO REGISTRO DE CONFIANÇA E STATUS (VDR) - RESUMO")
    print("=" * 80)

    # 1. Tabela de Emissores Autorizados
    print(f"\n📋 [1] EMISSORES AUTORIZADOS ({len(issuers)} registro(s)):")
    print("-" * 80)
    if not issuers:
        print("  (Nenhum emissor cadastrado)")
    else:
        for item in issuers:
            status_str = "✅ ATIVO" if item.is_active else "❌ INATIVO"
            print(f"  • DID:        {item.did}")
            print(f"    Nome:       {item.name}")
            print(f"    Status:     {status_str}")
            print(f"    Criado em:  {item.created_at}")
            print("  " + "." * 76)

    # 2. Tabela de Auditoria Efêmera (Datavalid)
    print(f"\n🔍 [2] AUDITORIAS DE VALIDAÇÃO DATAVALID ({len(audits)} registro(s)):")
    print("-" * 80)
    if not audits:
        print("  (Nenhuma auditoria registrada)")
    else:
        for item in audits:
            res_str = "Aprovado (True)" if item.is_valid else "Reprovado (False)"
            print(f"  • Validation ID: {item.validation_id}")
            print(f"    Resultado:     {res_str}")
            print(f"    Timestamp:     {item.created_at}")
            print("  " + "." * 76)

    # 3. Tabela de Status List de Credenciais
    print(f"\n🏷️  [3] STATUS LIST DE CREDENCIAIS ({len(cred_statuses)} registro(s)):")
    print("-" * 80)
    if not cred_statuses:
        print("  (Nenhuma credencial registrada)")
    else:
        for item in cred_statuses:
            print(f"  • Credential ID: {item.credential_id}")
            print(f"    Issuer DID:    {item.issuer_did}")
            print(f"    Status:        {item.status}")
            print(f"    Atualizado em: {item.updated_at}")
            print("  " + "." * 76)

    print("=" * 80 + "\n")


# -----------------------------------------------------------------------------
# 5. Serviços de Remoção/Deleção de Entradas
# -----------------------------------------------------------------------------

def delete_issuer_service(db: Session, did: str) -> bool:
    """
    Remove um Emissor do banco pelo seu DID.
    Também remove as credenciais associadas a esse emissor.
    """
    issuer = db.query(AuthorizedIssuerModel).filter(AuthorizedIssuerModel.did == did).first()
    if not issuer:
        return False

    # Remover credenciais associadas
    db.query(CredentialStatusModel).filter(CredentialStatusModel.issuer_did == did).delete()
    db.delete(issuer)
    db.commit()
    return True


def delete_validation_audit_service(db: Session, validation_id: str) -> bool:
    """Remove um registro de auditoria efêmera pelo validation_id."""
    audit = db.query(ValidationAuditModel).filter(ValidationAuditModel.validation_id == validation_id).first()
    if not audit:
        return False

    db.delete(audit)
    db.commit()
    return True


def delete_credential_status_service(db: Session, credential_id: str) -> bool:
    """Remove um registro de status de credencial pelo credential_id."""
    cred_status = db.query(CredentialStatusModel).filter(CredentialStatusModel.credential_id == credential_id).first()
    if not cred_status:
        return False

    db.delete(cred_status)
    db.commit()
    return True


def clear_all_tables_service(db: Session) -> None:
    """Remove todos os dados de todas as tabelas do VDR (Útil para resetar o ambiente de testes)."""
    db.query(CredentialStatusModel).delete()
    db.query(ValidationAuditModel).delete()
    db.query(AuthorizedIssuerModel).delete()
    db.commit()


if __name__ == "__main__":
    from vdr.models import init_db, SessionLocal
    init_db()
    db = SessionLocal()
    clear_all_tables_service(db)
    print_database_summary_service(db)
    db.close()


