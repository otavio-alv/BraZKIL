"""
    Modelos de Banco de Dados SQLAlchemy para o Registro de Confiança (VDR - Trust Registry)
    Define as tabelas de Emissores Autorizados e a Status List de Credenciais.
"""

from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, JSON, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./trust_registry.db"

# Engine de conexão do SQLAlchemy (SQLite local para PoC)
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Fábrica de Sessões para transações de banco de dados
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Classe Base Mapeadora do SQLAlchemy
Base = declarative_base()


class AuthorizedIssuerModel(Base):
    """
    Tabela de Emissores (Middlewares) Autorizados no Ecossistema BraZKIL.
    Armazena o DID do Emissor, sua Chave Pública (para verificação de assinatura ES256) e seu estado.
    """
    __tablename__ = "authorized_issuers"

    did = Column(String, primary_key=True)           # "did:brazkil:550e8400..."
    name = Column(String, nullable=False)            # Nome legível do Emissor
    did_document = Column(JSON, nullable=False)      # DID Document completo (W3C JSON)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relacionamento com as credenciais emitidas
    credentials = relationship("CredentialStatusModel", back_populates="issuer")


class CredentialStatusModel(Base):
    """
    Tabela de Status List de Credenciais Emitidas.
    Permite aos Verificadores consultar se uma credencial está ATIVA, SUSPENSA ou REVOGADA,
    sem expor dados pessoais do cidadão (Privacy by Design).
    """
    __tablename__ = "credential_status"

    credential_id = Column(String, primary_key=True, index=True)   # UUID da credencial
    issuer_did = Column(String, ForeignKey("authorized_issuers.did"), nullable=False, index=True)
    status = Column(String, default="ACTIVE", nullable=False)       # ACTIVE, SUSPENDED, REVOKED
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relacionamento de volta para o Emissor
    issuer = relationship("AuthorizedIssuerModel", back_populates="credentials")


class ValidationAuditModel(Base):
    """
    Tabela de Registros de Auditoria de Validação Efêmera.
    Armazena o UUID de auditoria (validation_id), o resultado booleano e o timestamp da consulta
    realizada na Fonte Autoritativa (Datavalid), garantindo auditoria sem PII (Privacy by Design).
    """
    __tablename__ = "validation_audits"

    validation_id = Column(String, primary_key=True, index=True)
    is_valid = Column(Boolean, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


def init_db():
    """Inicializa as tabelas no banco de dados SQLite caso ainda não existam."""
    Base.metadata.create_all(bind=engine)
