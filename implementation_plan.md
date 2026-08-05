# BraZKIL — Plano de Implementação da Prova de Conceito

## Contexto e Objetivo

O BraZKIL é uma arquitetura híbrida para verificação de maioridade que separa a **validação inicial** (com fonte autoritativa) das **comprovações recorrentes** (credenciais verificáveis com divulgação seletiva). A PoC deve exercitar emissão, armazenamento, apresentação seletiva, verificação e revogação de uma credencial de maioridade.

**Stack obrigatória (conforme artigo):**
- **Python 3.12**
- **FastAPI 0.115.6**
- **SQLAlchemy 2.0.36**
- **cryptography 44.0.0**
- **python-jose 3.3.0**
- **httpx 0.28.1**
- **Carteira:** walt.id `v0.22` (open-source)
- **Formato de credencial:** SD-JWT VC
- **Protocolos:** OID4VCI e OID4VP

---

## Estrutura de Diretórios Proposta

```
poc/
├── shared/                  # Utilitários compartilhados
│   ├── crypto.py            # ES256, SHA-256, geração de chaves
│   ├── did.py               # Resolução e geração de DIDs (did:key)
│   └── models.py            # Modelos SQLAlchemy compartilhados
├── datavalid/               # ATOR 1 — Fonte Autoritativa (mock)
│   ├── client.py            # Cliente HTTP para API Datavalid
│   └── schemas.py           # Schemas de entrada/saída
├── issuer/                  # ATOR 2 — Middleware BraZKIL (Emissor)
│   ├── main.py              # FastAPI app
│   ├── policy.py            # Política de aceitação
│   ├── sd_jwt.py            # Geração de SD-JWT VC
│   ├── oid4vci.py           # Endpoints OID4VCI
│   └── models.py            # IssuanceRecord
├── wallet/                  # ATOR 3 — Titular (integração walt.id)
│   ├── integration.py       # Client para walt.id v0.22
│   └── holder_binding.py    # Key Binding JWT
├── verifier/                # ATOR 4 — Serviço Verificador
│   ├── main.py              # FastAPI app
│   ├── oid4vp.py            # Endpoints OID4VP
│   └── verify.py            # Validação de apresentação
└── trust_registry/          # ATOR 5 — Registro de Confiança e Status
    ├── main.py              # FastAPI app
    ├── registry.py          # Emissores autorizados + DIDs
    └── status.py            # Status List (suspensão/revogação)
```

---

## Fase 1 — Fonte Autoritativa: Integração Datavalid

> **Prioridade máxima**, conforme solicitado. Este módulo alimenta toda a cadeia de confiança.

### O que é o Datavalid?

É o serviço da SERPRO que permite validação cadastral e biométrica via REST API. O ambiente de demonstração aceita **5 perfis sintéticos específicos** e não exige dados reais.

### Módulos a implementar

#### `datavalid/client.py`
Cliente HTTP (via `httpx`) para o ambiente de demonstração do Datavalid:

| Operação | Endpoint esperado | Dados enviados |
|---|---|---|
| Validação cadastral | `POST /v3/validate/cpf` | CPF, nome, data nascimento |
| Validação biométrica | `POST /v3/validate/cpf/face` | CPF + imagem facial (base64) |

**Regras obrigatórias:**
- Usar `httpx.AsyncClient` com `timeout` configurado
- Autenticação por Bearer Token (OAuth2 SERPRO)
- **Dados pessoais NÃO devem ser persistidos** após a avaliação da política — apenas o resultado da validação é propagado

#### `datavalid/schemas.py`
Modelos Pydantic para requisição e resposta:
- `DatavalidRequest`: CPF, nome, data_nascimento, imagem_facial (opcional)
- `DatavalidResponse`: `cadastral_ok: bool`, `biometric_score: float`, `birth_date_validated: date`
- **Nunca incluir CPF ou biometria no response propagado internamente**

### Critérios de aceitação desta fase

- [ ] Chamada real ao ambiente de demonstração do Datavalid retorna resposta processável
- [ ] Os 5 perfis sintéticos do ambiente são identificados e mapeados
- [ ] Dados pessoais (CPF, imagem, data de nascimento) são descartados após avaliação
- [ ] O módulo expõe apenas `age_validated: bool` e `validation_id: str` (UUID efêmero) para o Issuer

---

## Fase 2 — Middleware BraZKIL: Emissor (Issuer)

### Responsabilidade

Receber a decisão de validação do Datavalid, aplicar a política de aceitação e **emitir a SD-JWT VC** com o atributo `age_over_18`. Expõe endpoints OID4VCI para entrega à carteira.

### Módulos a implementar

#### `shared/crypto.py`
- Geração de par de chaves **ECDSA P-256** (ES256) — chave do emissor
- Função de assinatura ES256 (via `cryptography`)
- Geração de hashes SHA-256 para disclosures SD-JWT
- Geração de salts criptograficamente seguros (`secrets.token_bytes`)

#### `shared/did.py`
- Geração de DID `did:key` a partir da chave pública P-256
- Resolução do DID Document com chave pública e endpoint de status

#### `issuer/policy.py`
Política de aceitação — regras avaliadas internamente:
- `cadastral_validated == True`
- `biometric_score >= THRESHOLD` (ex: 0.80)
- `age_calculated >= 18` (a partir da data de nascimento validada)
- Retorna `PolicyDecision(approved: bool, reason: str)`

#### `issuer/sd_jwt.py`
Construção do SD-JWT VC conforme RFC SD-JWT VC:

```
SD-JWT = Header.Payload.Signature~disclosure_1~[KB-JWT]
```

**Estrutura do payload:**
- Claims públicos (não protegidos): `iss`, `iat`, `exp`, `vct`, `cnf`, `credentialStatus`
- Claims protegidos por disclosure: `age_over_18`, `_sd_alg`
- **CPF, nome, data de nascimento NUNCA entram no payload**

**Disclosure estrutura:**
```json
["<salt_b64>", "age_over_18", true]
```
Hash SHA-256 do disclosure JSON-encoded incluído em `_sd` do payload.

#### `issuer/oid4vci.py`
Endpoints FastAPI do fluxo OID4VCI:

| Endpoint | Método | Função |
|---|---|---|
| `/.well-known/openid-credential-issuer` | GET | Metadata do emissor |
| `/credential-offer` | GET | Gera Credential Offer (QR/URI) |
| `/token` | POST | Troca pre-auth code por access token |
| `/credential` | POST | Entrega a SD-JWT VC para a carteira |

#### `issuer/models.py` (SQLAlchemy)
```python
class IssuanceRecord(Base):
    id: UUID  # primary key
    issued_at: datetime
    expires_at: datetime
    credential_id: str  # identificador da VC
    status: str  # ACTIVE, SUSPENDED, REVOKED
    # NÃO armazenar CPF, biometria, data de nascimento
```

### Critérios de aceitação desta fase

- [ ] SD-JWT VC gerado é válido (header, payload, signature verificável com chave pública)
- [ ] `_sd` array contém apenas o hash de `age_over_18`
- [ ] CPF, data de nascimento e biometria ausentes do payload e de qualquer log
- [ ] Endpoint `/credential` entrega a VC com campo `cnf` preenchido com chave pública do holder
- [ ] `IssuanceRecord` persistido no banco sem dados pessoais

---

## Fase 3 — Titular: Integração com Walt.id v0.22

### Responsabilidade

Agir como Holder: receber a credencial via OID4VCI, armazená-la na carteira walt.id, e produzir apresentações seletivas via OID4VP.

### Módulos a implementar

#### `wallet/integration.py`
Cliente para a API REST da carteira walt.id v0.22:

| Operação | API walt.id | Descrição |
|---|---|---|
| Receber offer | `POST /holder/receive-credential` | Aceita Credential Offer e inicia OID4VCI |
| Listar credenciais | `GET /holder/credentials` | Lista VCs armazenadas |
| Criar apresentação | `POST /holder/present` | Gera VP com disclosure seletivo |

#### `wallet/holder_binding.py`
Geração do **Key Binding JWT** (KB-JWT):
- Header: `{"typ": "kb+jwt", "alg": "ES256"}`
- Payload: `{"iat": <now>, "aud": <verifier_url>, "nonce": <challenge>, "sd_hash": <hash_da_apresentação>}`
- Assinado com chave privada do holder (gerenciada pela walt.id)

**Fluxo de apresentação seletiva:**
1. Walt.id recebe `PresentationRequest` do verifier (via OID4VP)
2. Seleciona apenas o disclosure de `age_over_18`
3. Assina KB-JWT com nonce + audience
4. Envia: `SD-JWT~disclosure_age_over_18~KB-JWT`

### Critérios de aceitação desta fase

- [ ] Credencial armazenada na carteira walt.id com sucesso via OID4VCI
- [ ] Apresentação gerada contém apenas o disclosure de `age_over_18`
- [ ] KB-JWT contém `nonce`, `aud` e `iat` válidos
- [ ] CPF, nome e data de nascimento **ausentes** da apresentação enviada

---

## Fase 4 — Verificador (Verifier)

### Responsabilidade

Solicitar a apresentação via OID4VP e verificar **todas as camadas** da SD-JWT VC recebida.

### Módulos a implementar

#### `verifier/oid4vp.py`
Endpoints FastAPI:

| Endpoint | Método | Função |
|---|---|---|
| `/presentation-request` | GET | Gera PresentationRequest com nonce único |
| `/callback` | POST | Recebe VP e dispara verificação |

**PresentationRequest gerado:**
```json
{
  "response_type": "vp_token",
  "nonce": "<uuid_único_por_sessão>",
  "client_id": "<verifier_did>",
  "presentation_definition": {
    "input_descriptors": [{"id": "age_over_18", "constraints": {...}}]
  }
}
```

#### `verifier/verify.py`
Pipeline de verificação (ordem obrigatória):

1. **Parse** da SD-JWT VC recebida (separar por `~`)
2. **Verificar assinatura** ES256 do SD-JWT com chave pública do issuer (obtida do Trust Registry)
3. **Verificar validade temporal** (`iat`, `exp`, `validUntil`)
4. **Verificar status** da credencial no Trust Registry (ACTIVE / SUSPENDED / REVOKED)
5. **Verificar issuer** está na lista de emissores autorizados
6. **Reconstituir disclosures**: calcular SHA-256 de cada disclosure recebido e checar contra `_sd`
7. **Verificar KB-JWT**: validar assinatura com chave `cnf` da VC, checar `nonce`, `aud` e `iat`
8. **Verificar que APENAS `age_over_18` foi divulgado** — rejeitar se atributos extras presentes

### Critérios de aceitação desta fase

- [ ] Apresentação válida resulta em `age_over_18: true` e acesso concedido
- [ ] Credencial revogada é rejeitada com erro 403
- [ ] Nonce inválido ou reutilizado é rejeitado
- [ ] Assinatura ES256 inválida é rejeitada
- [ ] Verificador **nunca recebe** CPF, data de nascimento ou biometria

---

## Fase 5 — Registro de Confiança e Status (Trust Registry)

### Responsabilidade

Publicar metadados do emissor (DID, chave pública) e o estado das credenciais (ativa, suspensa, revogada).

### Módulos a implementar

#### `trust_registry/registry.py`
- Endpoint `GET /issuers` — lista emissores autorizados com DID e chave pública
- Endpoint `GET /did/{did}` — resolve DID Document
- Dados persistidos em SQLAlchemy

#### `trust_registry/status.py`
Implementação de **Status List** (modelo agregado):
- `POST /status/update` — emissor atualiza status de uma credencial
- `GET /status/{credential_id}` — retorna estado atual: `ACTIVE | SUSPENDED | REVOKED`
- **Diferenciação**: SUSPENDED (temporário, reversível) vs REVOKED (definitivo)

#### `trust_registry/models.py` (SQLAlchemy)
```python
class IssuerRecord(Base):
    did: str  # primary key
    public_key_jwk: JSON
    name: str
    authorized: bool

class CredentialStatus(Base):
    credential_id: str  # primary key
    status: str  # ACTIVE, SUSPENDED, REVOKED
    updated_at: datetime
    reason: str
```

### Critérios de aceitação desta fase

- [ ] Verifier consegue resolver a chave pública do issuer via Trust Registry
- [ ] Revogação de credencial reflete no Trust Registry em tempo real
- [ ] Verificador rejeita credencial revogada ao consultar o registry

---

## Fluxo Integrado — Sequência Completa

```
Titular → Middleware (Issuer)
    Middleware → Datavalid (validação cadastral + biométrica)
    Datavalid → Middleware (confirmações; dados pessoais descartados)
    Middleware aplica política de aceitação
    Middleware gera SD-JWT VC (apenas age_over_18)
    Middleware → Trust Registry (registra credential_id como ACTIVE)
    Middleware → Titular (Credential Offer via OID4VCI URI/QR)

Titular → Walt.id Wallet (aceita Credential Offer)
    Walt.id → Middleware (solicita token + credencial)
    Walt.id armazena SD-JWT VC

Serviço Digital (Verifier) → Titular (PresentationRequest OID4VP com nonce)
    Titular → Walt.id (solicita apresentação seletiva)
    Walt.id → SD-JWT~disclosure[age_over_18]~KB-JWT
    Titular → Verifier (VP)

Verifier → Trust Registry (resolve chave do issuer + status da credencial)
    Verifier verifica: assinatura, validade, status, disclosures, KB-JWT
    Verifier → Titular (ACESSO CONCEDIDO / NEGADO)
```

---

## Tabela de Resultados Funcionais a Reproduzir

Conforme `tabela_resultados-poc` do artigo:

| Fluxo | Resultado esperado |
|---|---|
| Validação Datavalid (perfil válido) | `age_validated: true` |
| Validação Datavalid (perfil inválido) | `age_validated: false`, emissão negada |
| Emissão SD-JWT VC | VC gerada com `age_over_18` e sem dados pessoais |
| Armazenamento na Walt.id | VC persistida na carteira |
| Apresentação seletiva | Apenas `age_over_18` revelado ao verifier |
| Verificação completa | Pipeline de 8 etapas aprovado |
| Revogação | Credencial rejeitada após revogação no Trust Registry |

---

## Medições de Latência a Coletar

Conforme `latencia-poc-brazkil` do artigo (usando `time.perf_counter()`):

| Operação | N medições | Métrica |
|---|---|---|
| Round-trip HTTP Datavalid | 50 | min, max, mediana, p95 |
| Geração SD-JWT VC (assinar + hashes) | N | idem |
| Armazenamento na carteira | N | idem |
| Geração de apresentação (KB-JWT) | N | idem |
| Verificação completa da VP | N | idem |
| Consulta ao Trust Registry (status) | N | idem |

---

## Propriedades de Segurança a Verificar (Tabela 4 do artigo)

| Ameaça | Mecanismo implementado na PoC |
|---|---|
| Fraude na validação | Datavalid + política de aceitação com limiar biométrico |
| Credencial inválida | Verificação de `exp` e consulta ao Trust Registry |
| Repetição de apresentação | Nonce por sessão no OID4VP + KB-JWT |
| Coleta excessiva | Apenas `age_over_18` divulgado |
| Correlação | Ausência de CPF/identificadores persistentes na VP |
| Emissor comprometido | Trust Registry com lista de emissores autorizados |

---

> [!IMPORTANT]
> **Ordem de implementação:** Fase 1 → Fase 5 → Fase 2 → Fase 3 → Fase 4 → Testes integrados.
> O Trust Registry (Fase 5) deve estar operacional antes do Issuer (Fase 2), pois o emissor precisa registrar credenciais nele.

> [!WARNING]
> **Nunca persistir** CPF, imagem facial, data de nascimento ou resposta bruta do Datavalid no banco de dados do emissor. Isso viola o princípio de finalidade da LGPD e a proposta central do artigo.

> [!NOTE]
> O ambiente de demonstração do Datavalid aceita apenas **5 perfis sintéticos**. Os dados de entrada da PoC devem ser mapeados conforme esses perfis antes de iniciar os testes de integração.
