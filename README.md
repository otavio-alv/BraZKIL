# BraZKIL: um Framework híbrido para verificação de maioridade via SSI, DID/VC e Divulgação Seletiva em conformidade com o ECA Digital

O objetivo do artefato é demonstrar a viabilidade de implementaçao do BraZKIL, assim como o funcionamento completo do fluxo proposto.

**_Resumo do artigo_**:

A entrada em vigor do ECA Digital exige mecanismos confiáveis de verificação de idade, enquanto a LGPD restringe a coleta excessiva de dados pessoais. Este trabalho propõe o BraZKIL, uma arquitetura híbrida de verificação de maioridade baseada em identidade autossoberana, identificadores descentralizados, credenciais verificáveis e divulgação  seletiva. A arquitetura separa a validação inicial, apoiada em uma fonte autoritativa, das comprovações posteriores realizadas por uma credencial reutilizável sob controle do titular. Foi implementada uma prova de
conceito com SD-JWT VC, serviços locais, uma carteira digital de código aberto e integração ao ambiente de demonstração do Datavalid. Os resultados indicam a viabilidade funcional do fluxo e permitem que o verificador receba apenas a afirmação de maioridade, sem acesso a CPF, biometria, data de nascimento ou aos demais dados utilizados na validação inicial.

# Screenshots dos serviços em execução



# Estrutura do README.md

Este README.md está organizado nas seguintes seções:

* **Título e Resumo**: Título do projeto e um resumo conciso.
* **Estrutura do Projeto**: Breve visão geral da organização do código-fonte.
* **Funcionalidades**: Lista as principais funcionalidades e o que é possível ser feito com a ferramenta.
* **Selos Considerados**: Selos do SBSeg requeridos pelo artefato.
* **Informações básicas**: Ambiente de execução e componentes.
* **Dependências**: Lista os requisitos de software (Python, APIs e bibliotecas).
* **Preocupações com segurança**: Lista das preocupações com a segurança ao utilizar a ferramenta.
* **Instalação**: Instruções passo a passo para instalar as dependências e iniciar a ferramenta.
* **Teste mínimo**: Como executar o teste funcional.
* **Uso**: Descreve como o fluxo da ferramenta pode ser utilizado.
* **Experimentos**: Explicação detalhada de como reproduzir os experimentos apresentados no artigo.
* **Finalização dos Serviços**: Como interromper a execução.
* **Licença**: Informações sobre a licença do projeto.

# Estrutura do projeto

A estrutura do repositório organiza-se da seguinte forma:

```text
Proof-of-Concept BraZKIL/
├── issuer/                       # Middleware Emissor (OID4VCI)
│   ├── main.py                   # API FastAPI do Issuer (porta 8002)
│   ├── policy.py                 # Regras da política de aceitação
│   ├── portal.html               # UI do Portal do Titular
│   ├── schema.py                 # Schemas Pydantic do OID4VCI
│   └── sd_jwt.py                 # Gerador e validador de SD-JWT VC
│
├── shared/                       # Biblioteca compartilhada
│   └── did.py                    # Gerador e resolvedor de DIDs
│
├── validator_datavalid/          # Integrador com a API Datavalid
│   ├── client.py                 # Cliente HTTP assíncrono para a API REST Serpro
│   ├── main.py                   # API FastAPI do Validador (porta 8000)
│   ├── schema.py                 # Schemas Pydantic da consulta cadastral/biométrica
│   └── service.py                # Orquestrador da validação inicial e registro no VDR
│
├── vdr/                          # Registro de Confiança e Status (VDR)
│   ├── main.py                   # API FastAPI do VDR e DID Resolver W3C (porta 8001)
│   ├── models.py                 # Modelo SQLAlchemy do banco SQLite
│   ├── schema.py                 # Schemas Pydantic do VDR e da Status List
│   └── service.py                # Regras de negócio e gerenciamento de DIDs/Status
├── trust_registry.db             # Banco de dados SQLite (VDR)
│
├── verifier/                     # Verificador OID4VP (Loja de Vinhos)
│   ├── main.py                   # API FastAPI do Verifier (porta 8003)
│   ├── schema.py                 # Schemas Pydantic da Presentation Definition OID4VP
│   ├── verify.py                 # Núcleo criptográfico de validação
│   └── wine_shop.html            # UI web de demonstração da Loja Autentico Vini
│
└── wallet/                       # Módulo de carteira e integração walt.id
    └── waltid-identity/          # Submódulo da carteira open-source walt.id (v0.22)
```

# Funcionalidades

A Prova de Conceito (PoC) do BraZKIL foi desenvolvida para demonstrar de forma prática a arquitetura híbrida de verificação de maioridade. Com este artefato, é possível realizar as seguintes ações:

* **Validação de Identidade com Fonte Autoritativa:** Integrar-se ao ambiente de demonstração do Datavalid para confirmar a autenticidade dos dados cadastrais (como CPF, nome e data de nascimento), simulando o primeiro passo de confiança.
* **Emissão de Credenciais Verificáveis (SD-JWT):** Atuar como um *Issuer* (emissor) que gera uma credencial assinada contendo a afirmação restrita de maioridade (`age_over_18`), ocultando completamente dados sensíveis como o CPF e a data de nascimento exata.
* **Divulgação Seletiva (Privacy by Design):** Demonstrar, na prática, como o mecanismo de *Selective Disclosure* do SD-JWT permite revelar apenas o predicado necessário (se a pessoa é maior de idade) durante uma apresentação, impedindo o vazamento de informações adjacentes.
* **Gerenciamento de Identidade Autossoberana (SSI):** Utilizar uma carteira digital local (baseada no *walt.id*) para resgatar, armazenar e apresentar a credencial emitida de forma descentralizada.
* **Verificação Confiável (OID4VP):** Simular um provedor de serviços (ex: uma loja de vinhos virtual) que atua como *Verifier*, processando a apresentação da credencial, checando a prova de posse e aceitando ou negando o acesso baseado na verificação da assinatura e da idade.
* **Registro de Confiança e Revogação (VDR):** Operar um *Verifiable Data Registry* local que armazena Documentos DID (método `did:brazkil`), chaves públicas, registros de auditoria efêmeros e a lista de status (*Status List*) para permitir a checagem imediata de credenciais revogadas.

# Selos Considerados

Os selos considerados para este artefato são:

* **SeloD (Artefato Disponível)**
* **SeloF (Artefato Funcional)** 

# Informações básicas

## Ambiente de execução

- Sistema operacional: Linux (ex.: Ubuntu, Arch Linux, etc)
- Linguagem: Python 3.12.
- Execução prevista em máquina local com rede habilitada para acessar a API demonstrativa do DataValid.

## Componentes executáveis

- Serviço de validação DataValid.
- Serviço emissor.
- Carteira local baseada em `walt.id`.
- Serviço verificador.
- Registro VDR/status.


# Dependências

As dependências explicitamente mencionadas no artigo são:

- `cryptography==44.0.0` ou superior
- `python-jose==3.3.0` ou superior
- `httpx==0.28.1` ou superior
- `FastAPI==0.115.6` ou superior
- `SQLAlchemy==2.0.36` ou superior
- `walt.id==v0.22` ou superior

Dependências e recursos externos relevantes:

- API demonstrativa do DataValid: `https://apicenter.estaleiro.serpro.gov.br/documentacao/datavalid/demonstracao/`. O Bearer token de demonstração já está configurado no próprio código.
- Carteira `walt.id`: `https://github.com/walt-id/waltid-identity`.

# Preocupações com segurança

Este artefato faz chamadas reais ao ambiente de demonstração do DataValid durante a etapa de validação. então:

- utilize apenas dados sintéticos ou perfis de demonstração;
- não forneça dados pessoais reais;
- execute em ambiente isolado;
- trate chaves, credenciais e arquivos de status como sensíveis;
- considere que a PoC não cobre segurança operacional completa, proteção de chaves em hardware nem hardening de produção.

# Instalação

Siga os passos abaixo para preparar o ambiente de teste:

### Passo 1: Clonar o Repositório
```bash
git clone https://github.com/otavio-alv/cuddly-octo-robot.git
cd cuddly-octo-robot
```

### Passo 2: Criar um Ambiente Virtual (recomendado):
```bash
python3 -m venv venv
source venv/bin/activate
```

### Passo 3: Instalar as Dependências
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
Caso tenha problemas, instale individualmente:

```bash
pip install fastapi uvicorn httpx cryptography python-jose[cryptography] sqlalchemy pydantic
```

### Passo 4: Subir o Container Docker do walt.id
O projeto inclui o submódulo `wallet/waltid-identity/`, que fornece a stack local da carteira. Para iniciar os serviços do walt.id usados pela PoC:

```bash
cd wallet/waltid-identity/docker-compose
docker compose pull
docker compose up -d
```

Se preferir executar a stack com imagens construídas localmente, consulte o README do diretório `wallet/waltid-identity/docker-compose/`.

### Passo 5: Dar Permissão de Execução ao Script de start
```bash
chmod +x start_brazkil.sh
```

# Uso

A utilização do BraZKIL nesta Prova de Conceito foca em demonstrar o ciclo de vida completo de uma identidade descentralizada voltada à verificação de maioridade. O fluxo de uso principal pode ser reproduzido nas seguintes etapas:

1. **Ativação do Ambiente:** Inicie a stack da carteira *walt.id* via Docker e os microsserviços locais do BraZKIL por meio do script de inicialização (`start_brazkil.sh`). O próprio script já se encarrega de subir os contêineres e as APIs.
2. **Emissão da Credencial:** Como titular da identidade, você deve acessar o portal do *Issuer* simulado. Ao submeter dados de demonstração (que são validados contra a base governamental/Datavalid), o portal gera uma oferta de credencial (*credential offer*).
3. **Resgate na Carteira:** Com a oferta em mãos, você utiliza a interface da carteira digital (*walt.id*) para aceitar a emissão. A credencial, protegida criptograficamente (SD-JWT), é então armazenada no seu dispositivo.
4. **Apresentação e Verificação:** Ao acessar um serviço com restrição de idade (simulado pela aplicação "Loja de Vinhos" embutida), a plataforma solicita uma prova de maioridade. Você utiliza a sua carteira para assinar a prova e compartilhar *apenas* a afirmação de que é maior de idade (`age_over_18: true`).
5. **Auditoria e Monitoramento:** Um administrador ou avaliador pode consultar a API do VDR (*Verifiable Data Registry*) para atestar a comunicação, o registro de emissores e a revogação de credenciais, observando de perto a aplicação de Privacy by Design (sem persistência de dados pessoais sensíveis nos logs).

Os detalhes específicos de execução de endpoints, parâmetros e resultados obtidos na PoC encontram-se descritos na seção **Experimentos**, que espelha exatamente as tabelas de avaliação presentes no artigo acadêmico.

# Teste mínimo

O teste mínimo valida o fluxo completo da PoC com os 4 microsserviços locais e a wallet `walt.id`.

Para começar, simplesmente execute o script de inicialização na raiz do projeto:

```bash
./start_brazkil.sh
```

### Fluxo de validação
1. Abra e valide o status de cada serviço nos endpoints `/health`

2. Abra o portal do Issuer em `http://127.0.0.1:8002/` ou `http://127.0.0.1:8002/portal`, interaja com o formulário, valide as informações informadas e gere a `credential offer`.

3. Use a wallet do `walt.id` exposta pela stack local em `http://localhost:7101` para resgatar a credencial emitida.

4. Acesse o Verifier em `http://127.0.0.1:8003/`, faça a apresentação da credencial e confirme a resposta positiva da verificação.

5. Consulte os registros persistidos no VDR pelos próprios endpoints, principalmente:
   - `http://127.0.0.1:8001/vdr/issuers`
   - `http://127.0.0.1:8001/vdr/audits`
   - `http://127.0.0.1:8001/vdr/did/{did}`
   - `http://127.0.0.1:8001/vdr/credentials/status/{credential_id}`

# Experimentos

Esta seção guia o avaliador na reprodução exata das **reivindicações funcionais e dos resultados tabulados na Seção 5 do artigo** (Tabela 2 — Resultados da PoC BraZKIL e Tabela 3 — Latências).

### Experimento 1: Validação Integrada por Fonte Autoritativa (Datavalid) e Geração de Oferta (Issuer)
* **Objetivo:** Confirmar que o portal do Issuer realiza a consulta cadastral via Validador e gera uma oferta de credencial (*Credential Offer*).
* **Instruções:**
  1. Acesse o portal do Issuer no seu navegador: `http://127.0.0.1:8002/portal`
  2. Preencha o formulário com dados de demonstração (ex: CPF: `25774435016`, Nome: `Manuela Elisa da Mota`, Data de Nascimento: `1975-06-04`).
  3. Clique no botão para solicitar a credencial e aguarde a validação.
* **Verificação:** O portal retornará uma *Credential Offer* (geralmente em formato URI/texto) na tela. Nos logs do terminal, o Validador confirmará a comunicação com o Datavalid e o VDR mostrará a entrada da auditoria sem armazenar o nome, CPF ou data de nascimento.

![Tela do Portal do Issuer](image.png)

### Experimento 2: Resgate da Credencial na Wallet walt.id
* **Objetivo:** Demonstrar o uso da carteira digital para resgatar e armazenar a credencial emitida pelo Issuer.
* **Instruções:**
  1. Acesse a interface web da wallet local em: `http://localhost:7101`
  2. Na interface da carteira, acesse a funcionalidade para adicionar uma nova credencial (via "Scan/Add Credential").
  3. Utilize a opção de colar a *Credential Offer* obtida no Experimento 1.
  4. Aceite a oferta e confirme o recebimento da credencial na carteira.
* **Verificação:** A credencial de maioridade (SD-JWT VC) aparecerá listada na sua carteira, pronta para ser apresentada. Nos logs, o Issuer (porta 8002) registrará a emissão bem-sucedida.

![Tela da Wallet walt.id](image-placeholder-wallet.png) <!-- Por favor, coloque aqui o nome do arquivo da screenshot da wallet quando adicionar -->

### Experimento 3: Emissão da Credencial Verificável SD-JWT VC (Fluxo Automatizado OID4VCI)
* **Objetivo:** Validar o fluxo de emissão OID4VCI Pre-Authorized Code via script automatizado.
* **Comando:**
  ```bash
  python test_flow.py
  ```
* **Verificação:** O script executará o ciclo completo de emissão com o Issuer (porta 8002), demonstrando a troca do `pre_authorized_code`, a emissão do `c_nonce`, a assinatura da prova de posse e a entrega da credencial serializada no formato `vc+sd-jwt`.

### Experimento 4: Preservação de Privacidade e Minimização de Dados (OID4VP)
* **Objetivo:** Verificar que o Verificador recebe **estritamente** a afirmação etária `age_over_18`, mantendo a data de nascimento e o CPF ocultos.
* **Instruções:**
  1. Acesse no navegador a interface da Loja de Vinhos: `http://127.0.0.1:8003`.
  2. Abra a ferramenta de desenvolvedor do navegador (F12 > Network).
  3. Clique no botão **"Verificar Maioridade via BraZKIL"** (isso gerará uma solicitação de apresentação que deve ser lida/respondida com a wallet).
  4. Inspecione o payload enviado/processado na rota `/verifier/present`.
* **Verificação:** Observe que na propriedade `revealed_claims` apenas a chave `"age_over_18": true` é apresentada. O atributo `birthdate` permanece protegido pela árvore de hashes do SD-JWT.

![Tela do Verifier - Loja de Vinhos](image-1.png)

### Experimento 5: Verificação de Revogação de Credencial no VDR
* **Objetivo:** Demonstrar a recusa de uma credencial cuja validade foi cancelada na Status List do VDR.
* **Comando:**
  ```bash
  # 1. Atualizar o status da credencial para REVOKED no VDR (porta 8001)
  curl -s -X POST 'http://127.0.0.1:8001/vdr/credentials/status' \
    -H 'Content-Type: application/json' \
    -d '{"credential_id": "TEST_CREDENTIAL_01", "issuer_did": "did:brazkil:issuer", "status": "REVOKED"}' | python -m json.tool

  # 2. Consultar o status como o Verificador faria
  curl -s 'http://127.0.0.1:8001/vdr/credentials/status/TEST_CREDENTIAL_01' | python -m json.tool
  ```
* **Verificação:** O VDR retornará `"is_valid": false` e `"status": "REVOKED"`, o que faz a Etapa 2 da função `verify_presentation` interromper a verificação imediatamente com rejeição de acesso.

### Experimento 6: Avaliação Automatizada de Reivindicações e Latências (Tabelas 2 e 3)
* **Objetivo:** Reproduzir, através de um único script automatizado, todas as **reivindicações funcionais** e o **benchmark de latências** das operações do artigo.
  - **Reivindicações Funcionais (Tabela 2):** Valida a emissão do SD-JWT (protegendo atributos base), a apresentação via *Selective Disclosure* (divulgando somente `age_over_18`), a verificação de integridade OID4VP e bloqueio por revogação de status.
  - **Benchmark (Tabela 3):** Dispara `N=50` vezes a validação na API e `N=1000` vezes as demais operações da PoC, calculando média e desvio padrão.
* **Comando:**
  ```bash
  python evaluate_brazkil.py
  ```
* **Verificação:** O console exibirá um status `[PASS]` ou `[FAIL]` para cada uma das reivindicações, garantindo a corretude do modelo de minimização de dados, além de imprimir a tabela consolidada com as latências (média e desvio).

# Finalização dos Serviços

Ao concluir os testes, encerre as execuções instanciadas em segundo plano, como os serviços Python (via `uvicorn`) e a stack do Docker. Para isso, execute os seguintes comandos:
```bash
pkill -f uvicorn
cd wallet/waltid-identity/docker-compose/
docker compose down
```

# LICENSE

Este projeto está licenciado sob os termos da **MIT License**. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

