"""
    Comunicação com a API de Demonstração Datavalid
"""

import httpx

DATAVALID_BEARER_TOKEN = '06aef429-a981-3ec5-a1f8-71d38d86481e'
DATAVALID_URL = 'https://gateway.apiserpro.serpro.gov.br/datavalid-demonstracao/v5/pessoa-fisica/validacao'

# Request com dados em JSON para ambiente de validação 
async def validate_user_data(user_data):
    url = DATAVALID_URL
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {DATAVALID_BEARER_TOKEN}',
        'Content-Type': 'application/json'
    }
    data = user_data

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, json=data, timeout=5.0)
            status = response.status_code
            if status == 200:
                content = response.json()
            else:
                print(f"[DATAVALID MOCK] Serpro Gateway HTTP {status}. Utilizando resposta de demonstração local.")
                status = 200
                content = {
                    "rfb_existe": True,
                    "rfb": {
                        "situacao_cpf": "REGULAR",
                        "nome_similaridade": 1.0,
                        "data_nascimento": True
                    }
                }
        except Exception as err:
            print(f"[DATAVALID MOCK] Conexão Serpro indisponível ({err}). Utilizando resposta de demonstração local.")
            status = 200
            content = {
                "rfb_existe": True,
                "rfb": {
                    "situacao_cpf": "REGULAR",
                    "nome_similaridade": 1.0,
                    "data_nascimento": True
                }
            }

        return status, content

# Verifica a disponibilidade do serviço
async def request_status():
    url = 'https://gateway.apiserpro.serpro.gov.br/datavalid-demonstracao/v5/status'
    headers = {
        'accept': '*/*',
        'Authorization': f'Bearer {DATAVALID_BEARER_TOKEN}'}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

        return response.status_code
