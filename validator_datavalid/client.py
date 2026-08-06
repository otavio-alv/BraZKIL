"""
    Comunicação com a API de Demonstração Datavalid
"""

import httpx
import difflib

DATAVALID_BEARER_TOKEN = '06aef429-a981-3ec5-a1f8-71d38d86481e'
DATAVALID_URL = 'https://gateway.apiserpro.serpro.gov.br/datavalid-demonstracao/v5/pessoa-fisica/validacao'


def _get_mock_response(data):
    """
    Gera uma resposta mockada realista para demonstração, 
    avaliando os dados de entrada contra a base simulada.
    """
    cpf = data.get("cpf", "")
    validacao = data.get("validacao", {})
    name = validacao.get("nome", "")
    birth_date = validacao.get("data_nascimento", "")
    
    # Apenas o CPF de teste da PoC (Manuela) é considerado "existente" na RFB.
    if cpf != "25774435016":
        return {"rfb_existe": False, "rfb": None}
        
    # CPF válido, calcula similaridade do nome
    expected_name = "Manuela Elisa da Mota"
    similarity = difflib.SequenceMatcher(None, name.lower(), expected_name.lower()).ratio()
    
    # Verifica a data de nascimento
    expected_birth = "1975-06-04"
    birth_date_valid = (birth_date == expected_birth) if birth_date else True
    
    return {
        "rfb_existe": True,
        "rfb": {
            "situacao_cpf": True,
            "nome_similaridade": similarity,
            "data_nascimento": birth_date_valid
        }
    }


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
                print(f"[DATAVALID MOCK] Serpro Gateway HTTP {status}. Utilizando resposta de demonstração local (smart mock).")
                status = 200
                content = _get_mock_response(data)
        except Exception as err:
            print(f"[DATAVALID MOCK] Conexão Serpro indisponível ({err}). Utilizando resposta de demonstração local (smart mock).")
            status = 200
            content = _get_mock_response(data)

        return status, content

# Verifica a disponibilidade do serviço
async def request_status():
    url = 'https://gateway.apiserpro.serpro.gov.br/datavalid-demonstracao/v5/status'
    headers = {
        'accept': '*/*',
        'Authorization': f'Bearer {DATAVALID_BEARER_TOKEN}'}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code not in (200, 204):
                print(f"[DATAVALID MOCK] Serpro Gateway HTTP {response.status_code} no /status. Simulando 200 OK.")
                return 200
            return response.status_code
        except Exception as err:
            print(f"[DATAVALID MOCK] Falha ao verificar /status ({err}). Simulando 200 OK.")
            return 200
