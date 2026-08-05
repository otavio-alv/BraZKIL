# 1 - Validator (implementado)
* 1 - client.py: realiza a requisição direta à API Datavalid, com as informaões informadas pelo request
* 2- schema.py: define o esquema Pydant para recebimento JSON da request (variaveis, tipos, nomes), assim como o esquema da resposta JSON enviada para o Middleware de volta
* 3 - service.py: é a lógica de serviço principal. É ela quem recebe os esquemas, os valida, verifica se o Datavalid está disponível, faz a request de validação, estrutura a resposta higienizada

PONTOS A ALTERAR: 
* emissão de validation_id para cada verificação ocorrida no VDR (olhar auditoria promovida pelo datavalid);
* o request recebido deve ser assinado pelo Issuer autorizado e acompanhado de seu DID, de modo que o serviço possa verificar se a solicitação parte de um issuer autorizado.

# 2 - Issuer
* Ao ser emitida uma credencial, eu quero que o validation_id correspondente a validação daquela credencial seja armazenada

#   - Shared
## did.py
