"""
    shared/did.py - Gerador de DIDs e DID Documents do método brazkil
    Responsável pela criação do par de chaves ES256 (EC P-256),
    geração do DID com UUID aleatório e construção do DID Document W3C.
"""

import uuid
import json
import base64
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1, EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat,
    NoEncryption, load_pem_private_key
)
from cryptography.hazmat.backends import default_backend


def _b64url(data: bytes) -> str:
    """Codifica bytes em Base64URL sem padding (padrão JWK/JWT)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_key_to_jwk(public_key: EllipticCurvePublicKey) -> dict:
    """
    Converte uma chave pública EC P-256 para o formato JWK (JSON Web Key).
    Usado no DID Document como 'publicKeyJwk'.
    """
    pub_numbers = public_key.public_numbers()
    x_bytes = pub_numbers.x.to_bytes(32, byteorder="big")
    y_bytes = pub_numbers.y.to_bytes(32, byteorder="big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(x_bytes),
        "y": _b64url(y_bytes),
    }


def generate_brazkil_did(name: str) -> dict:
    """
    Gera um novo DID do método 'brazkil' com par de chaves ES256.

    Retorna um dicionário com:
    - did: a string DID completa (ex: did:brazkil:550e8400-...)
    - did_document: o DID Document W3C completo em formato dict (incluindo o nome do emissor)
    - private_key_pem: a chave privada em formato PEM (guardar no ambiente do Middleware!)
    """
    # 1. Gera par de chaves EC P-256 (ES256)
    private_key = generate_private_key(SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # 2. Gera o DID com UUID v4 como method-specific identifier
    method_specific_id = str(uuid.uuid4())
    did = f"did:brazkil:{method_specific_id}"
    key_id = f"{did}#key-1"

    # 3. Serializa a chave privada em PEM (para o Middleware armazenar)
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ).decode()

    # 4. Constrói o DID Document W3C com metadados do Emissor (bloco service e name)
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "controller": did,
        "name": name,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_key_to_jwk(public_key)
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id]
    }

    return {
        "did": did,
        "did_document": did_document,
        "private_key_pem": private_key_pem,
    }


def resolve_public_key_from_did_document(did_document: dict) -> EllipticCurvePublicKey:
    """
    Extrai e reconstrói a chave pública EC P-256 a partir de um DID Document armazenado.
    Usado pelo Validator e pelo Verifier para verificação de assinaturas ES256.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1

    jwk = did_document["verificationMethod"][0]["publicKeyJwk"]
    x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big")

    pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    return pub_numbers.public_key(default_backend())


def sign_message(private_key_pem: str, message: bytes) -> bytes:
    """
    Assina uma mensagem em bytes utilizando a Chave Privada PEM do Emissor (Algoritmo ES256 / ECDSA-SHA256).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_signature(did_document: dict, message: bytes, signature: bytes) -> bool:
    """
    Reconstrói a Chave Pública a partir do DID Document W3C e valida a assinatura criptográfica ES256.
    Retorna True se a Chave Privada que assinou a mensagem corresponder exatamente à Chave Pública do DID Document.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    public_key = resolve_public_key_from_did_document(did_document)
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    result = generate_brazkil_did("Issuer Tata")
    print("=== 1. DID Gerado ===")
    print(f"DID:  {result['did']}")
    print("\n=== 2. DID Document (W3C) ===")
    print(json.dumps(result["did_document"], indent=2))
    print("\n=== 3. Chave Privada PEM ===")
    print(result["private_key_pem"])

    # 4. Teste de Validação Criptográfica Assinatura/Verificação ES256
    print("=== 4. Teste de Verificação Criptográfica da Chave ===")
    mensagem_teste = b"Desafio de Autenticidade BraZKIL - Maioridade Confirmada"
    
    # Emissor assina a mensagem com a Chave Privada PEM
    assinatura = sign_message(result["private_key_pem"], mensagem_teste)
    print(f"Mensagem de Teste: '{mensagem_teste.decode()}'")
    print(f"Assinatura ES256 (Base64): {_b64url(assinatura)}")

    # Verificador extrai a Chave Pública do DID Document e valida a assinatura
    valida = verify_signature(result["did_document"], mensagem_teste, assinatura)
    print(f"\nResultado da Verificação Cruzada (Chave Privada <-> DID Document): {valida}")

    # Teste de inviolabilidade: tentar verificar com mensagem alterada
    valida_falsificada = verify_signature(result["did_document"], b"Mensagem Alterada Falsificada", assinatura)
    print(f"Resultado com Mensagem Falsificada: {valida_falsificada}")


