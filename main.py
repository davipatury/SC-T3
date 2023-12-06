from base64 import b64encode, b64decode
from hashlib import sha3_256
from pickle import dumps, loads
from rsa import generate_keys, oaep_encrypt, oaep_decrypt

def main():
    message = input("Mensagem a ser cifrada: ").encode()
    print()
    # 1.a) geração de chaves (p e q primos com no mínimo de 1024 bits) 
    
    print("-- Gerando chaves pública e privada --")
    public_key, private_key = generate_keys()

    print("Public key: ", public_key)
    print("Private key: ", private_key)

    # 1.b) cifração/decifração assimétrica RSA usando OAEP
    encrypted_message = oaep_encrypt(message, public_key)   
    print("Mensagem cifrada: ", encrypted_message, "\n")

    decrypted_message = oaep_decrypt(encrypted_message, private_key)
    print("Mensagem decifrada: ", decrypted_message)

    # 2.a) calculo de hashes da mensagem em claro (função de hash SHA-3) 
    hash_sha3 = sha3_256(message).digest()
    print("-- Gerando hash SHA3 a partir da mensagem --")
    print("Hash: ", hash_sha3)

    # 2.b) assinatura da mensagem (cifração do hash da mensagem) 
    signature_message = oaep_encrypt(hash_sha3, public_key)
    print("-- Cifrando hash com OAEP --")

    # 2.c) formatação do resultado (caracteres especiais e informações para verificação em BASE64)
    b64_message_encoded = b64encode(dumps(signature_message))
    print("-- Codificando B64 --")
    print("BASE64 encoded message: ", b64_message_encoded)

    # 3.a) Parsing do documento assinado e decifração da mensagem (de acordo com a formatação usada, no caso BASE64) 
    b64_message_decoded = b64decode(b64_message_encoded)
    signature_message = loads(b64_message_decoded)
    print("-- Decodificando B64 --")

    # 3.b) Decifração da assinatura (decifração do hash) 
    decrypted_hash = oaep_decrypt(signature_message, private_key)
    print("-- Decifrando hash com OEAP --")

    # 3.c) Verificação (cálculo e comparação do hash do arquivo) 

    hash_sha3_file = sha3_256(message).digest()

    if hash_sha3_file == decrypted_hash:
        print("Verificação foi validada!")
    else:
        print("Falha ao validar verificação.")

main()
