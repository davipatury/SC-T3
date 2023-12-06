from hashlib import sha256
from math import ceil
from millerrabin import generate_prime
from os import urandom
from struct import pack

K = int(1024 / 8)
H_LENGTH = sha256().digest_size

def mdc(a, b):
    if b == 0:
        return a, 1, 0
    _mdc, x, y = mdc(b, a % b)
    return _mdc, y, x - (a // b) * y

def xor(al, bl):
    return [a ^ b for a, b in zip(al, bl)]

def generate_keys():
    prime_p = generate_prime()  
    prime_q = generate_prime()  

    modulus = prime_p * prime_q

    totient = (prime_p - 1) * (prime_q - 1)

    encryption_exponent = 65537

    out_mdc = mdc(encryption_exponent, totient)
    decryption_exponent = out_mdc[1]

    if decryption_exponent < 0: 
        decryption_exponent += totient

    public_key = [modulus, encryption_exponent]
    private_key = [modulus, decryption_exponent]

    return (public_key, private_key)

def rsa_encrypt(encoded_message, public_key):
    return [pow(i, public_key[1], public_key[0]) for i in encoded_message]

def rsa_decrypt(encoded_message, private_key):
    return [pow(i, private_key[1], private_key[0]) for i in encoded_message]

def form_data_block(l_hash, message):
    ps = bytearray([0 for _ in range(K - len(message) - (2 * H_LENGTH) - 2)])
    return l_hash + ps + b'\x01' + message

def oaep_encrypt(message, public_key, label=""):
    label = label.encode()
    max_len = K - 2 * H_LENGTH - 2
    if len(message) > max_len:
        raise ValueError(f"Mensagem muito longa para ser codificada utilizando OAEP. Tamanho máximo: {max_len}")
    l_hash = sha256(label).digest()
    db = form_data_block(l_hash, message)
    seed = urandom(H_LENGTH)
    db_mask = mgf1(seed, K - H_LENGTH - 1, sha256)
    masked_db = bytes(xor(db, db_mask))
    seed_mask = mgf1(masked_db, H_LENGTH, sha256)
    masked_seed = bytes(xor(seed, seed_mask))
    encoded_message = b'\x00' + masked_seed + masked_db
    return rsa_encrypt(encoded_message, public_key)

def oaep_decrypt(encoded_message, private_key, label=""):
    label = label.encode()
    encoded_message = rsa_decrypt(list(encoded_message), private_key)
    l_hash = sha256(label).digest()
    if len(encoded_message) != K:
        raise ValueError(f"Tamanho da mensagem codificada é inválido. O tamanho deve ser {K}.")
    masked_seed = bytes(encoded_message[1 : H_LENGTH + 1])
    masked_db = bytes(encoded_message[H_LENGTH + 1:])
    seed_mask = mgf1(masked_db, H_LENGTH, sha256)
    seed = bytes(xor(masked_seed, seed_mask))
    db_mask = mgf1(seed, K - H_LENGTH - 1, sha256)
    db = bytes(xor(masked_db, db_mask))
    l_hash_gen = db[:H_LENGTH]

    if l_hash_gen != l_hash:
        raise ValueError("Hash da mensagem decodificada é inválida.")
        
    message_start = H_LENGTH + db[H_LENGTH:].find(b'\x01') + 1
    message = db[message_start:]
        
    return message

def mgf1(seed, mask_len, hash_func):
    if mask_len > 2**32 * H_LENGTH:
        raise ValueError("Tamanho da máscara muito grande.")  
    T = bytearray()
    for counter in range(ceil(mask_len / H_LENGTH)):
        c = pack(">I", counter)
        T += hash_func(seed + c).digest()
    return T[:mask_len]
