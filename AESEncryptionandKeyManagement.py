from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# Use scrypt for key derivation
def derive_key(password: bytes, salt: bytes):
    return scrypt(password, salt, dklen=32, N=2**14, r=8, p=1)

# AES-GCM Encryption
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

# Example usage
password = b"mysecretpassword"
salt = get_random_bytes(16)
key = derive_key(password, salt)
encrypted_data = encrypt_data(b"Important secret data", key)
