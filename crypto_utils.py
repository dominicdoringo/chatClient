from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# --- RSA utilities (Requirement: RSA-2048 for key exchange) ---
def generate_rsa_keypair():
    """
    Returns (private_key_bytes, public_key_bytes) in PEM format.
    Uses 2048-bit RSA under the hood.
    """
    key = RSA.generate(2048)        # <-- RSA.generate(2048) meets “Use RSA (2048-bit or higher)”
    return key.export_key(), key.publickey().export_key()

def encrypt_with_rsa(pubkey_bytes, message_bytes):
    """
    Encrypt message_bytes (bytes) with the given RSA public key bytes.
    """
    cipher = PKCS1_OAEP.new(RSA.import_key(pubkey_bytes))
    return cipher.encrypt(message_bytes)

def decrypt_with_rsa(privkey_bytes, encrypted_bytes):
    """
    Decrypt encrypted_bytes (bytes) with the given RSA private key bytes.
    """
    cipher = PKCS1_OAEP.new(RSA.import_key(privkey_bytes))
    return cipher.decrypt(encrypted_bytes)

# --- AES utilities (Requirement: AES-128 CBC with fresh IV + PKCS#7 padding) ---
BLOCK_SIZE = AES.block_size        # 16 bytes

def pad(data):
    """
    PKCS#7 padding to a multiple of BLOCK_SIZE.
    """
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    """
    Remove PKCS#7 padding.
    """
    return data[:-data[-1]]

def generate_aes_key():
    """
    Returns a fresh 16-byte AES key.
    """ 
    return get_random_bytes(16)     # <-- 16 bytes = 128-bit AES key

def encrypt_with_aes(aes_key, plaintext_str):
    """
    Encrypt plaintext_str under aes_key using AES-CBC.
    Returns Base64 of (IV || ciphertext).
    """
    iv = get_random_bytes(BLOCK_SIZE)   # <-- “random Initial Vector for each encryption”
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = pad(plaintext_str.encode('utf-8'))
    ct = cipher.encrypt(padded)
    # Base64-encode “IV||ciphertext” for safe UDP transport
    return base64.b64encode(iv + ct).decode('utf-8')

def decrypt_with_aes(aes_key, b64_ciphertext_str):
    """
    Decrypt Base64-encoded IV||ciphertext under aes_key.
    Returns the decrypted UTF-8 string.
    """
    data = base64.b64decode(b64_ciphertext_str)
    iv = data[:BLOCK_SIZE]
    ct = data[BLOCK_SIZE:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    return unpad(padded).decode('utf-8')
