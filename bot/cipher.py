import os
import base64
import hashlib
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(process)d - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("cipher")

# Constants
SALT_SIZE = 16
KEY_SIZE = 32  # AES-256 key size is 32 bytes
IV_SIZE = 12   # Initialization vector size for AES
TAG_SIZE = 16  # Authentication tag size for GCM mode
ITERATIONS = 100000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from the given password and salt using PBKDF2."""
    logger.debug("Deriving key using PBKDF2.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_aes_key_from_seed(key_seed: str, broker: str) -> str:
    """
    Generate a 256-bit AES key using the provided key_seed and broker.
    Returns the AES key as a hexadecimal string.
    """
    logger.debug("Generating AES key from seed.")
    salt = hashlib.sha256(broker.encode('utf-8')).digest()[:SALT_SIZE]
    aes_key = derive_key(key_seed, salt)
    return aes_key.hex()

def encrypt(key: str, plaintext: str) -> str:
    """Encrypt the plaintext using AES-256 in GCM mode."""
    logger.debug("Starting encryption process.")
    try:
        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)
        aes_key = derive_key(key, salt)
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        tag = encryptor.tag
        encrypted_message = base64.b64encode(salt + iv + ciphertext + tag).decode('utf-8')
        return encrypted_message
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise

def is_base64(encoded_string: str) -> bool:
    """Check if a string is valid Base64."""
    try:
        base64.b64decode(encoded_string, validate=True)
        return True
    except (ValueError, TypeError):
        return False

def decrypt(key: str, encrypted_message: str, caller: str) -> str:
    """Decrypt the ciphertext using AES-256 in GCM mode."""
    logger.debug("Starting decryption process.")
    if not is_base64(encrypted_message):
        logger.error(f"{caller} Invalid Base64 encoded message.")
        return "ERROR_DECRYPTION_FAILED"

    try:
        decoded_data = base64.b64decode(encrypted_message)
        logger.info(f"{caller} decoded_data: {decoded_data}")
        if len(decoded_data) < (SALT_SIZE + IV_SIZE + TAG_SIZE):
            logger.error(f"{caller} Decoded data length is insufficient for decryption.")
            return "ERROR_DECRYPTION_FAILED"

        salt = decoded_data[:SALT_SIZE]
        iv = decoded_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
        ciphertext = decoded_data[SALT_SIZE + IV_SIZE:-TAG_SIZE]
        tag = decoded_data[-TAG_SIZE:]
        aes_key = derive_key(key, salt)
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        logger.info(f"{caller} Decryption successful.")
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"{caller} Decryption failed: {e}")
        return "ERROR_DECRYPTION_FAILED"
