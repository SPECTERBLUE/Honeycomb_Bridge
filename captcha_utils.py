import random
import string
import redis.asyncio as redis
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import config
import logging

# ---------------------------
# Configure logging
# ---------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ---------------------------
# Redis connection
# ---------------------------
redis_client_binary = redis.Redis(
    host="localhost",
    port=6389,
    decode_responses=False
)
redis_client = redis.Redis(
    host="localhost",
    port=6389,
    decode_responses=True
)

async def init_redis():
    """Call this during startup to verify Redis connection."""
    try:
        pong = await redis_client.ping()
        logger.info(f"Redis connected: {pong}")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}", exc_info=True)

async def close_redis():
    """Call this during shutdown."""
    await redis_client.close()
    logger.info("Redis connection closed")

# ---------------------------
# Symmetric key setup (AES-256)
# ---------------------------
AES_KEY = config.AES_KEY  # Must be 32 bytes
aesgcm = AESGCM(AES_KEY)
login_aesgcm = AESGCM(config.LOGIN_AESGCM_KEY)  # Must be 32 bytes
# ---------------------------
# Generate Captcha Text (6 chars)
# ---------------------------
def generate_captcha_text():
    digits = random.choices(string.digits, k=2)
    lower = random.choice(string.ascii_lowercase)
    upper = random.choice(string.ascii_uppercase)
    extra = random.choices(string.ascii_letters + string.digits, k=2)
    captcha_chars = digits + [lower, upper] + extra
    random.shuffle(captcha_chars)
    captcha_text = "".join(captcha_chars)
    logger.info(f"Generated captcha text: {captcha_text}")
    return captcha_text

# ---------------------------
# Encrypt / Decrypt using AES-GCM
# ---------------------------
def encrypt_aes_gcm(plaintext: str):
    iv = os.urandom(12)  # unique per captcha
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
    encrypted = {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext[:-16]).decode(),  # last 16 bytes = tag
        "tag": base64.b64encode(ciphertext[-16:]).decode()
    }
    logger.info(f"Encrypted captcha: {encrypted}")
    return encrypted

def decrypt_aes_gcm(encrypted: dict):
    if not encrypted or not all(k in encrypted for k in ("iv", "ciphertext", "tag")):
        # Log and return None to indicate invalid input
        logger.warning("Encrypted input is null or incomplete")
        return None

    try:
        iv = base64.b64decode(encrypted["iv"])
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        tag = base64.b64decode(encrypted["tag"])
        combined = ciphertext + tag
        plaintext = aesgcm.decrypt(iv, combined, None).decode()
        logger.info(f"Decrypted captcha text: {plaintext}")
        return plaintext
    except Exception as e:
        logger.warning(f"Failed to decrypt captcha: {e}", exc_info=True)
        return None
    
def encrypt_aes_gcm_downlink_login(plaintext: str):
    iv = os.urandom(12)  # unique per encryption
    ciphertext = login_aesgcm.encrypt(iv, plaintext.encode(), None)
    encrypted = {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext[:-16]).decode(),  # last 16 bytes = tag
        "tag": base64.b64encode(ciphertext[-16:]).decode()
    }
    logger.info(f"Encrypted login data: {encrypted}")
    return encrypted

def decrypt_aes_gcm_downlink_login(encrypted: dict):
    if not encrypted or not all(k in encrypted for k in ("iv", "ciphertext", "tag")):
        # Log and return None to indicate invalid input
        logger.warning("Encrypted input is null or incomplete")
        return None

    try:
        iv = base64.b64decode(encrypted["iv"])
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        tag = base64.b64decode(encrypted["tag"])
        combined = ciphertext + tag
        plaintext = login_aesgcm.decrypt(iv, combined, None).decode()
        logger.info(f"Decrypted captcha text: {plaintext}")
        return plaintext
    except Exception as e:
        logger.warning(f"Failed to decrypt : {e}", exc_info=True)
        return None