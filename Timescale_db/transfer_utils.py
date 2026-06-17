import base64
import hashlib
import logging
import os

import paramiko
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("transfer_utils")


def load_key() -> bytes:
    """Load AES-256 key from BACKUP_ENCRYPTION_KEY env var (64-char hex or base64, must be 32 bytes)."""
    raw = os.environ.get("BACKUP_ENCRYPTION_KEY", "")
    if not raw:
        raise ValueError("BACKUP_ENCRYPTION_KEY env var is not set")
    try:
        key = bytes.fromhex(raw)
        if len(key) == 32:
            return key
    except ValueError:
        pass
    try:
        key = base64.b64decode(raw)
        if len(key) == 32:
            return key
    except Exception:
        pass
    raise ValueError("BACKUP_ENCRYPTION_KEY must be 32 bytes (64-char hex or base64)")


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns 12-byte nonce + ciphertext (GCM tag is appended by library)."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-GCM decrypt. Input must be 12-byte nonce followed by ciphertext+tag."""
    return AESGCM(key).decrypt(data[:12], data[12:], None)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sftp_connect(host: str, port: int, username: str, password: str):
    """Open SSH + SFTP connection. Returns (ssh_client, sftp_client)."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
    ssh.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=60,
        banner_timeout=60,
        auth_timeout=60,
        look_for_keys=False,   # don't scan ~/.ssh/ for keys
        allow_agent=False,     # don't use SSH agent
    )
    return ssh, ssh.open_sftp()


def sftp_ensure_dir(sftp: paramiko.SFTPClient, path: str) -> None:
    """Recursively create remote directory if it doesn't exist."""
    if not path or path == "/":
        return
    try:
        sftp.stat(path)
        return
    except FileNotFoundError:
        pass
    parent = path.rstrip("/").rsplit("/", 1)[0]
    if parent and parent != path:
        sftp_ensure_dir(sftp, parent)
    try:
        sftp.mkdir(path)
    except IOError:
        pass  # created by another process between stat and mkdir
