from fastapi import FastAPI, HTTPException, Query, status, Path, Request, Depends, Body
from fastapi.responses import JSONResponse
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
import event_fetcher_parse as efp
import User_token
from SMTP_init import LoginAlertMailer
from pydantic import BaseModel, Field, field_validator, EmailStr
from pydantic import FieldValidationInfo
from pydantic import BaseModel, Field
from typing import Literal, Optional, Dict
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from auth import models,schemas,database,auth
from forgot_password import generate_reset_token, verify_reset_token
from typing import Optional
from Predictive_ML import fetch_assets_telemetry
from Predictive_ML import telemetry_processor
from fastapi import BackgroundTasks, HTTPException, Depends
from Predictive_ML.training_dataset_csv_creation import (
    create_training_dataset_csv
)
from Predictive_ML.ml.train_service import TrainService
from Predictive_ML.ml.model_store import load_model, delete_model as stored_delete_model, list_models as stored_list_models 
from Predictive_ML.ml.prediction import predict, predict_specific
from typing import List
import pyotp
import qrcode
import base64
from io import BytesIO
import json
import os
import logging
import subprocess
import requests
import config
import re
import uuid
import threading
import asyncio
import torch
from fastapi import Query
from fastapi.encoders import jsonable_encoder
from Notifications.worker import run_notification_worker
from Notifications.db_notification.models import Notification, NotificationAction
from Notifications.schema import CloseNotificationRequest, NotificationResponse
from Notifications.db_notification.crud import get_notifications, get_last_notification_timestamp, close_notification, get_notifications_by_status
import csv
import io
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import psycopg2
from fastapi import FastAPI, HTTPException, Query, status
from psycopg2.extras import execute_batch

from db_config import get_source_conn, get_target_conn
from Timescale_db.secure_export import secure_export
from Timescale_db.secure_import import COLUMNS, secure_import, find_latest_export
from transfer_utils import decrypt, encrypt, load_key, sftp_connect, sha256_hex

from captcha_utils import (
    encrypt_aes_gcm_downlink_login,
    redis_client,
    generate_captcha_text,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    decrypt_aes_gcm_downlink_login
)

from backup_scheduler import (
    _AVAILABLE as _SCHEDULER_AVAILABLE,
    _scheduler,
    apply_schedule as _apply_schedule,
    apply_nas_schedule as _apply_nas_schedule,
    apply_restore_schedule as _apply_restore_schedule,
    apply_import_schedule as _apply_import_schedule,
    start_backup_scheduler,
    SCHEDULE_FILE,
    NAS_SCHEDULE_FILE,
    RESTORE_SCHEDULE_FILE,
    IMPORT_BACKUP_SCHEDULE_FILE,
    IMPORT_PRODUCTION_SCHEDULE_FILE,
    IMPORT_BACKUP_HISTORY_FILE,
    IMPORT_PRODUCTION_HISTORY_FILE,
    NAS_HISTORY_FILE,
    BACKUP_HISTORY_FILE,
    RESTORE_HISTORY_FILE,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
SYNC_SCRIPT = os.path.join(_HERE, "Timescale_db", "sync.py")
NAS_CONFIG_FILE = os.path.join(_HERE, "Timescale_db", "nas_config.json")
_history_lock = threading.Lock()
_HISTORY_MAX = 1000

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

app = FastAPI(
    #docs_url=None,      # Disables Swagger UI (/docs)
    #redoc_url=None,     # Disables ReDoc (/redoc)
    #openapi_url=None    # Disables OpenAPI schema (/openapi.json)
)
CONFIG_FILE = "config-api.json"
JSON_FILE = "edgex_users.json"
SUPERSET_CONTAINER = "superset_app"

# Woker thread to pull notifications from edgex and store in DB
worker_started = False


@app.on_event("startup")
def start_worker():
    global worker_started

    if not worker_started:
        thread = threading.Thread(
            target=run_notification_worker,
            args=(5,),
            daemon=True
        )
        thread.start()
        worker_started = True

#AUTH_API ------------------------------------------------------------------

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/downlink/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate,current_user = Depends(auth.get_current_user) ,db: Session = Depends(get_db)):
    
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hashed_password = auth.get_password_hash(user.secret)
    new_user = models.User(email=user.email, secret=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

class MFAEnableReq(BaseModel):
    email: EmailStr


@app.post("/downlink/mfa/enable", summary="Enable MFA for a user by email")
def enable_mfa(
    req: MFAEnableReq,
    current_user = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enables MFA for the given user (provided by email in request).
    """

    # get target user
    db_user = db.query(models.User).filter(models.User.email == req.email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # if already enabled
    if db_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA already enabled for this user")

    # generate secret + URI
    mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(req.email, issuer_name="Honeycomb DL")

    # QR image
    qr_img = qrcode.make(provisioning_uri)
    buf = BytesIO()
    qr_img.save(buf, format='PNG')
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    # store secret
    db_user.mfa_secret = mfa_secret
    db.commit()

    return {
        "message": "MFA enabled successfully",
        "email": req.email,
        "mfa_secret": mfa_secret,
        "mfa_uri": provisioning_uri,
        "mfa_qr_base64_png": f"data:image/png;base64,{qr_base64}"
    }

    

@app.post("/downlink/mfa/status", summary="To check mfa status")
def status_mfa(current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """
    Returns whether MFA is enabled for the currently authenticated user.
    """

    is_enabled = bool(current_user.mfa_secret)

    return {
        "email": current_user.email,
        "mfa_enabled": is_enabled,
        "message": "MFA is enabled" if is_enabled else "MFA is disabled"
    }

class LoginRequest(BaseModel):
    captcha_id: str
    encrypted_input: dict  # { "iv": ..., "ciphertext": ..., "tag": ... }
    identity: dict
    secret: dict
    mfa_code: Optional[str] = None

@app.post("/downlink/login", response_model=schemas.Token)
async def login(
    data: LoginRequest = Body(...),
    db: Session = Depends(get_db)
):
    # 1. Verify captcha
    stored_captcha = await redis_client.get(data.captcha_id)
    try:
        decrypted_input = decrypt_aes_gcm(data.encrypted_input)
    except Exception:
        await redis_client.delete(data.captcha_id)
        return JSONResponse(status_code=400, content={"status":"error","message":"Invalid captcha input."})

    if not stored_captcha or stored_captcha != decrypted_input:
        await redis_client.delete(data.captcha_id)
        return JSONResponse(status_code=400, content={"status":"error","message":"Captcha mismatch or null input."})

    # Delete captcha after successful verification (single-use)
    await redis_client.delete(data.captcha_id)

    # 2. Decrypt username and password
    username = decrypt_aes_gcm_downlink_login(data.identity)
    password = decrypt_aes_gcm_downlink_login(data.secret)
    if not username or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid encrypted credentials")

    # 4. Authenticate
    user = auth.authenticate_user(db, username, password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials. Request a new captcha.")
    
    # MFA logic
    if user.mfa_secret:  # MFA enabled
        if not data.mfa_code:
            raise HTTPException(status_code=400, detail="MFA code required")
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(data.mfa_code):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    # else → MFA disabled → skip OTP

    # 5. Create access token
    access_token = auth.create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/downlink/mfa/reset")
def reset_mfa(current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    
    new_secret = pyotp.random_base32()
    totp = pyotp.TOTP(new_secret)
    provisioning_uri = totp.provisioning_uri(current_user.email, issuer_name="Honeycomb DL")

    qr_img = qrcode.make(provisioning_uri)
    buf = BytesIO()
    qr_img.save(buf, format='PNG')
    qr_base64 = base64.b64encode(buf.getvalue()).decode()

    # update DB
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    user.mfa_secret = new_secret
    db.commit()
    db.refresh(user)

    return {
        "status": "ok",
        "message": "MFA secret regenerated",
        "mfa_secret": new_secret,
        "mfa_uri": provisioning_uri,
        "mfa_qr_base64_png": f"data:image/png;base64,{qr_base64}"
    }

class MFADisableRequest(BaseModel):
    mfa_code: str

@app.post("/downlink/mfa/disable")
def disable_mfa(body: MFADisableRequest, current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    
    user = db.query(models.User).filter(models.User.id == current_user.id).first()

    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not enabled")

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(body.mfa_code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    user.mfa_secret = None
    db.commit()
    db.refresh(user)

    return {"status":"ok","message":"MFA disabled successfully"}

#mfa reset by email link
class forgot_mfa_request(BaseModel):
    email: EmailStr   # account email (primary login email)
    
@app.post("/downlink/forgot-mfa", summary="Send reset link to login-alert email for MFA reset")
def forgot_mfa(req: forgot_mfa_request, db: Session = Depends(get_db)):
    # Find user by primary account email
    user = db.query(models.User).filter(models.User.email == req.email).first()
    
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    # Check if login-alert email is set
    if not user.login_alert_email:
        raise HTTPException(
            status_code=400,
            detail="Login alert email not set for this user."
        )

    # Generate reset token
    token = generate_reset_token(req.email)

    # Reset link 
    reset_link = f"{config.FRONTEND_URL}/forgot-mfa?token={token}"

    # Send email 
    mailer = LoginAlertMailer()
    mailer.send_mfa_reset(user.login_alert_email, reset_link)

    return {"message": "If this email exists, an MFA reset link has been sent."}

class reset_mfa_request(BaseModel):
    token: str

@app.post("/downlink/reset-mfa-forgotpass", summary="Reset MFA using token")
def reset_mfa_email(req: reset_mfa_request, db: Session = Depends(get_db)):

    # Validate token
    email = verify_reset_token(req.token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Find user
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Reset MFA
    user.mfa_secret = None
    db.commit()
    db.refresh(user)

    return {"message": "MFA has been reset. You can now enable it again from your account settings."}
    
# APIs for login alerts and notifications can be added here
@app.post("/downlink/login-alert", summary="Set login alert email")
def set_login_alert_email(email: EmailStr, current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """
    Sets the login alert email for the currently authenticated user.
    """
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    user.login_alert_email = email
    db.commit()
    db.refresh(user)

    return {
        "status": "success",
        "message": f"Login alert email set to {email}"
    }

class LoginAlertEmailAddUserReq(BaseModel):
    default_email : EmailStr
    email: EmailStr

@app.post("/downlink/register-login-alert-email-adduser", summary="Set login alert email at add user when admin adds a new user")
def set_login_alert_email(body: LoginAlertEmailAddUserReq, current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """
    Sets the login alert email for the new user being added by the admin.
    """
    admin = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin user not found")
    
    user = db.query(models.User).filter(models.User.email == body.default_email).first()
    user.login_alert_email = body.email
    db.commit()
    db.refresh(user)

    return {
        "status": "success",
        "message": f"Login alert email set to {body.email} for user {body.default_email}"
    }
    
@app.get("/downlink/login-alert", summary="Get login alert email")
def get_login_alert_email(current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """
    Retrieves the login alert email for the currently authenticated user.
    """
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not user.login_alert_email:
        return {
            "status": "info",
            "message": "No login alert email set."
        }

    return {
        "status": "success",
        "login_alert_email": user.login_alert_email
    }

@app.post("/downlink/send_login-alert", summary="Send login alert email")
def send_login_alert(current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """
    Sends a login alert email to the user's configured email address.
    """
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not user.login_alert_email:
        raise HTTPException(status_code=400, detail="No login alert email set.")

    mailer = LoginAlertMailer()
    mailer.send_alert(user.login_alert_email)

    return {
        "status": "success",
        "message": f"Login alert email sent to {user.login_alert_email}"
    }

@app.post("/downlink/disable_login-alert", summary="Disable login alert email")
def disable_login_alert(current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """
    Disables the login alert email for the currently authenticated user.
    """
    user = db.query(models.User).filter(models.User.id == current_user.id).first()

    if not user.login_alert_email:
        return {
            "status": "info",
            "message": "Login alert email is already disabled."
        }

    user.login_alert_email = None
    db.commit()
    db.refresh(user)

    return {
        "status": "success",
        "message": "Login alert email has been disabled."
    }

    
# reset password by email link

def forgot_password_superset(email: EmailStr, new_password: str):

    # Superset password reset Python script executed inside container
    superset_password_change_script = """
from superset import create_app
from superset.extensions import db, security_manager
import sys

email = sys.argv[1]
new_password = sys.argv[2]

app = create_app()
with app.app_context():
    user = security_manager.find_user(email=email)
    if not user:
        print("USER_NOT_FOUND")
        sys.exit(1)

    security_manager.reset_password(user.id, new_password)
    db.session.commit()
    print("PASSWORD_UPDATED")
"""

    # Execute inside superset_app container
    result = subprocess.run(
        [
            "docker", "exec", "superset_app",
            "python3", "-c", superset_password_change_script,
            email, new_password
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    stdout = result.stdout.strip()

    if "PASSWORD_UPDATED" in stdout:
        return {
            "status": "success",
            "message": f"Password updated for '{email}'."
        }

    if "USER_NOT_FOUND" in stdout:
        raise HTTPException(
            status_code=404,
            detail=f"User '{email}' not found in Superset."
        )

    raise HTTPException(
        status_code=500,
        detail=f"Unexpected error: {stdout or result.stderr}"
    )
class ForgotPasswordRequest(BaseModel):
    email: EmailStr   # account email (primary login email)


@app.post("/downlink/forgot-password", summary="Send reset link to login-alert email")
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    # Find user by primary account email
    user = db.query(models.User).filter(models.User.email == req.email).first()
    
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    # Check if login-alert email is set
    if not user.login_alert_email:
        raise HTTPException(
            status_code=400,
            detail="Login alert email not set for this user."
        )

    # Generate reset token
    token = generate_reset_token(req.email)

    # Reset link 
    reset_link = f"{config.FRONTEND_URL}/forgot-password?token={token}"

    # Send email 
    mailer = LoginAlertMailer()
    mailer.send_password_reset(user.login_alert_email, reset_link)

    return {"message": "If this email exists, a password reset link has been sent."}

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

password_pattern = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)"
    r"(?=.*[!@#$%^&*()_\-+=\[{\]};:'\",<.>/?\\|`~]).{8,}$"
)

@app.post("/downlink/reset-password-forgotpass", summary="Reset account password using token")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    # Validate token
    email = verify_reset_token(req.token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    new_pw = req.new_password

    # 1) Check regex
    if not password_pattern.match(new_pw):
        raise HTTPException(
            status_code=400,
            detail=(
                "Password must be at least 8 characters long and include at least one lowercase "
                "letter, one uppercase letter, one digit, and one special character."
            )
        )

    # 2) Ensure password does NOT contain email username (before @)
    local_part = email.split("@")[0].lower()
    if local_part in new_pw.lower():
        raise HTTPException(
            status_code=400,
            detail="Password must not contain your email username."
        )

    # Find user
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Hash and update
    hashed_pw = auth.get_password_hash(new_pw)
    user.secret = hashed_pw
    db.commit()
    db.refresh(user)

    # Push to Magistrala service
    payload = {
        "email_id": email,
        "password": new_pw
    }

    try:
        response = requests.post(
            f"{config.USERS_SERVICE_URL}/users/reset-without-token",
            json=payload,
            timeout=10
        )
        if response.status_code != 201:
            raise HTTPException(
                status_code=502,
                detail=f"User service error: {response.text}"
            )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=503,
            detail=f"User service unreachable: {str(e)}"
        )

    forgot_password_superset(email, new_pw)

    return {"message": "Password updated successfully"}

# set to symmetric cyphering or asymmetric cyphering

@app.post("/downlink/chirpstack-data", summary="Sending data decripted from chirpstack using symetric cyphering, also converting the json format of the data to senml format")
async def chirpstack_data(data: Request):
    
    try:
        '''retrive incoming headers and body data'''
        headers = data.headers
        body = await data.body()
        logger.info(f"Received headers: {headers}")
        logger.info(f"Received body: {body}")
        
        for key, value in headers.items():
            logger.info(f"Header: {key} = {value}")
            
        # Get Device-Type header (case-insensitive)
        device_type = headers.get("device-type")

        if not device_type:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Device-Type header missing"
            )

        logger.info(f"Device-Type: {device_type}")
        
        
    except Exception as e:
        logger.error(f"Error reading request data: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request data"
        )    


        
#####################################################################################################        
CONFIG_FILE = "config.py"

class Cymetric_body(BaseModel):
    symetric: bool = Field(..., description="True for symmetric cyphering, False for asymmetric cyphering")
    identity: dict
    secret: dict

@app.post("/downlink/symetric-cyphering", summary="Set symmetric or asymmetric cyphering")
def set_cyphering_method(cymeric:Cymetric_body,current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    try:
        username = decrypt_aes_gcm_downlink_login(cymeric.identity)
        password = decrypt_aes_gcm_downlink_login(cymeric.secret)
        if not username or not password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid encrypted credentials")

        # 4. Authenticate
        user = auth.authenticate_user(db, username, password)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials. Request a new captcha.")
    
        # Update in-memory
        config.SYMETRIC_CYPHERING = cymeric.symetric

        # Read file
        with open(CONFIG_FILE, "r") as f:
            content = f.read()

        # Replace the value in file
        new_content = re.sub(
            r"SYMETRIC_CYPHERING\s*=\s*(True|False)",
            f"SYMETRIC_CYPHERING = {cymeric.symetric}",
            content
        )

        # Write back to file
        with open(CONFIG_FILE, "w") as f:
            f.write(new_content)

        return {
            "status": "success",
            "message": f"Cyphering method permanently set to {'symmetric' if cymeric.symetric else 'asymmetric'}",
            "persisted_value": cymeric.symetric
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist cyphering method: {str(e)}"
        )

@app.get("/downlink/me", response_model=schemas.UserResponse)
def read_users_me(current_user = Depends(auth.get_current_user)):
    return current_user

@app.put("/downlink/secret", response_model=schemas.UserResponse)
def update_secret(update: schemas.SecretUpdate, current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    # Query the user again within the current session
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    
    if not auth.verify_password(update.old_secret, user.secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Old password is incorrect")

    user.secret = auth.get_password_hash(update.new_secret)    
    db.commit()
    db.refresh(user)
    return user
    
@app.put("/downlink/identity", response_model=schemas.UserResponse)
def update_identity(update: schemas.IdentityUpdate, current_user = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    # Query the user again within the current session
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    
    existing_user = db.query(models.User).filter(models.User.email == update.new_email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use")

    user.email = update.new_email
    db.commit()
    db.refresh(user)
    return user

@app.get("/protected-data")
def protected_data(current_user = Depends(auth.validate_token)):
    return {"message": f"Hello, {current_user.email}! This is protected data."}


class UserRequestToken(BaseModel):
    username_enc: dict

@app.post("/downlink/get-token")
def get_token(request: UserRequestToken, auth: str = Depends(auth.validate_token)):
    """Return token for a given username from JSON file."""
    
    username = decrypt_aes_gcm_downlink_login(request.username_enc)

    if not os.path.exists(JSON_FILE):
        raise HTTPException(status_code=500, detail="Token store not found.")

    try:
        with open(JSON_FILE, "r") as f:
            data = json.load(f)

        for entry in data:
            if entry.get("username") == username:
                return {"token": entry.get("token", "")}

        raise HTTPException(status_code=404, detail="User not found.")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading token store: {e}")
    

@app.get("/downlink/edgex_token_list")
def get_token_list(auth: str = Depends(auth.validate_token)):
    """Return all tokens from JSON file."""
    if not os.path.exists(JSON_FILE):
        raise HTTPException(status_code=500, detail="Token store not found.")

    try:
        with open(JSON_FILE, "r") as f:
            data = json.load(f)
            return JSONResponse(content=data)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading token store: {e}")
    
@app.post("/downlink/edgex_token_list_update")
def update_token_list(data: dict, auth: str = Depends(auth.validate_token)):
    """
    Overwrite the JSON file with new token data.

    This function updates the token list stored in a JSON file. If the file does not exist,
    an HTTPException is raised. The function expects the input data to be in the following format:
    
    {
        "list": [
            {
                "username": "admin",
                "token": ""
            },
            {
                "username": "user9",
                "token": ""
            },
            {
                "username": "user1",
                "token": "1234567"
            }
        ]
    }

    Args:
        data (dict): A dictionary containing the new token list under the key "list".

    Returns:
        dict: A dictionary containing the status and a success message if the operation is successful.

    Raises:
        HTTPException: If the JSON file does not exist or if there is an error writing to the file.
    """
    """overwrite the JSON file with new data."""
    if not os.path.exists(JSON_FILE):
        raise HTTPException(status_code=500, detail="Token store not found.")

    try:
        with open(JSON_FILE, "w") as f:
            formatted_data = data.get("list", [])
            json.dump(formatted_data, f, indent=4)
            return {"status": "success", "message": "Token list updated successfully."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error writing to token store: {e}")
    
@app.get("/downlink/honeycomb_user_list")
def get_honeycomb_user_list( auth: str = Depends(auth.validate_token)):
   """Returns the list of user after runing update_user_list() function."""
   try:
        # Call the function to update the user list
        User_token.update_user_list()
        
        # Read the updated JSON file
        if os.path.exists(JSON_FILE):
            with open(JSON_FILE, "r") as f:
                data = json.load(f)
                return JSONResponse(content=data)
        else:
            raise HTTPException(status_code=500, detail="Token store not found.")
    
   except Exception as e:
       raise HTTPException(status_code=500, detail=f"Error reading token store: {e}") 
   
@app.post("/downlink/jwt_rotation", status_code=status.HTTP_200_OK)
def jwt_rotation( auth: str = Depends(auth.validate_token)):
    """
    Endpoint to trigger JWT rotation for all users.
    """
    try:
        User_token.Jwt_rotaion_all()
        return {
            "status": "success",
            "message": "JWT rotation completed successfully."
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during JWT rotation: {str(e)}"
        )

@app.post("/downlink/reset-keyrotation", status_code=status.HTTP_200_OK)
async def resetkeyrotation(data: dict, auth: str = Depends(auth.validate_token)):
    """
    Endpoint to send downlink data for resetting key rotation.
    """
    try:
        if efp.key_manager:
            efp.key_manager.rotate_keys()
            return {
                "status": "success",
                "message": "Key rotation triggered successfully",
                "data": data
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
                detail="KeyRotationManager not initialized"
            )

    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=str(ve)
        )
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail=str(pe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal Server Error: " + str(e)
        )
        
def save_update_config(update_frequency, dev_euid):
    """Save update frequency and dev_euid to a JSON file with exception handling."""
    try:
        data = {"update_frequency": update_frequency, "dev_euid": dev_euid}
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save configuration: {str(e)}"
        )


def get_update_info():
    """Read the update frequency and dev_euid from the JSON file with exception handling."""
    try:
        if not os.path.exists(CONFIG_FILE):
            raise FileNotFoundError("Configuration file not found.")
        
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Configuration file not found."
        )
    
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Configuration file is corrupted."
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read configuration: {str(e)}"
        )


@app.post("/downlink/update-frequency", status_code=status.HTTP_200_OK)
async def update_frequency(update_frequency: int, dev_euid: str, auth: str = Depends(auth.validate_token)):
    """
    Endpoint to send downlink data for updating frequency.
    """
    try:
        # Validate update_frequency (must be greater than 1 minute)
        if not isinstance(update_frequency, int):
            raise TypeError("Update frequency must be an integer.")
        if update_frequency <= 1:
            raise ValueError("Invalid update frequency value. It must be greater than 1.")
        logger.info(f"update_frequency,{update_frequency}")

        # Check if efp.key_manager exists and has the method
        if hasattr(efp, "key_manager") and hasattr(efp.key_manager, "send_update_frequency"):
            efp.key_manager.send_update_frequency(dev_euid, update_frequency)
        else:
            logger.error("Key manager is not available or method is missing.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Key manager service is unavailable."
            )

        # Save configuration
        save_update_config(update_frequency, dev_euid)

        return {
            "status": "success",
            "message": "Update frequency set successfully",
            "data_cycle": update_frequency,
            "dev_euid": dev_euid
        }

    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )

    except TypeError as te:
        logger.error(f"Type error: {te}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid data type. Frequency must be an integer."
        )

    except AttributeError as ae:
        logger.error(f"Attribute error: {ae}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal configuration error. Missing required attributes."
        )

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later."
        )


@app.get("/downlink/get-config", status_code=status.HTTP_200_OK)
async def get_config():
    """Endpoint to retrieve stored update frequency and dev_euid."""
    return get_update_info()

@app.post("/downlink/device-reboot", status_code=status.HTTP_200_OK)
async def device_reboot(dev_euid: str, auth: str = Depends(auth.validate_token)):
    """
    Endpoint to send downlink data for device reboot.
    """
    try:
        # software reboot
        if efp.key_manager:
            efp.key_manager.send_reboot_command(dev_euid)
            return {
                "status": "success",
                "message": "Device reboot command sent successfully",
                "dev_euid": dev_euid
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="KeyRotationManager not initialized"
            )

    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )
   
@app.post("/downlink/device-status", status_code=status.HTTP_200_OK)
async def device_status(dev_euid: str, auth: str = Depends(auth.validate_token)):
    """
    Endpoint to send downlink data for device status.
    """
    try:
        # current status of the connected device
        if efp.key_manager:
            efp.key_manager.send_device_status(dev_euid)
            return {
                "status": "success",
                "message": "Device status command sent successfully",
                "dev_euid": dev_euid
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="KeyRotationManager not initialized"
            )

    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )
        
@app.post("/downlink/log-level", status_code=status.HTTP_200_OK)
async def log_level(dev_euid: str,level: int, auth: str = Depends(auth.validate_token)):
    """
    Endpoint to set the logging level.
    """
    try:
        # Set the logging level
        if level > 4 :
            raise ValueError("Invalid log level. It must be between 0 and 4.")
        
        if efp.key_manager:
            efp.key_manager.set_log_level(dev_euid, level)
            return {
                "status": "success",
                "message": "Log level set successfully",
                "dev_euid": dev_euid,
                "level": level
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="KeyRotationManager not initialized"
            )
        
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except PermissionError as pe:   
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )
        
@app.post("/downlink/time-sync", status_code=status.HTTP_200_OK)
async def time_sync(dev_euid: str, auth: str = Depends(auth.validate_token)):
    """
    Endpoint to send downlink data for time synchronization.
    """
    try:
        # Time synchronization
        if efp.key_manager:
            efp.key_manager.send_time_sync(dev_euid)
            return {
                "status": "success",
                "message": "Time sync command sent successfully",
                "dev_euid": dev_euid
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="KeyRotationManager not initialized"
            )

    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )
    
@app.post("/downlink/reset-device", status_code=status.HTTP_200_OK)
async def reset_device(dev_euid: str, auth: str = Depends(auth.validate_token)):
    """
    Endpoint to send downlink data for device reset.(factory reset)
    """
    try:
        # Reset device
        if efp.key_manager:
            efp.key_manager.send_reset_factory(dev_euid)
            return {
                "status": "success",
                "message": "Device reset command sent successfully-factory reset",
                "dev_euid": dev_euid
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="KeyRotationManager not initialized"
            )

    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )
    
# Mapping container roles to their Docker names
CONTAINERS = {
    "edgex": config.CONTAINER_EDGEX_SECURITY_PROXY,     # Used for EdgeX user/password management
    "chirpstack": config.CONTAINER_CHIRPSTACK,            # ChirpStack container for CLI operations
    "root": config.CONTAINER_VAULT          # Container that holds the Vault token config
}

# Path to the Vault response JSON file inside the container
ROOT_FILE_PATH = config.VAULT_ROOT_PATH

# === FastAPI Endpoints ===

# Regex pattern for validating username
SAFE_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?$")

class UserRequest(BaseModel):
    username: str

def validate_username(username: str):
    if '\x00' in username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Null byte in username is not allowed."
        )
    if not SAFE_USERNAME_PATTERN.fullmatch(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid username format. Only letters, digits, '-', '_' are allowed."
        )

@app.post(
    "/downlink/generate-password",
    summary="Generate EdgeX Password",
    description="Generates a password for EdgeX.",
    response_description="The generated password for the user"
)
async def generate_password(user_req: UserRequest, auth: str = Depends(auth.validate_token)):
    username = user_req.username
    validate_username(username)

    try:

        # Secure, parameterized Docker command
        cmd = [
            "docker", "exec", CONTAINERS["edgex"],
            "./secrets-config", "proxy", "adduser",
            "--user", username,
            "--tokenTTL", "3650d",
            "--jwtTTL", "1d",
            "--useRootToken"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout.strip()

        parsed_output = json.loads(output)

        return {
            "status": "success",
            "message": "User password generated successfully",
            "password": parsed_output.get("password", "No password found")
        }

    except json.JSONDecodeError as je:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to parse Docker output: {output}"
        )
        
    except subprocess.CalledProcessError as cpe:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Docker command failed: {cpe}"
        )
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )

@app.post("/downlink/create-chirpstack-api-key/{name}", summary="Create ChirpStack API Key", description="Creates an API key in ChirpStack.")
async def create_api_key(name: str = Path(..., min_length=1, description="API key name"), auth: str = Depends(auth.validate_token)):
    """
    Uses the ChirpStack CLI inside the container to generate an API key.
    """
    try:
        # Validate API key name format
        if not name.strip() or name == ":name" or not re.match(r'^[a-zA-Z0-9_\-]+$', name):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or missing 'name' parameter"
            )

        logging.info(f"Creating ChirpStack API key for: {name}")

        # Parameterized Docker command (safe)
        cmd = [
            "docker", "exec",
            CONTAINERS["chirpstack"],
            "chirpstack",
            "--config", "/etc/chirpstack",
            "create-api-key",
            "--name", name
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout.strip()

        # Extract the token from command output
        match = re.search(r'token: (\S+)', output)
        token = match.group(1) if match else "No API key found"

        return {
            "status": "success",
            "message": "API key created successfully",
            "api_key": token
        }

    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create API key: {e.stderr.strip()}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )

@app.get("/downlink/tokens", summary="Get Root Token", description="Extracts the last root token and returns it as JSON.")
def get_tokens( auth: str = Depends(auth.validate_token)):
    """
    Reads the root token from the Vault response JSON file inside the container.
    """
    try:

        # Parameterized docker exec command as list
        cmd = ["docker", "exec", CONTAINERS["root"], "cat", ROOT_FILE_PATH]

        output = subprocess.check_output(cmd, text=True).strip()

        parsed_output = json.loads(output)
        root_token = parsed_output.get("root_token")
        if not root_token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Root token not found in the JSON file."
            )

        return {
            "status": "success",
            "message": "Root token retrieved successfully",
            "root_token": root_token
        }

    except json.JSONDecodeError as je:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to parse JSON from Vault response."
        )
    except subprocess.CalledProcessError as cpe:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Docker command failed: {cpe}"
        )
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )

''' This section is for creating a new user in Apache Superset using Docker exec.
   It uses the Superset CLI to create a user with specified attributes. '''

class ConflictError(Exception):
    pass


class UserCreate(BaseModel):
    username: str = Field(..., example="string")
    first_name: str = Field("", example="string")
    last_name: str = Field("", example="string")
    email: str = Field(..., example="string")   
    password: str = Field(..., example="string")
    role: str = Field(..., example="Admin")

    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        email_regex = re.compile(
            r'^[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        if not email_regex.match(v):
            raise ValueError("Invalid email format")
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str, info: FieldValidationInfo) -> str:
        values = info.data
        email = values.get('email', '').lower()
        password = v.lower()

        # Identity restriction for @gmail.com
        if email.endswith('@gmail.com'):
            local_part = email.split('@')[0]

            if any(sep in local_part for sep in ['.', '-', '_']):
                parts = re.split(r'[._-]', local_part)
                for part in parts:
                    if part and part in password:
                        raise ValueError(
                            f"Password must not contain parts of your email address: '{part}'"
                        )
            else:
                if local_part in password:
                    raise ValueError(
                        f"Password must not contain the email local part: '{local_part}'"
                    )

        # Password strength checks
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')

        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')

        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')

        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')

        if not re.search(r'\W', v):
            raise ValueError('Password must contain at least one special character')

        return v


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError, auth: str = Depends(auth.validate_token)):
    errors = exc.errors()
    error_messages = []

    for error in errors:
        loc = " -> ".join(str(i) for i in error['loc'] if i != 'body')
        msg = error['msg']
        error_messages.append(f"{loc}: {msg}")

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "status": "error",
            "code": 400,
            "detail": "Validation Failed",
            "errors": error_messages
        }
    )


@app.post("/downlink/create_superset_user", status_code=status.HTTP_200_OK)
async def create_superset_user(user: UserCreate, auth: str = Depends(auth.validate_token)):
    try:
        if not user.username or not user.email or not user.password:
            raise ValueError("Username, email, and password are required.")

        docker_command = [
            "docker", "exec", SUPERSET_CONTAINER,
            "superset", "fab", "create-user",
            "--username", user.username,
            "--firstname", user.first_name,
            "--lastname", user.last_name,
            "--email", user.email,
            "--password", user.password,
            "--role", user.role
        ]

        result = subprocess.run(docker_command, capture_output=True, text=True)
        stdout = result.stdout.strip().lower()
        stderr = result.stderr.strip().lower()

        if "no such container" in stderr or "not found" in stderr:
            raise FileNotFoundError("Superset container or command not found.")

        if "already exists" in stdout or "already exists" in stderr:
            raise ConflictError(f"User with email '{user.email}' already exists.")

        if result.returncode != 0:
            raise RuntimeError(
                f"Docker command failed.\nSTDOUT: {stdout}\nSTDERR: {stderr}"
            )

        return {
            "status": "success",
            "code": 200,
            "message": f"User '{user.username}' created successfully.",
            "stdout": result.stdout.strip()
        }

    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )

    except FileNotFoundError as fnfe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(fnfe)
        )

    except ConflictError as ce:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(ce)
        )

    except RuntimeError as re_err:
        clean_msg = str(re_err).replace('\n', ' ')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + clean_msg
        )


class PasswordChangeRequest(BaseModel):
    email: EmailStr
    old_password: str 
    new_password: str 
    confirm_password: str


@app.post("/downlink/change_password", status_code=status.HTTP_200_OK)
async def change_password(body: PasswordChangeRequest, auth: str = Depends(auth.validate_token)):
    # 1. Password pattern: At least 8 chars, one uppercase, one lowercase, one digit, one special char
    password_pattern = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)"
        r"(?=.*[!@#$%^&*()_\-+=\[{\]};:'\",<.>/?\\|`~]).{8,}$"
    )
    if not password_pattern.match(body.new_password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long, "
                   "contain at least one uppercase letter, one lowercase letter, "
                   "one digit, and one special character."
        )

    # 2. Confirm new_password and confirm_password match
    if body.new_password != body.confirm_password:
        raise HTTPException(
            status_code=400,
            detail="New password and confirm password do not match."
        )

    # 3. Prevent reusing the old password
    if body.old_password == body.new_password:
        raise HTTPException(
            status_code=400,
            detail="New password cannot be the same as the old password."
        )

    # 4. Gmail-specific logic: Reject if new password contains local part or any split parts
    email = body.email.lower()
    new_password_lower = body.new_password.lower()

    if email.endswith("@gmail.com"):
        local_part = email.split("@")[0]

        # Full local part not allowed in password
        if local_part in new_password_lower:
            raise HTTPException(
                status_code=400,
                detail="Password cannot contain your emal username."
            )

        # If contains '.', '_', or '-', check individual parts
        if any(sep in local_part for sep in ['.', '_', '-']):
            parts = re.split(r"[._-]", local_part)
            for part in parts:
                if part and part in new_password_lower:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Password cannot contain parts of your email address: '{part}'"
                    )

    # 5. Docker command to change Superset user password
    superset_password_change_script = """
from superset import create_app
from superset.extensions import db, security_manager
from werkzeug.security import check_password_hash
import sys

email = sys.argv[1]
old_password = sys.argv[2]
new_password = sys.argv[3]

app = create_app()
with app.app_context():
    user = security_manager.find_user(email=email)
    if not user or not check_password_hash(user.password, old_password):
        print('Old password is incorrect')
        sys.exit(1)
    security_manager.reset_password(user.id, new_password)
    db.session.commit()
    print('Password updated')
"""

    try:
        result = subprocess.run(
            [
                "docker", "exec", SUPERSET_CONTAINER,
                "python3", "-c", superset_password_change_script,
                body.email, body.old_password, body.new_password
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except subprocess.CalledProcessError:
        raise HTTPException(
            status_code=404,
            detail=f"Docker container '{SUPERSET_CONTAINER}' not found or failed to exec command."
        )

    if result.returncode != 0:
        if "old password is incorrect" in result.stdout.lower():
            raise HTTPException(status_code=401, detail="Old password is incorrect.")
        raise HTTPException(
            status_code=500,
            detail="Docker exec error: " + (result.stderr.strip() or result.stdout.strip())
        )

    output = result.stdout.strip()

    if "password updated" in output.lower():
        return {
            "status": "success",
            "code": 200,
            "message": f"Password updated for '{body.email}'.",
            "stdout": output
        }

    raise HTTPException(
        status_code=500,
        detail="Unexpected output: " + output
    )
class CaptchaVerifyRequest(BaseModel):
    captcha_id: str
    encrypted_input: dict  # { "iv": ..., "ciphertext": ..., "tag": ... }
    
@app.post("/downlink/captcha")

async def generate_captcha():
    try:
        captcha_text = generate_captcha_text()
        captcha_id = str(uuid.uuid4())

        # Save captcha in Redis (expires in 5 minutes)
        await redis_client.setex(captcha_id, 300, captcha_text)
        logger.info(f"Generated CAPTCHA: id={captcha_id}")
        # Encrypt captcha
        encrypted = encrypt_aes_gcm(captcha_text)

        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "message": "Captcha generated successfully",
                "captcha_id": captcha_id,
                "encrypted_captcha": encrypted
            }
        )

    except ValueError as ve:
        logger.warning(f"ValueError during CAPTCHA generation: {ve}")
        return JSONResponse(
            status_code=400,
            content={"status": "error", "detail": str(ve)}
        )

    except PermissionError as pe:
        logger.warning(f"PermissionError during CAPTCHA generation: {pe}")
        return JSONResponse(
            status_code=403,
            content={"status": "error", "detail": str(pe)}
        )

    except Exception as e:
        logger.error(f"Unexpected error during CAPTCHA generation: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "detail": "Internal Server Error: " + str(e)}
        )

# ---------------------------
# Verify Captcha Endpoint
# ---------------------------
@app.post("/downlink/captcha/verify")
async def verify_captcha(request: CaptchaVerifyRequest, auth: str = Depends(auth.validate_token)):
    try:
        stored_captcha = await redis_client.get(request.captcha_id)
        if not stored_captcha:
            logger.info(f"Captcha expired or invalid: id={request.captcha_id}")
            raise ValueError("Captcha expired or invalid")

        decrypted_input = decrypt_aes_gcm(request.encrypted_input)

        if not decrypted_input or stored_captcha != decrypted_input:
    # Generate new captcha if mismatch or null input
            new_captcha = generate_captcha_text()
            await redis_client.setex(request.captcha_id, 300, new_captcha)
            encrypted_new = encrypt_aes_gcm(new_captcha)
            logger.info(f"Captcha mismatch or null input for id={request.captcha_id}. New captcha generated.")

            return JSONResponse(
            status_code=400,  
            content={
                "status": "error",
                "message": "Captcha mismatch or null input. New captcha generated.",
                "captcha_id": request.captcha_id,
                "encrypted_captcha": encrypted_new
            }
        )

        # Success: delete captcha from Redis
        await redis_client.delete(request.captcha_id)
        logger.info(f"Captcha verified successfully: id={request.captcha_id}")
        return {"status": "ok", "message": "Captcha verified successfully"}

    except ValueError as ve:
        logger.warning(f"Captcha verification failed: {ve}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except PermissionError as pe:
        logger.warning(f"Permission error during captcha verification: {pe}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Unexpected error during captcha verification: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error: " + str(e)
        )

##############################################################################################
# predictive maintainance apis below
##############################################################################################

# ------------------ REQUEST MODELS ------------------ #

class ThresholdConfig(BaseModel):
    sensor: str
    prefailure: float
    failure: float


class AssetTelemetryRequest(BaseModel):
    asset_id: str
    window_length: int = Field(
        ...,
        gt=0,
        description="Window length in seconds for aggregation"
    )
    thresholds: list[ThresholdConfig]


# ------------------ API ------------------ #

@app.post(
    "/downlink/predictive_ML/assets/telemetry",
    summary="Fetch telemetry, aggregate, label and generate training CSV"
)
async def get_asset_telemetry(
    payload: AssetTelemetryRequest,
    current_user=Depends(auth.get_current_user)
):

    asset_id = payload.asset_id
    window_length = payload.window_length

    try:
        # 🔹 Convert threshold list → fast lookup dict
        threshold_map = {
            t.sensor: {
                "prefailure": t.prefailure,
                "failure": t.failure
            }
            for t in payload.thresholds
        }

        telemetry_fetcher = fetch_assets_telemetry.FetchAssetsTelemetry()
        telemetry_data = telemetry_fetcher.get_telemetry_data_asset(asset_id)

        if telemetry_data is None:
            return {
                "status": "error",
                "message": "Failed to fetch telemetry data for the asset."
            }

        # 🔹 Aggregate
        processor = telemetry_processor.TelemetryProcessor(telemetry_data)

        processed_data = processor.aggregate_window(
            window_size_sec=window_length
        )

        # 🔹 Handle missing windows (your existing logic)
        processed_data = telemetry_processor.handle_missing_windows(
            processed_data
        )

        # 🔹 Apply labeling
        labeled_data = telemetry_processor.label_data(
            aggregated_data=processed_data,
            threshold_map=threshold_map
        )
        
        # 🔹 Store labeled data in Redis
        await redis_client.set(f"Window_length:{asset_id}", window_length)
        await redis_client.set(f"threshold_map:{asset_id}", json.dumps(threshold_map))
        
        # 🔹 Store CSV for ML training
        dataset_path = create_training_dataset_csv(
            processed_data=labeled_data,
            asset_id=asset_id,
            window_length=window_length
        )

        return {
            "status": "success",
            "asset_id": asset_id,
            "window_length": window_length,
            "count": len(labeled_data),
            "dataset_path": dataset_path,
            "data": labeled_data
        }

    except Exception as e:
        logging.error(
            f"Error processing telemetry for asset {asset_id}: {e}",
            exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail="Internal server error while processing telemetry data."
        )

class ThingTelemetryRequest(BaseModel):
    thing_id: str
    asset_id: str
    window_length: int = Field(
        ...,
        gt=0,
        description="Window length in seconds for aggregation"
    )
    
@app.post(
    "/downlink/predictive_ML/things/telemetry",
    summary="Fetch telemetry data for a thing within an asset"
)
def get_thing_telemetry(
    payload: ThingTelemetryRequest,
    current_user = Depends(auth.get_current_user)
):
    """
    Fetches all telemetry data for a given thing ID within a specified asset ID.
    """

    thing_id = payload.thing_id
    asset_id = payload.asset_id
    window_length = payload.window_length

    try:
        telemetry_fetcher = fetch_assets_telemetry.FetchAssetsTelemetry()
        telemetry_data = telemetry_fetcher.get_telemetry_data_things(thing_id, asset_id)

        if telemetry_data is None:
            return {
                "status": "error",
                "message": "Failed to fetch telemetry data for the thing."
            }
        
        # process telemetry
        processor = telemetry_processor.TelemetryProcessor(telemetry_data)
        processed_data_thing = processor.aggregate_window(
            window_size_sec=window_length
        )

        return {
            "status": "success",
            "thing_id": thing_id,
            "asset_id": asset_id,
            "count": len(telemetry_data),
            "data": processed_data_thing
        }

    except Exception as e:
        logging.error(f"Error fetching telemetry for thing {thing_id} in asset {asset_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error while fetching telemetry data."
        )

########################################################################
# list of the csv files required for training
########################################################################
@app.get(
    "/downlink/predictive_ML/datasets",
    summary="List all available training CSV datasets"
)
def list_training_datasets(
    current_user=Depends(auth.get_current_user)
) -> dict:

    try:
        BASE_DATASET_DIR = "data/training_datasets"
        if not os.path.exists(BASE_DATASET_DIR):
            raise HTTPException(
                status_code=404,
                detail="Dataset directory not found"
            )

        files = [
            f for f in os.listdir(BASE_DATASET_DIR)
            if f.endswith(".csv")
        ]

        datasets: List[dict] = []

        for file in files:
            full_path = os.path.join(BASE_DATASET_DIR, file)

            datasets.append({
                "file_name": file,
                "path": full_path,
                "size_kb": round(os.path.getsize(full_path) / 1024, 2),
                "last_modified": os.path.getmtime(full_path)
            })

        return {
            "status": "success",
            "dataset_dir": BASE_DATASET_DIR,
            "count": len(datasets),
            "datasets": datasets
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error listing datasets: {str(e)}"
        )
######################################################################
# Model training and management APIs below
######################################################################
class TrainModelRequest(BaseModel):
    model_name: str = Field(..., description="User-defined unique model name")
    asset_id: str
    dataset_path: str
    model_type: Literal["random_forest", "xgboost", "lstm"]
    target_column: str  # "label" or the name of the target column in the dataset
    horizon: Literal["1h", "6h", "24h"]

# ─────────────────────────────────────────────
# Key builders
# ─────────────────────────────────────────────

def train_job_key(job_id: str, model_name: str, target_column: str) -> str:
    return f"train:{job_id}:{model_name}:{target_column}"

def pred_job_key(job_id: str, model_name: str, asset_id: str) -> str:
    return f"pred:{job_id}:{model_name}:{asset_id}"

@app.post("/downlink/predictive_ML/train")
async def submit_training_job(
    payload: TrainModelRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(auth.get_current_user)
):
    existing_models = await stored_list_models()
    if payload.model_name in existing_models:
        raise HTTPException(status_code=400, detail="Model name already exists")
 
    job_id = str(uuid.uuid4())
    key = f"train:{job_id}:{payload.model_name}:{payload.target_column}"
 
    await redis_client.set(key, json.dumps({
        "status": "queued",
        "model_name": payload.model_name,
        "target_column": payload.target_column
    }))
 
    async def _run():
        try:
            await redis_client.set(key, json.dumps({"status": "running"}))

            window_length = await redis_client.get(f"Window_length:{payload.asset_id}")
            freq_minutes = int(window_length) / 60 if window_length else 5.0

            train_service = TrainService()
            result = await train_service.train(
                csv_path=payload.dataset_path,
                target_column=payload.target_column,
                user_model_name=payload.model_name,
                algorithm=payload.model_type,
                horizon=payload.horizon,
                freq_minutes=freq_minutes
            )
            await redis_client.set(key, json.dumps({
                "status": "completed",
                "model_name": payload.model_name,
                "target_column": payload.target_column,
                "metrics": result["metrics"],
                "metadata": result["metadata"],
                "sensor_correlation": result["sensor_correlation"],
                "label_info": result["label_info"]
            }))
        except Exception as e:
            logging.error(f"Training failed: {e}", exc_info=True)
            await redis_client.set(key, json.dumps({"status": "failed", "error": str(e)}))
 
    background_tasks.add_task(_run)
    return {
        "status": "accepted",
        "job_id": job_id,
        "job_key": key,
        "message": "Training started in background"
    }

@app.get("/downlink/predictive_ML/status/train/{job_id}")
async def get_train_status(job_id: str, current_user=Depends(auth.get_current_user)):
    keys = await redis_client.keys(f"train:{job_id}:*")
    if not keys:
        raise HTTPException(status_code=404, detail="Train job not found")
    data = await redis_client.get(keys[0])
    return {"job_key": keys[0], **json.loads(data)}

############################################################################
# Model store in redis using pickle for model and JSON for metadata. This allows storing complex ML models and their associated metadata efficiently.
############################################################################

@app.get("/downlink/predictive_ML/models", summary="List stored ML models")
async def list_models(current_user=Depends(auth.get_current_user)):
    
    models =  await stored_list_models()

    return {
        "status": "success",
        "models": models
    }

@app.get("/downlink/predictive_ML/models/{model_name}")
async def get_model_metadata(
    model_name: str,
    current_user=Depends(auth.get_current_user)
):
    
    model, metadata = await load_model(model_name)

    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    return {
        "status": "success",
        "model_name": model_name,
        "metadata": metadata
    }
    
@app.delete("/downlink/predictive_ML/models/{model_name}")
async def delete_model(
    model_name: str,
    current_user=Depends(auth.get_current_user)
):
    
    await stored_delete_model(model_name)

    return {
        "status": "success",
        "message": f"Model '{model_name}' deleted"
    }

###################################################################################################################
#APis for prediction of telemetry data using the stored models can be added here. The endpoint would accept telemetry data, load the appropriate model from Redis, and return predictions based on the input data.
###################################################################################################################
# Aslo the user will need to specify the model that is saved in the redis database to be used for the prediction. The model will be loaded from the redis database and used to make predictions on the input telemetry data. The predictions can then be returned in the response of the API call.
class PredictRequest(BaseModel):
    model_name: str
    asset_id: str
    
@app.post("/downlink/predictive_ML/predict", summary="Run prediction using stored ML model")
async def predict_api(
    payload: PredictRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(auth.get_current_user)
):
    job_id = str(uuid.uuid4())
    key = f"pred:{job_id}:{payload.model_name}:{payload.asset_id}"
 
    await redis_client.set(key, json.dumps({
        "status": "queued",
        "model_name": payload.model_name,
        "asset_id": payload.asset_id
    }))
 
    async def _run():
        try:
            await redis_client.set(key, json.dumps({"status": "running"}))
            result = await predict(model_name=payload.model_name, asset_id=payload.asset_id)
            if result is None:
                await redis_client.set(key, json.dumps({
                    "status": "failed",
                    "error": "No telemetry data found"
                }))
                return
            await redis_client.set(key, json.dumps({
                "status": "completed",
                "model_name": payload.model_name,
                "asset_id": payload.asset_id,
                "result": result
            }))
        except Exception as e:
            logging.error(f"Predict job failed: {e}", exc_info=True)
            await redis_client.set(key, json.dumps({"status": "failed", "error": str(e)}))
 
    background_tasks.add_task(_run)
    return {
        "status": "accepted",
        "job_id": job_id,
        "job_key": key,
        "message": "Prediction started in background"
    }

@app.get("/downlink/predictive_ML/status/pred/{job_id}")
async def get_pred_status(job_id: str, current_user=Depends(auth.get_current_user)):
    keys = await redis_client.keys(f"pred:{job_id}:*")
    if not keys:
        raise HTTPException(status_code=404, detail="Prediction job not found")
    data = await redis_client.get(keys[0])
    return {"job_key": keys[0], **json.loads(data)}
 


#########################################################################################
# apis for brousing and managing the redis database for predictive maintenance models and telemetry data can be added here. This would include endpoints to list all keys, view specific key values, and delete keys from the Redis database. These APIs would help users manage their stored models and telemetry data effectively.
#########################################################################################

@app.get("/downlink/predictive_ML/redis/keys", summary="List all Redis keys for predictive maintenance")
async def list_redis_keys(current_user=Depends(auth.get_current_user)):
    try:
        keys = await redis_client.keys("threshold_map:*") + await redis_client.keys("Window_length:*") + await redis_client.keys("model:*")
        return {
            "status": "success",
            "keys": keys
        }
    except Exception as e:
        logging.error(f"Failed to list Redis keys: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to list Redis keys"
        )
        
@app.get("/downlink/predictive_ML/redis/key", summary="Get value of a specific Redis key")
async def get_redis_key_value(key_name: str, current_user=Depends(auth.get_current_user)):
    try:
        value = await redis_client.get(key_name)
        if value is None:
            raise HTTPException(
                status_code=404,
                detail="Key not found in Redis"
            )
        return {
            "status": "success",
            "key": key_name,
            "value": value
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to get Redis key value: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to get Redis key value"
        )
        
@app.delete("/downlink/predictive_ML/redis/key", summary="Delete a specific Redis key")
async def delete_redis_key(key_name: str, current_user=Depends(auth.get_current_user)):
    try:
        result = await redis_client.delete(key_name)
        if result == 0:
            raise HTTPException(
                status_code=404,
                detail="Key not found in Redis"
            )
        return {
            "status": "success",
            "message": f"Key '{key_name}' deleted from Redis"
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to delete Redis key: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to delete Redis key"
        )
        
###################################################################################
# sensor mapping between frontend and backend can be handled in the telemetry processing step. The API can accept a mapping of sensor names from the frontend to the actual sensor names used in the telemetry data. This mapping can then be applied during the aggregation and labeling process to ensure that the correct sensors are being processed and labeled according to the provided thresholds. This allows for flexibility in the frontend while maintaining consistency in the backend processing.
###################################################################################
class SensorMappingRequest(BaseModel):
    model_name: str
    sensor_mapping: dict[str, str]  # backend sensor name -> frontend sensor name

@app.post(
    "/downlink/predictive_ML/model/sensor-mapping",
    summary="Register frontend sensors to model features"
)
async def set_sensor_mapping(
    payload: SensorMappingRequest,
    current_user=Depends(auth.get_current_user)
):
    try:

        key = f"sensor_map:{payload.model_name}"

        await redis_client.set(
            key,
            json.dumps(payload.sensor_mapping)
        )

        return {
            "status": "success",
            "model_name": payload.model_name,
            "sensor_mapping": payload.sensor_mapping
        }

    except Exception as e:
        logging.error(f"Failed to store sensor mapping: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to store sensor mapping"
        )
        
@app.post(
    "/downlink/predictive_ML/model/sensor-mapping/getSensorDetails",
    summary="Get sensor mapping for a model"
)
async def get_sensor_mapping(
    payload: SensorMappingRequest,
    current_user=Depends(auth.get_current_user)
):
    try:
        key = f"sensor_map:{payload.model_name}"
        mapping_json = await redis_client.get(key)

        if not mapping_json:
            raise HTTPException(
                status_code=404,
                detail="Sensor mapping not found for the model"
            )

        sensor_mapping = json.loads(mapping_json)

        return {
            "status": "success",
            "model_name": payload.model_name,
            "sensor_mapping": sensor_mapping
        }

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to retrieve sensor mapping: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve sensor mapping"
        )
        
@app.delete(
    "/downlink/predictive_ML/model/sensor-mapping",
    summary="Delete sensor mapping for a model"
)
async def delete_sensor_mapping(
    payload: SensorMappingRequest,
    current_user=Depends(auth.get_current_user)
):
    try:
        key = f"sensor_map:{payload.model_name}"
        result = await redis_client.delete(key)

        if result == 0:
            raise HTTPException(
                status_code=404,
                detail="Sensor mapping not found for the model"
            )

        return {
            "status": "success",
            "message": f"Sensor mapping for model '{payload.model_name}' deleted"
        }

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to delete sensor mapping: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to delete sensor mapping"
        )
        
###########################################################################
# get the key and modelname sensor mapping from json file- sensor_mapping.json. This file will contain a mapping of the sensor names used in the telemetry data to the sensor names used in the ML model. The API can read this file and return the mapping to the frontend, which can then use it to display the correct sensor names to the user and ensure that the correct sensors are being processed for predictions.
###########################################################################

@app.get(
    "/downlink/predictive_ML/model/sensor-mapping/default",
    summary="Get backend sensor mapping from JSON file"
)
async def get_default_sensor_mapping(
    current_user=Depends(auth.get_current_user)
):
    try:
        with open("Predictive_ML/sensor_mapping.json", "r") as f:
            data = json.load(f)

        return {
            "status": "success",
            "whole_json": data,
            "model_name": data.get("model_name"),
            "sensor_mapping": data.get("sensor_mapping")
        }

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Sensor mapping file not found"
        )
    except Exception as e:
        logging.error(f"Failed to read sensor mapping file: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to read sensor mapping file"
        )

###################################################################
# Apis for asset specific models
###################################################################
class Assettelemertyfetchandtrainrequest(BaseModel):
    asset_id: str
    model_name: str
    model_type: Literal["random_forest", "xgboost", "lstm"]
    target_column: str # "label" or the name of the target column in the dataset
    horizon: Literal["1h", "6h", "24h"]
    window_length: int = Field(
        ...,
        gt=0,
        description="Window length in seconds for aggregation"
    )

@app.post("/downlink/predictive_ML/Asset_specific/assets/fetch-train", summary="Fetch telemetry, process and train a model")
async def fetch_train_asset_model(
    payload: Assettelemertyfetchandtrainrequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(auth.get_current_user)
):
    job_id = str(uuid.uuid4())
    key = f"train:{job_id}:{payload.model_name}:{payload.target_column}"
 
    await redis_client.set(key, json.dumps({
        "status": "queued",
        "model_name": payload.model_name,
        "target_column": payload.target_column
    }))
 
    async def _run():
        try:
            await redis_client.set(key, json.dumps({"status": "running"}))
 
            telemetry_fetcher = fetch_assets_telemetry.FetchAssetsTelemetry()
            telemetry_data = telemetry_fetcher.get_telemetry_data_asset(payload.asset_id)
            if telemetry_data is None:
                await redis_client.set(key, json.dumps({
                    "status": "failed",
                    "error": "Failed to fetch telemetry data"
                }))
                return
 
            processor = telemetry_processor.TelemetryProcessor(telemetry_data)
            processed_data = processor.aggregate_window(window_size_sec=payload.window_length)
            processed_data = telemetry_processor.handle_missing_windows(processed_data)
            await redis_client.set(f"Window_length:{payload.asset_id}", payload.window_length)
 
            sensor_map_json = await redis_client.get(f"sensor_map:{payload.model_name}")
            if not sensor_map_json:
                await redis_client.set(key, json.dumps({
                    "status": "failed",
                    "error": f"Sensor mapping not found for model: {payload.model_name}"
                }))
                return
 
            sensor_map = json.loads(sensor_map_json)
 
            threshold_map = {}
            if payload.model_name == "Slipring Induction motor 60kw":
                sensor_thresholds = {
                    "Vibration_avg":      {"prefailure": 5.0,  "failure": 7.0},
                    "Temperature_avg":    {"prefailure": 80.0, "failure": 90.0},
                    "Stator_Current_avg": {"prefailure": 10.0, "failure": 15.0},
                    "Rotor_Current_avg":  {"prefailure": 8.0,  "failure": 12.0},
                }
                threshold_map = {
                    sensor_map[k]: v
                    for k, v in sensor_thresholds.items()
                    if k in sensor_map
                }
 
            labeled_data = telemetry_processor.label_data(
                aggregated_data=processed_data,
                threshold_map=threshold_map
            )
 
            train_service = TrainService()
            result = await train_service.train_specific_model(
                labeled_data=labeled_data,
                target_column=payload.target_column,
                user_model_name=payload.model_name,
                algorithm=payload.model_type,
                horizon=payload.horizon,
                equipment_type=payload.model_name,
                thresholds=threshold_map,
                freq_minutes=payload.window_length / 60,
            )
 
            await redis_client.set(key, json.dumps({
                "status": "completed",
                "model_name": payload.model_name,
                "target_column": payload.target_column,
                "metrics": result["metrics"],
                "metadata": result["metadata"],
                "sensor_correlation": result["sensor_correlation"],
                "label_info": result["label_info"]
            }))
        except Exception as e:
            logging.error(f"Fetch-train job failed: {e}", exc_info=True)
            await redis_client.set(key, json.dumps({"status": "failed", "error": str(e)}))
 
    background_tasks.add_task(_run)
    return {
        "status": "accepted",
        "job_id": job_id,
        "job_key": key,
        "message": "Fetch-train started in background"
    }
    
    
class PredictSpecificRequest(BaseModel):
    model_name: str
    asset_id: str
    
@app.post("/downlink/predictive_ML/Asset_specific/predict", summary="Run prediction using an asset-specific model")
async def predict_specific_asset_model(
    payload: PredictSpecificRequest,
    background_tasks: BackgroundTasks,
    current_user=Depends(auth.get_current_user)
):
    job_id = str(uuid.uuid4())
    key = f"pred:{job_id}:{payload.model_name}:{payload.asset_id}"
 
    await redis_client.set(key, json.dumps({
        "status": "queued",
        "model_name": payload.model_name,
        "asset_id": payload.asset_id
    }))
 
    async def _run():
        try:
            await redis_client.set(key, json.dumps({"status": "running"}))
            result = await predict_specific(model_name=payload.model_name, asset_id=payload.asset_id)
            if result is None:
                await redis_client.set(key, json.dumps({
                    "status": "failed",
                    "error": "No telemetry data found"
                }))
                return
            await redis_client.set(key, json.dumps({
                "status": "completed",
                "model_name": payload.model_name,
                "asset_id": payload.asset_id,
                "result": result
            }))
        except Exception as e:
            logging.error(f"Asset-specific predict job failed: {e}", exc_info=True)
            await redis_client.set(key, json.dumps({"status": "failed", "error": str(e)}))
 
    background_tasks.add_task(_run)
    return {
        "status": "accepted",
        "job_id": job_id,
        "job_key": key,
        "message": "Asset-specific prediction started in background"
    }
   
######################################################################
# List stored job IDs
######################################################################

@app.get("/downlink/predictive_ML/jobs/train", summary="List all stored train job IDs")
async def list_train_jobs(current_user=Depends(auth.get_current_user)):
    try:
        keys = await redis_client.keys("train:*")
        jobs = []
        for key in keys:
            data_json = await redis_client.get(key)
            if data_json:
                data = json.loads(data_json)
                # key format: train:{job_id}:{model_name}:{target_column}
                _, job_id, model_name, target_column = key.split(":", 3)
                jobs.append({
                    "job_id": job_id,
                    "job_key": key,
                    "model_name": model_name,
                    "target_column": target_column,
                    "status": data.get("status"),
                })
        return {"status": "success", "count": len(jobs), "jobs": jobs}
    except Exception as e:
        logging.error(f"Failed to list train jobs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list train jobs")


@app.get("/downlink/predictive_ML/jobs/pred", summary="List all stored prediction job IDs")
async def list_pred_jobs(current_user=Depends(auth.get_current_user)):
    try:
        keys = await redis_client.keys("pred:*")
        jobs = []
        for key in keys:
            data_json = await redis_client.get(key)
            if data_json:
                data = json.loads(data_json)
                # key format: pred:{job_id}:{model_name}:{asset_id}
                _, job_id, model_name, asset_id = key.split(":", 3)
                jobs.append({
                    "job_id": job_id,
                    "job_key": key,
                    "model_name": model_name,
                    "asset_id": asset_id,
                    "status": data.get("status"),
                })
        return {"status": "success", "count": len(jobs), "jobs": jobs}
    except Exception as e:
        logging.error(f"Failed to list pred jobs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list pred jobs")

    
###############################################################################
# store the preditions for future use in visullisation
###############################################################################

@app.get(
    "/downlink/predictive_ML/stored-predictions/list",
    summary="Get stored predictions for an asset and model"
)
async def list_stored_predictions(
    current_user=Depends(auth.get_current_user)
):
    try:
        keys = await redis_client.keys("prediction:*")
        predictions = []
        for key in keys:
            data_json = await redis_client.get(key)
            if data_json:
                predictions.append(json.loads(data_json))
        return {
            "status": "success",
            "count": len(predictions),
            "predictions": predictions
        }
    except Exception as e:
        logging.error(f"Failed to list stored predictions: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to list stored predictions"
        )
        
@app.get(
    "/downlink/predictive_ML/stored-predictions/specific-model",
    summary="Get stored predictions for a specific asset and model"
)
async def get_stored_predictions_specific(
    asset_id: str,
    model_name: str,
    horizon: str,
    current_user=Depends(auth.get_current_user)
):
    try:
        key = f"prediction:{asset_id}:{model_name}:{horizon}"
        data_json = await redis_client.get(key)
        if not data_json:
            raise HTTPException(
                status_code=404,
                detail="No stored predictions found for the specified asset and model"
            )
        prediction_data = json.loads(data_json)
        return {
            "status": "success",
            "prediction": prediction_data
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to get stored predictions: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to get stored predictions"
        )
        
@app.delete(
    "/downlink/predictive_ML/stored-predictions/specific-model",
    summary="Delete stored predictions for a specific asset and model"
)
async def delete_stored_predictions_specific(
    asset_id: str,
    model_name: str,    
    horizon: str,
    current_user=Depends(auth.get_current_user)
):
    try:
        key = f"prediction:{asset_id}:{model_name}:{horizon}"
        result = await redis_client.delete(key)
        if result == 0:
            raise HTTPException(
                status_code=404,
                detail="No stored predictions found to delete for the specified asset and model"
            )
        return {
            "status": "success",
            "message": f"Stored predictions for asset '{asset_id}' and model '{model_name}' deleted"
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to delete stored predictions: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to delete stored predictions"
        )

############################################################################################
# Notifications NEW --> REMARK --> CLOSE
############################################################################################

@app.get(
    "/downlink/notifications",
    summary="Fetch notifications with filtering, pagination and sorting"
)

async def get_notifications_api(
    status: str = Query(None),
    search: str = Query(None),
    severity: str = Query(None),
    asset: str = Query(None),
    device: str = Query(None),
    start_time: int = Query(None),   # epoch millis
    end_time: int = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    sort_by: str = Query("edgex_created"),
    order: str = Query("desc"),
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user)
):
    try:
        total, data = get_notifications(
            db=db,
            status=status,
            search=search,
            severity=severity,
            asset=asset,
            device=device,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            order=order
        )

        return {
            "status": "success",
            "total": total,     
            "count": len(data),
            "data": data
        }

    except Exception as e:
        logging.error(f"Failed to fetch notifications: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch notifications")
    
@app.get(
    "/downlink/notifications/stats",
    summary="Get notification stats"
)
async def get_notification_stats(
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user)
):
    try:
        new_count = db.query(Notification).filter(Notification.status == "NEW").count()
        closed_count = db.query(Notification).filter(Notification.status == "CLOSED").count()

        return {
            "status": "success",
            "data": {
                "NEW": new_count,
                "CLOSED": closed_count
            }
        }

    except Exception as e:
        logging.error(f"Failed to fetch stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch stats")  
    
@app.get(
    "/downlink/notifications/{notification_id}",
    summary="Get a specific notification"
)
async def get_notification_by_id(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user)
):
    try:
        notif = db.query(Notification).filter(Notification.id == notification_id).first()

        if not notif:
            raise HTTPException(status_code=404, detail="Notification not found")

        return {
            "status": "success",
            "data": notif
        }

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to fetch notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch notification")
    
@app.post(
    "/downlink/notifications/method-close/{notification_id}",
    summary="Close notification with remark"
)
async def close_notification_def(
    notification_id: str,
    request: CloseNotificationRequest,
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user)
):
    try:
        notif = close_notification(
            db,
            notification_id,
            request.remark,
            request.user # or user id
        )

        if not notif:
            raise HTTPException(status_code=404, detail="Notification not found")

        return {
            "status": "success",
            "message": "Notification closed successfully"
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except HTTPException:
        raise

    except Exception as e:
        logging.error(f"Failed to close notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to close notification")
    

@app.get("/downlink/notifications/{status}")

async def get_notifications_by_status_api(
    status: str,
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user)
):
    try:
        data = (
            db.query(Notification)
            .filter(Notification.status == status.upper())
            .order_by(Notification.edgex_created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        return {
            "status": "success",
            "count": len(data),
            "data": jsonable_encoder(data)
        }

    except Exception as e:
        logging.error(f"Failed to fetch notifications: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch notifications")
    
    
@app.get("/downlink/notifications/actions/closed_remarks")
async def get_closed_notifications_with_remarks(
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: Session = Depends(get_db),
    current_user=Depends(auth.get_current_user)
):
    try:
        subquery = (
            db.query(
                NotificationAction.notification_id,
                NotificationAction.remark,
                NotificationAction.performed_by,
                NotificationAction.performed_at
            )
            .order_by(
                NotificationAction.notification_id,
                NotificationAction.performed_at.desc()
            )
            .distinct(NotificationAction.notification_id)
            .subquery()
        )

        results = (
            db.query(
                Notification,
                subquery.c.remark,
                subquery.c.performed_by,
                subquery.c.performed_at
            )
            .join(subquery, Notification.id == subquery.c.notification_id)
            .filter(Notification.status == "CLOSED")
            .order_by(Notification.edgex_created.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        data = [
            {
                "notification": jsonable_encoder(notif),
                "remark": remark,
                "performed_by": performed_by,
                "performed_at": performed_at
            }
            for notif, remark, performed_by, performed_at in results
        ]

        return {
            "status": "success",
            "count": len(data),
            "data": data
        }

    except Exception as e:
        logging.error(f"Failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch")

@app.websocket("/downlink/ws/notifications/{status}")
async def websocket_notifications_by_status(websocket: WebSocket, status: str):
    await websocket.accept()

    try:
        while True:
            with database.SessionLocal() as db:
                data = (
                    db.query(Notification)
                    .filter(Notification.status == status.upper())
                    .order_by(Notification.edgex_created.desc())
                    .limit(10)
                    .all()
                )

            await websocket.send_json({
                "status": "success",
                "count": len(data),
                "data": jsonable_encoder(data)
            })

            await asyncio.sleep(10)

    except WebSocketDisconnect:
        pass
    
###############################################################################################################################
# Consolidating the auth for honeycomb
################################################################################################################################
LOGIN_MAX_ATTEMPTS = 3
LOGIN_LOCKOUT_TTL = 900  # 15 minutes in seconds


async def _record_login_failure(username: str) -> dict:
    fail_key = f"login_fails:{username}"
    lock_key = f"login_lock:{username}"
    fails = int(await redis_client.incr(fail_key))
    if fails == 1:
        await redis_client.expire(fail_key, LOGIN_LOCKOUT_TTL)
    if fails >= LOGIN_MAX_ATTEMPTS:
        await redis_client.setex(lock_key, LOGIN_LOCKOUT_TTL, "locked")
        await redis_client.delete(fail_key)
        return {
            "locked": True,
            "failed_attempts": LOGIN_MAX_ATTEMPTS,
            "lockout_seconds": LOGIN_LOCKOUT_TTL,
        }
    return {
        "locked": False,
        "failed_attempts": fails,
        "attempts_remaining": LOGIN_MAX_ATTEMPTS - fails,
    }
    
class HoneycombAuthRequest(BaseModel):
    captcha_id: str
    encrypted_input: dict  # { "iv": ..., "ciphertext": ..., "tag": ... }
    identity: dict
    secret: dict
    
_RATE_LIMIT_IP_MAX = 10        # max attempts per IP per window
_RATE_LIMIT_WINDOW = 60        # seconds

async def _check_rate_limit(redis, key: str, max_attempts: int):
    """Increment counter and set TTL on first hit. Returns (count, ttl)."""
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, _RATE_LIMIT_WINDOW)
    ttl = await redis.ttl(key)
    return count, ttl


@app.post("/downlink/auth/honeycomb", summary="Authenticate with Honeycomb using encrypted credentials and MFA")
async def honeycomb_auth(body: HoneycombAuthRequest, http_request: Request, db: Session = Depends(get_db)):

    # Resolve real client IP (works behind nginx/reverse proxy)
    forwarded_for = http_request.headers.get("X-Forwarded-For")
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else http_request.client.host

    # Per-IP rate limit
    ip_count, ip_ttl = await _check_rate_limit(redis_client, f"rate:auth:ip:{client_ip}", _RATE_LIMIT_IP_MAX)
    if ip_count > _RATE_LIMIT_IP_MAX:
        raise HTTPException(status_code=429, detail=f"Too many requests from your IP. Try again in {ip_ttl} seconds.")

    request = body

    # 1. Verify captcha
    stored_captcha = await redis_client.get(request.captcha_id)
    try:
        decrypted_input = decrypt_aes_gcm(request.encrypted_input)
    except Exception:
        await redis_client.delete(request.captcha_id)
        return JSONResponse(status_code=400, content={"status": "error", "message": "Invalid captcha input."})

    if not stored_captcha or stored_captcha != decrypted_input:
        await redis_client.delete(request.captcha_id)
        return JSONResponse(status_code=400, content={"status": "error", "message": "Captcha mismatch or null input."})

    await redis_client.delete(request.captcha_id)

    # 2. Decrypt credentials
    username = decrypt_aes_gcm_downlink_login(request.identity)
    password = decrypt_aes_gcm_downlink_login(request.secret)
    if not username or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid encrypted credentials")

    # 3. Check lockout
    lock_key = f"login_lock:{username}"
    if await redis_client.get(lock_key):
        ttl = max(int(await redis_client.ttl(lock_key)), 0)
        return JSONResponse(status_code=429, content={
            "status": "error",
            "message": "Account temporarily locked due to too many failed login attempts.",
            "lockout_seconds_remaining": ttl
        })

    # 4. Authenticate
    user = auth.authenticate_user(db, username, password)
    if not user:
        info = await _record_login_failure(username)
        if info["locked"]:
            return JSONResponse(status_code=429, content={
                "status": "error",
                "message": f"Account locked for {LOGIN_LOCKOUT_TTL // 60} minutes due to too many failed login attempts.",
                "failed_attempts": info["failed_attempts"],
                "lockout_seconds": info["lockout_seconds"]
            })
        return JSONResponse(status_code=401, content={
            "status": "error",
            "message": "Invalid credentials. Request a new captcha.",
            "failed_attempts": info["failed_attempts"],
            "attempts_remaining": info["attempts_remaining"]
        })

    # 5. MFA check see if the user has MFA enabled
    if user.mfa_secret:
        user.mfa_secret = str(user.mfa_secret)  # ensure it's a string for the MFA check
        mfa_enabled = True
    else:
        user.mfa_secret = None
        mfa_enabled = False
        

    # Success — read and clear any prior failure counters
    prior_fails_raw = await redis_client.get(f"login_fails:{username}")
    prior_fails = int(prior_fails_raw) if prior_fails_raw else 0
    await redis_client.delete(f"login_fails:{username}")
    await redis_client.delete(lock_key)

    # 6. Create access token
    Bridge_access_token = auth.create_access_token(data={"sub": str(user.id)})
    
    # 6. Magistrala token generation
    magistrala_identity = encrypt_aes_gcm_downlink_login(username)  # Re-encrypt for magistrala
    magistrala_secret = encrypt_aes_gcm_downlink_login(password)  
    
    magistrala_token_response = requests.post(
        f"{config.BASE_URL}/users/tokens/issue",
        json ={
        "identity": magistrala_identity,
        "secret": magistrala_secret
    })
    if magistrala_token_response.status_code != 200:
        logging.error(f"Failed to get Magistrala token: {magistrala_token_response.text}")
        raise HTTPException(status_code=500, detail="Failed to authenticate with Magistrala")
    
    magistrala_access_token = magistrala_token_response.json().get("data", {}).get("access_token")
    magistrala_refresh_token = magistrala_token_response.json().get("data", {}).get("refresh_token")
    
    # 7. edgex token generation (get token )
    edgex_user = username.split("@")[0]  
    logging.info(f"Looking for Edgex token for user: {edgex_user} in token store")
    if not os.path.exists(JSON_FILE):
        raise HTTPException(status_code=500, detail="Token store not found.")
    
    try:
        with open(JSON_FILE, "r") as f:
            data = json.load(f)

        for entry in data:
            if entry.get("username") == edgex_user:
                edgex_token = entry.get("token")
                logging.info(f"Found Edgex token for user: {edgex_user}")
                break
        else:
            raise HTTPException(status_code=404, detail="Edgex token not found for user.")
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error reading token store: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error accessing token store.")
    
    # 8. get the JWT for edgex using the token and username
    
    JWT_responce_edgex = requests.get(
        f"{config.EDGEX_VAULT_BASE_URL}/v1/identity/oidc/token/{edgex_user}",
        headers={"Authorization": f"Bearer {edgex_token}"}
    )
    if JWT_responce_edgex.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to get Edgex JWT")
    
    edgex_jwt = JWT_responce_edgex.json().get("data", {}).get("token")
    logging.info(f"Obtained Edgex JWT for user: {edgex_user}")
    
    # 9. login for chirpstack and get the token
    
    chirpstack_login_response = requests.get(
        f"{config.CHIRPSTACK_HTTP_BASE_URL}/api/tenants?limit=1&offset=0",
        headers={"Authorization": f"Bearer {config.API_TOKEN}"}
    )
    if chirpstack_login_response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to fetch ChirpStack tenants")

    tenants_data = chirpstack_login_response.json()

    first_tenant_id = tenants_data["result"][0]["id"]
        
    logging.info(f"First ChirpStack tenant ID: {first_tenant_id}")
    
    # 10. login for superset and get the token
    
    superset_username = magistrala_identity
    superset_password = magistrala_secret
    
    # combine {iv,chiphertext and tag into one string with : as separator to send to superset}
    
    superset_identity = f"{magistrala_identity['iv']}:{magistrala_identity['ciphertext']}:{magistrala_identity['tag']}"
    superset_secret = f"{magistrala_secret['iv']}:{magistrala_secret['ciphertext']}:{magistrala_secret['tag']}"
    
    superset_login_response = requests.post(
        f"{config.SUPERSET_BASE_URL}/api/v1/security/login",
        json={
            "username": superset_identity,
            "password": superset_secret,
            "provider": "db",
            "refresh": True
        })
    if superset_login_response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to authenticate with Superset")
    
    superset_access_token = superset_login_response.json().get("access_token")
    superset_refresh_token = superset_login_response.json().get("refresh_token")
    
    # session management and concurrnt session check
    
    sesson_management_response = requests.post(
        f"{config.BASE_URL}/users/login",
        json={
            "identity": magistrala_identity,
            "password": magistrala_secret
        }
    )
    if sesson_management_response.status_code != 200:
        logging.error(f"Failed session management check: {sesson_management_response.text}")
        raise HTTPException(status_code=500, detail="Failed to manage user session")
    
    session_token = sesson_management_response.json().get("token")

    all_tokens = {
        "bridge_access_token": Bridge_access_token,
        "magistrala_access_token": magistrala_access_token,
        "magistrala_refresh_token": magistrala_refresh_token,
        "edgex_token": edgex_token,
        "edgex_jwt": edgex_jwt,
        "superset_access_token": superset_access_token,
        "superset_refresh_token": superset_refresh_token,
        "session_token": session_token,
        "chirpstack_token": config.API_TOKEN,
        "chirpstack_tenant_id": first_tenant_id,
        "failed_attempts_before_login": prior_fails,
        "user_id": user.id,
    }

    if mfa_enabled:
        mfa_pending_token = str(uuid.uuid4())
        await redis_client.setex(f"mfa_pending:{mfa_pending_token}", 120, json.dumps(all_tokens))
        return {
            "status": "mfa_required",
            "mfa_enabled": True,
            "mfa_pending_token": mfa_pending_token,
        }

    return {
        "status": "success",
        "mfa_enabled": False,
        **{k: v for k, v in all_tokens.items() if k != "user_id"},
    }
    
class MFAVerifyRequest(BaseModel):
    mfa_code: str
    mfa_pending_token: str

@app.post(
    "/downlink/auth/honeycomb/mfa-verify",
    summary="Verify MFA code for Honeycomb authentication"
)
async def honeycomb_mfa_verify(
    request: MFAVerifyRequest,
    db: Session = Depends(get_db)
):
    pending_raw = await redis_client.get(f"mfa_pending:{request.mfa_pending_token}")
    if not pending_raw:
        raise HTTPException(status_code=401, detail="MFA session expired or invalid")

    pending = json.loads(pending_raw)

    user = db.query(models.User).filter(models.User.id == pending["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not enabled for this user")

    totp = pyotp.TOTP(str(user.mfa_secret))
    if not totp.verify(request.mfa_code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    await redis_client.delete(f"mfa_pending:{request.mfa_pending_token}")

    return {
        "status": "success",
        "mfa_enabled": True,
        **{k: v for k, v in pending.items() if k != "user_id"},
    }
    
# check GPU specifications and availability for LSTM training
@app.get("/downlink/predictive_ML/lstm/gpu-info", summary="Get GPU information for LSTM training")
async def get_gpu_info(current_user=Depends(auth.get_current_user)):
    try:
        if torch.cuda.is_available():
            gpu_count = torch.cuda.device_count()
            gpu_info = []
            for i in range(gpu_count):
                gpu_info.append({
                    "name": torch.cuda.get_device_name(i),
                    "total_memory": torch.cuda.get_device_properties(i).total_memory,
                    "available_memory": torch.cuda.memory_allocated(i),
                    "free_memory": torch.cuda.memory_reserved(i) - torch.cuda.memory_allocated(i)
                })
            return {
                "status": "success",
                "gpu_available": True,
                "gpu_count": gpu_count,
                "gpu_info": gpu_info
            }
        else:
            return {
                "status": "success",
                "gpu_available": False,
                "message": "No GPU available, training will use CPU which may be slower."
            }
    except Exception as e:
        logging.error(f"Failed to get GPU info: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get GPU information")
    
########################################################################## BACKUP INTEGRATION ##########################################################################
def _append_history(file_path: str, entry: dict) -> None:
    try:
        with _history_lock:
            history = []
            if os.path.exists(file_path):
                with open(file_path) as f:
                    history = json.load(f)
            history.append(entry)
            if len(history) > _HISTORY_MAX:
                history = history[-_HISTORY_MAX:]
            with open(file_path, "w") as f:
                json.dump(history, f, indent=2)
    except Exception as e:
        logging.warning(f"Failed to append history to {file_path}: {e}")

def _save_nas_config(host: str, port: int, username: str, remote_path: str) -> None:
    """Save or update a NAS server entry in nas_config.json (no password stored)."""
    try:
        configs = _load_nas_configs()
        key = f"{host}:{port}:{remote_path}"
        entry = {
            "host": host,
            "port": port,
            "username": username,
            "remote_path": remote_path,
            "last_used": datetime.now(timezone.utc).isoformat(),
        }
        configs = {k: v for k, v in configs.items() if k != key}
        configs[key] = entry
        with open(NAS_CONFIG_FILE, "w") as f:
            json.dump(list(configs.values()), f, indent=2)
    except Exception as e:
        logging.warning(f"Failed to save NAS config: {e}")


def _load_nas_configs() -> dict:
    """Return saved NAS configs keyed by host:port."""
    if not os.path.exists(NAS_CONFIG_FILE):
        return {}
    try:
        with open(NAS_CONFIG_FILE) as f:
            entries = json.load(f)
        return {f"{e['host']}:{e['port']}:{e['remote_path']}": e for e in entries}
    except Exception:
        return {}
    
    
# ── Helpers ─────────────────────────────────────────────

@contextmanager
def managed_conn(conn_fn):
    """Context manager that guarantees cursor + connection cleanup."""
    conn = conn_fn()
    cur = conn.cursor()
    try:
        yield conn, cur
    finally:
        cur.close()
        conn.close()


def _run_script(command: list[str]) -> str:
    """Run a Python script and return combined stdout+stderr. Raises on failure."""
    script = command[1] if len(command) > 1 else command[0]
    if not os.path.exists(script):
        raise RuntimeError(f"Script not found: {script}")
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError(output)
    return output


# ── Pydantic models ─────────────────────────────────────

class RemoteConfig(BaseModel):
    host: str = Field(..., description="Remote server hostname or IP address")
    port: int = Field(22, ge=1, le=65535, description="SSH port")
    username: str = Field(..., description="SSH username")
    password: str = Field(..., description="SSH password")
    remote_path: str = Field(..., description="Absolute path on remote server for backup files")


class DateRangeRequest(BaseModel):
    start: str = Field(..., description="Start datetime (ISO format, UTC) e.g. 2026-06-06T00:00:00")
    end: str = Field(..., description="End datetime (ISO format, UTC) e.g. 2026-06-07T23:59:59")


class ScheduleRequest(BaseModel):
    time: str = Field(..., description="Daily backup time in HH:MM format (24-hour)")
    timezone: str = Field("UTC", description="IANA timezone name e.g. UTC, Asia/Kolkata, America/New_York")


class BackupScheduleRequest(BaseModel):
    time: str = Field(..., description="Daily backup time in HH:MM format (24-hour)")
    timezone: str = Field("UTC", description="IANA timezone name e.g. UTC, Asia/Kolkata, America/New_York")
    mode: Literal["incremental", "full", "limit", "hours", "range"] = Field(
        "incremental",
        description="incremental=watermark-based (default), full=reset+sync all, limit=last N records, hours=last N hours, range=date range",
    )
    limit: Optional[int] = Field(None, gt=0, description="Required for mode=limit")
    hours: Optional[int] = Field(None, gt=0, description="Required for mode=hours")
    start: Optional[str] = Field(None, description="Required for mode=range. ISO datetime e.g. 2026-06-01T00:00:00")
    end: Optional[str] = Field(None, description="Required for mode=range. ISO datetime e.g. 2026-06-07T23:59:59")


def _validate_backup_request(req: BackupScheduleRequest):
    parts = req.time.split(":")
    try:
        if len(parts) != 2:
            raise ValueError
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time '{req.time}': use HH:MM (24-hour, e.g. 02:00)",
        )
    try:
        import zoneinfo
        zoneinfo.ZoneInfo(req.timezone)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown timezone '{req.timezone}'.",
        )
    if req.mode == "limit" and req.limit is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit is required for mode=limit")
    if req.mode == "hours" and req.hours is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="hours is required for mode=hours")
    if req.mode == "range":
        if not req.start or not req.end:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="start and end are required for mode=range")
        try:
            def _to_utc(s):
                dt = datetime.fromisoformat(s)
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            start_dt = _to_utc(req.start)
            end_dt = _to_utc(req.end)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid datetime: {e}")
        if start_dt >= end_dt:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="start must be before end")
        return start_dt, end_dt
    return None, None


class NasScheduleRequest(BaseModel):
    time: str = Field(..., description="Daily NAS backup time in HH:MM format (24-hour)")
    timezone: str = Field("UTC", description="IANA timezone name e.g. UTC, Asia/Kolkata, America/New_York")
    host: str = Field(..., description="NAS / SSH server hostname or IP")
    port: int = Field(22, description="SSH port")
    username: str = Field(..., description="SSH username")
    password: str = Field(..., description="SSH password — stored on server for scheduled runs")
    remote_path: str = Field(..., description="Base folder on NAS for exports")
    mode: Literal["full", "limit", "hours", "range"] = Field(
        "full", description="full=all records (default), limit=last N records, hours=last N hours, range=date range"
    )
    limit: Optional[int] = Field(None, gt=0, description="Required for mode=limit")
    hours: Optional[int] = Field(None, gt=0, description="Required for mode=hours")
    start: Optional[str] = Field(None, description="Required for mode=range. ISO datetime e.g. 2026-06-01T00:00:00")
    end: Optional[str] = Field(None, description="Required for mode=range. ISO datetime e.g. 2026-06-07T23:59:59")


def _validate_nas_request(req: NasScheduleRequest):
    parts = req.time.split(":")
    try:
        if len(parts) != 2:
            raise ValueError
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time '{req.time}': use HH:MM (24-hour, e.g. 02:00)",
        )
    try:
        import zoneinfo
        zoneinfo.ZoneInfo(req.timezone)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown timezone '{req.timezone}'.",
        )
    if req.mode == "limit" and req.limit is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit is required for mode=limit")
    if req.mode == "hours" and req.hours is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="hours is required for mode=hours")
    if req.mode == "range":
        if not req.start or not req.end:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="start and end are required for mode=range")
        try:
            def _to_utc(s):
                dt = datetime.fromisoformat(s)
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            start_dt = _to_utc(req.start)
            end_dt = _to_utc(req.end)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid datetime: {e}")
        if start_dt >= end_dt:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="start must be before end")
        return start_dt, end_dt
    return None, None


class ImportScheduleRequest(BaseModel):
    time: str = Field(..., description="Daily import time in HH:MM format (24-hour)")
    timezone: str = Field("UTC", description="IANA timezone name e.g. UTC, Asia/Kolkata, America/New_York")
    host: str = Field(..., description="NAS / SSH server hostname or IP")
    port: int = Field(22, description="SSH port")
    username: str = Field(..., description="SSH username")
    password: str = Field(..., description="SSH password — stored encrypted for scheduled runs")
    remote_path: str = Field(..., description="Base NAS folder containing export_* subfolders")
    mode: Literal["full", "limit", "hours", "range"] = Field(
        "full", description="full=all rows (default), limit=first N rows, hours=last N hours, range=date range"
    )
    limit: Optional[int] = Field(None, gt=0, description="Required for mode=limit")
    hours: Optional[int] = Field(None, gt=0, description="Required for mode=hours")
    start: Optional[str] = Field(None, description="Required for mode=range. ISO datetime e.g. 2026-06-01T00:00:00")
    end: Optional[str] = Field(None, description="Required for mode=range. ISO datetime e.g. 2026-06-07T23:59:59")
    folder: Optional[str] = Field(None, description="Specific export_* folder name to import from. Omit to auto-pick the latest.")


def _validate_import_request(req: ImportScheduleRequest):
    parts = req.time.split(":")
    try:
        if len(parts) != 2:
            raise ValueError
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time '{req.time}': use HH:MM (24-hour, e.g. 02:00)",
        )
    try:
        import zoneinfo
        zoneinfo.ZoneInfo(req.timezone)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown timezone '{req.timezone}'.",
        )
    if req.mode == "limit" and req.limit is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit is required for mode=limit")
    if req.mode == "hours" and req.hours is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="hours is required for mode=hours")
    if req.mode == "range":
        if not req.start or not req.end:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="start and end are required for mode=range")
        try:
            def _to_utc(s):
                dt = datetime.fromisoformat(s)
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            start_dt = _to_utc(req.start)
            end_dt = _to_utc(req.end)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid datetime: {e}")
        if start_dt >= end_dt:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="start must be before end")
        return start_dt, end_dt
    return None, None


# ── Health ──────────────────────────────────────────────

@app.get("/downlink/guardian/health")
def health_check(current_user=Depends(auth.get_current_user)):
    """Check if the source (Magistrala) DB is reachable."""
    try:
        conn = get_source_conn()
        conn.close()
        return {"status": "UP", "message": "Magistrala DB is reachable"}
    except psycopg2.OperationalError as oe:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(oe))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal Server Error: {e}")


@app.get("/downlink/guardian/backup-db/health")
def backup_db_health(current_user=Depends(auth.get_current_user)):
    """Check if the Backup DB (TimescaleDB) is reachable."""
    try:
        with managed_conn(get_target_conn) as (_conn, cur):
            cur.execute("SELECT 1")
        return {"status": "UP", "message": "Backup DB (TimescaleDB) is reachable"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))


# ── Internal Backup (source → target) ──────────────────

@app.post("/downlink/guardian/backup")
def backup(current_user=Depends(auth.get_current_user)):
    """Backup the latest 50,000 records from source to TimescaleDB (hard cap)."""
    MAX_LIMIT = 50000
    start = datetime.now(timezone.utc)
    try:
        # Check backup_control.enabled
        with managed_conn(get_target_conn) as (_conn, cur):
            cur.execute("SELECT enabled FROM backup_control WHERE id = TRUE")
            row = cur.fetchone()
            if not row or row[0] is not True:
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Backup is disabled. Enable it first via POST /downlink/guardian/backup/enable",
                )

        src_conn = get_source_conn()
        tgt_conn = get_target_conn()
        src_cur = src_conn.cursor()
        tgt_cur = tgt_conn.cursor()

        insert_sql = """
            INSERT INTO messages (
                time, channel, subtopic, publisher, protocol,
                name, unit, value, string_value, bool_value,
                data_value, sum, update_time
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (time, publisher, subtopic, name) DO UPDATE SET
                channel      = EXCLUDED.channel,
                protocol     = EXCLUDED.protocol,
                unit         = EXCLUDED.unit,
                value        = EXCLUDED.value,
                string_value = EXCLUDED.string_value,
                bool_value   = EXCLUDED.bool_value,
                data_value   = EXCLUDED.data_value,
                sum          = EXCLUDED.sum,
                update_time  = EXCLUDED.update_time
        """

        try:
            src_cur.execute("""
                SELECT * FROM (
                    SELECT
                        time, channel, subtopic, publisher, protocol,
                        name, unit, value, string_value, bool_value,
                        data_value, sum,
                        COALESCE(NULLIF(update_time, 0), time) AS update_time_epoch
                    FROM messages
                    ORDER BY COALESCE(NULLIF(update_time, 0), time) DESC
                    LIMIT %s
                ) t ORDER BY update_time_epoch
            """, (MAX_LIMIT,))

            rows = src_cur.fetchall()
            total_fetched = len(rows)

            processed = []
            for r in rows:
                row = list(r)
                epoch_val = row[-1]
                ts_val = (
                    datetime.fromtimestamp(epoch_val, timezone.utc)
                    if epoch_val is not None
                    else datetime.now(timezone.utc)
                )
                processed.append(tuple(list(row[:-1]) + [ts_val]))

            BATCH_SIZE = 10000
            total_upserted = 0
            for i in range(0, len(processed), BATCH_SIZE):
                batch = processed[i:i + BATCH_SIZE]
                execute_batch(tgt_cur, insert_sql, batch)
                tgt_conn.commit()
                total_upserted += len(batch)

        finally:
            src_cur.close()
            tgt_cur.close()
            src_conn.close()
            tgt_conn.close()

        duration = round((datetime.now(timezone.utc) - start).total_seconds(), 2)
        _append_history(BACKUP_HISTORY_FILE, {
            "start_time": start.isoformat(),
            "status": "SUCCESS",
            "mode": "limit",
            "duration_seconds": duration,
            "rows_fetched": total_fetched,
            "rows_upserted": total_upserted,
        })
        return {
            "status": "SUCCESS",
            "rows_fetched": total_fetched,
            "rows_upserted": total_upserted,
            "limit": MAX_LIMIT,
            "duration_seconds": duration,
        }

    except HTTPException:
        raise
    except Exception as e:
        logging.warning(f"Unexpected error occurred: {e}")
        _append_history(BACKUP_HISTORY_FILE, {
            "start_time": start.isoformat(),
            "status": "FAILED",
            "duration_seconds": round((datetime.now(timezone.utc) - start).total_seconds(), 2),
            "rows_fetched": None,
            "rows_upserted": None,
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal Server Error: {e}",
        )


# ── Restore Schedule (merged: full | limit | hours | range) ────────────────

class RestoreScheduleRequest(BaseModel):
    time: str = Field(..., description="Daily restore time in HH:MM format (24-hour)")
    timezone: str = Field("UTC", description="IANA timezone name e.g. UTC, Asia/Kolkata")
    mode: Literal["full", "limit", "hours", "range"] = Field(
        ..., description="full=all records, limit=last N records, hours=last N hours, range=date range"
    )
    limit: Optional[int] = Field(None, gt=0, description="Required for mode=limit")
    hours: Optional[int] = Field(None, gt=0, description="Required for mode=hours")
    start: Optional[str] = Field(None, description="Required for mode=range. ISO datetime e.g. 2026-06-01T00:00:00")
    end: Optional[str] = Field(None, description="Required for mode=range. ISO datetime e.g. 2026-06-07T23:59:59")


def _validate_restore_request(req: RestoreScheduleRequest):
    parts = req.time.split(":")
    try:
        if len(parts) != 2:
            raise ValueError
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid time '{req.time}': use HH:MM (24-hour, e.g. 02:00)",
        )
    try:
        import zoneinfo
        zoneinfo.ZoneInfo(req.timezone)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown timezone '{req.timezone}'.",
        )
    if req.mode == "limit" and req.limit is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="limit is required for mode=limit")
    if req.mode == "hours" and req.hours is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="hours is required for mode=hours")
    if req.mode == "range":
        if not req.start or not req.end:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="start and end are required for mode=range")
        try:
            def _to_utc(s):
                dt = datetime.fromisoformat(s)
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            start_dt = _to_utc(req.start)
            end_dt = _to_utc(req.end)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid datetime: {e}")
        if start_dt >= end_dt:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="start must be before end")
        return start_dt, end_dt
    return None, None


@app.post("/downlink/guardian/restore/schedule")
def set_restore_schedule(req: RestoreScheduleRequest, current_user=Depends(auth.get_current_user)):
    """Schedule a daily restore. Returns 409 if a schedule already exists — DELETE it first."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )

    existing = _scheduler.get_job("daily_restore")
    if existing:
        saved = {}
        if os.path.exists(RESTORE_SCHEDULE_FILE):
            try:
                with open(RESTORE_SCHEDULE_FILE) as f:
                    saved = json.load(f)
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "A restore schedule already exists. DELETE /downlink/guardian/restore/schedule first.",
                "current_schedule": {k: v for k, v in saved.items() if k != "user_id"},
                "next_run": existing.next_run_time.isoformat() if existing.next_run_time else None,
            },
        )

    start_dt, end_dt = _validate_restore_request(req)
    try:
        kwargs = {}
        saved = {"time": req.time, "timezone": req.timezone, "mode": req.mode, "user_id": current_user.id}

        if req.mode == "limit":
            kwargs["limit"] = req.limit
            saved["limit"] = req.limit
        elif req.mode == "hours":
            kwargs["hours"] = req.hours
            saved["hours"] = req.hours
        elif req.mode == "range":
            kwargs["start_dt"] = start_dt
            kwargs["end_dt"] = end_dt
            saved["start_dt"] = start_dt.isoformat()
            saved["end_dt"] = end_dt.isoformat()

        _apply_restore_schedule(req.time, req.timezone, req.mode, **kwargs)
        with open(RESTORE_SCHEDULE_FILE, "w") as f:
            json.dump(saved, f, indent=2)

        job = _scheduler.get_job("daily_restore")
        next_run = job.next_run_time.isoformat() if job and job.next_run_time else None

        return {
            "status": "Scheduled",
            "time": req.time,
            "timezone": req.timezone,
            "mode": req.mode,
            "next_run": next_run,
            "note": "Restore runs daily at the specified time. Persisted — survives API restarts.",
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/downlink/guardian/restore/schedule")
def get_restore_schedule(current_user=Depends(auth.get_current_user)):
    """Return the current restore schedule, or indicate none is set."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )
    job = _scheduler.get_job("daily_restore")
    if not job:
        return {"scheduled": False, "schedule": None, "next_run": None}

    schedule_data = None
    if os.path.exists(RESTORE_SCHEDULE_FILE):
        try:
            with open(RESTORE_SCHEDULE_FILE) as f:
                schedule_data = json.load(f)
        except Exception:
            pass

    return {
        "scheduled": True,
        "schedule": schedule_data,
        "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
    }


@app.delete("/downlink/guardian/restore/schedule")
def delete_restore_schedule(current_user=Depends(auth.get_current_user)):
    """Remove the scheduled restore."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )
    job = _scheduler.get_job("daily_restore")
    if job:
        _scheduler.remove_job("daily_restore")
    if os.path.exists(RESTORE_SCHEDULE_FILE):
        try:
            os.remove(RESTORE_SCHEDULE_FILE)
        except OSError as e:
            logging.warning(f"Could not remove restore schedule file: {e}")
    return {"status": "Restore schedule removed"}


@app.get("/downlink/guardian/restore/history")
def restore_history(limit: int = Query(default=20, ge=1, le=1000), current_user=Depends(auth.get_current_user)):
    """Return last N restore run records (newest first). Default 20, max 1000."""
    if not os.path.exists(RESTORE_HISTORY_FILE):
        return {"total": 0, "history": []}
    try:
        with open(RESTORE_HISTORY_FILE) as f:
            history = json.load(f)
        records = list(reversed(history))[:limit]
        return {"total": len(records), "history": records}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ── Backup control ─────────────────────────────────────

@app.get("/downlink/guardian/backup/status")
def backup_status(current_user=Depends(auth.get_current_user)):
    """Check whether backup is currently enabled or disabled."""
    try:
        with managed_conn(get_target_conn) as (_conn, cur):
            cur.execute("SELECT enabled FROM backup_control WHERE id = TRUE")
            row = cur.fetchone()

            if not row:
                raise ValueError("backup_control row not found")

            return {"backup_enabled": row[0]}

    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except psycopg2.Error as pe:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(pe),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal Server Error: {e}",
        )


@app.post("/downlink/guardian/backup/enable")
def enable_backup(current_user=Depends(auth.get_current_user)):
    """Enable the backup flag so sync runs will proceed."""
    try:
        with managed_conn(get_target_conn) as (conn, cur):
            cur.execute("""
                UPDATE backup_control
                SET enabled = TRUE, updated_at = now()
                WHERE id = TRUE
            """)
            conn.commit()
        return {"status": "Backup enabled"}
    except psycopg2.Error as pe:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal Server Error: {e}")


@app.post("/downlink/guardian/backup/disable")
def disable_backup(current_user=Depends(auth.get_current_user)):
    """Disable the backup flag so sync runs will be skipped."""
    try:
        with managed_conn(get_target_conn) as (conn, cur):
            cur.execute("""
                UPDATE backup_control
                SET enabled = FALSE, updated_at = now()
                WHERE id = TRUE
            """)
            conn.commit()
        return {"status": "Backup disabled"}
    except psycopg2.Error as pe:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal Server Error: {e}")


# ── Watermark reset ────────────────────────────────────

@app.post("/downlink/guardian/backup/reset-watermark")
def reset_watermark(
    from_time: str | None = Query(
        default=None,
        description="Reset watermark to this UTC datetime (ISO format: 2026-01-01T00:00:00). "
                    "Omit to reset to beginning (full re-sync).",
    ),
    current_user=Depends(auth.get_current_user)
):
    """
    Reset the incremental sync watermark.
    Use this if the backup DB crashes and loses data — the next /backup run
    will re-sync from the specified time (or from the very beginning if omitted).
    """
    try:
        if from_time is not None:
            try:
                reset_ts = datetime.fromisoformat(from_time).replace(tzinfo=timezone.utc)
            except ValueError:
                raise ValueError(f"Invalid datetime format: '{from_time}'. Use ISO format e.g. 2026-01-01T00:00:00")
        else:
            reset_ts = datetime(1970, 1, 1, tzinfo=timezone.utc)  # full re-sync from beginning

        with managed_conn(get_target_conn) as (conn, cur):
            cur.execute("""
                UPDATE backup_metadata
                SET last_message_time = %s,
                    last_synced_time  = NULL
                WHERE id = TRUE
            """, (reset_ts,))
            conn.commit()

        return {
            "status": "Watermark reset",
            "last_message_time": reset_ts.isoformat(),
            "note": "Next /downlink/backup run will re-sync all rows after this time",
        }

    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except psycopg2.Error as pe:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal Server Error: {e}")


# ── Scheduled backup ───────────────────────────────────

@app.post("/downlink/guardian/backup/schedule")
def set_backup_schedule(req: BackupScheduleRequest, current_user=Depends(auth.get_current_user)):
    """Schedule a daily automatic backup. Returns 409 if a schedule already exists — DELETE it first.
    mode: incremental (default) | full | limit | hours | range
    """
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )

    existing = _scheduler.get_job("daily_backup")
    if existing:
        saved = {}
        if os.path.exists(SCHEDULE_FILE):
            try:
                with open(SCHEDULE_FILE) as f:
                    saved = json.load(f)
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "A backup schedule already exists. DELETE /downlink/guardian/backup/schedule first.",
                "current_schedule": {k: v for k, v in saved.items() if k != "user_id"},
                "next_run": existing.next_run_time.isoformat() if existing.next_run_time else None,
            },
        )

    start_dt, end_dt = _validate_backup_request(req)
    try:
        kwargs = {}
        persist = {"time": req.time, "timezone": req.timezone, "mode": req.mode, "user_id": current_user.id}

        if req.mode == "limit":
            kwargs["limit"] = req.limit
            persist["limit"] = req.limit
        elif req.mode == "hours":
            kwargs["hours"] = req.hours
            persist["hours"] = req.hours
        elif req.mode == "range":
            kwargs["start_dt"] = start_dt
            kwargs["end_dt"] = end_dt
            persist["start_dt"] = start_dt.isoformat()
            persist["end_dt"] = end_dt.isoformat()

        _apply_schedule(req.time, req.timezone, req.mode, **kwargs)
        with open(SCHEDULE_FILE, "w") as f:
            json.dump(persist, f, indent=2)

        job = _scheduler.get_job("daily_backup")
        next_run = job.next_run_time.isoformat() if job and job.next_run_time else None

        return {
            "status": "Scheduled",
            "time": req.time,
            "timezone": req.timezone,
            "mode": req.mode,
            "next_run": next_run,
            "note": "Backup runs daily at the specified time. Persisted — survives API restarts.",
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/downlink/guardian/backup/schedule")
def get_backup_schedule(current_user=Depends(auth.get_current_user)):
    """Return the current backup schedule, or indicate none is set."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )

    job = _scheduler.get_job("daily_backup")
    if not job:
        return {"scheduled": False, "schedule": None, "next_run": None}

    schedule_data = None
    if os.path.exists(SCHEDULE_FILE):
        try:
            with open(SCHEDULE_FILE) as f:
                schedule_data = json.load(f)
        except Exception:
            pass

    return {
        "scheduled": True,
        "schedule": schedule_data,
        "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
    }


@app.delete("/downlink/guardian/backup/schedule")
def delete_backup_schedule(current_user=Depends(auth.get_current_user)):
    """Remove the scheduled backup."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )

    job = _scheduler.get_job("daily_backup")
    if job:
        _scheduler.remove_job("daily_backup")
    if os.path.exists(SCHEDULE_FILE):
        try:
            os.remove(SCHEDULE_FILE)
        except OSError as e:
            logging.warning(f"Could not remove schedule file: {e}")
    return {"status": "Schedule removed"}


# ── NAS backup schedule ────────────────────────────────

@app.post("/downlink/guardian/nas-backup/schedule")
def set_nas_schedule(req: NasScheduleRequest, current_user=Depends(auth.get_current_user)):
    """Schedule a daily automatic NAS export. Returns 409 if a schedule already exists — DELETE it first.
    mode: full (default) | limit | hours | range
    """
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )

    existing = _scheduler.get_job("daily_nas_backup")
    if existing:
        saved = {}
        if os.path.exists(NAS_SCHEDULE_FILE):
            try:
                with open(NAS_SCHEDULE_FILE) as f:
                    saved = json.load(f)
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "A NAS backup schedule already exists. DELETE /downlink/guardian/nas-backup/schedule first.",
                "current_schedule": {k: v for k, v in saved.items() if k not in ("password", "user_id")},
                "next_run": existing.next_run_time.isoformat() if existing.next_run_time else None,
            },
        )

    start_dt, end_dt = _validate_nas_request(req)

    try:
        ssh, sftp = sftp_connect(req.host, req.port, req.username, req.password)
        sftp.close()
        ssh.close()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSH connection test failed: {e}",
        )

    try:
        kwargs = {}
        enc_password = base64.b64encode(encrypt(req.password.encode(), load_key())).decode()
        persist = {
            "time": req.time, "timezone": req.timezone,
            "host": req.host, "port": req.port,
            "username": req.username, "password": enc_password,
            "remote_path": req.remote_path,
            "mode": req.mode, "user_id": current_user.id,
        }

        if req.mode == "limit":
            kwargs["limit"] = req.limit
            persist["limit"] = req.limit
        elif req.mode == "hours":
            kwargs["hours"] = req.hours
            persist["hours"] = req.hours
        elif req.mode == "range":
            kwargs["start_dt"] = start_dt
            kwargs["end_dt"] = end_dt
            persist["start_dt"] = start_dt.isoformat()
            persist["end_dt"] = end_dt.isoformat()

        _apply_nas_schedule(
            req.time, req.timezone,
            req.host, req.port, req.username, req.password, req.remote_path,
            req.mode, **kwargs,
        )
        with open(NAS_SCHEDULE_FILE, "w") as f:
            json.dump(persist, f, indent=2)

        job = _scheduler.get_job("daily_nas_backup")
        next_run = job.next_run_time.isoformat() if job and job.next_run_time else None

        return {
            "status": "Scheduled",
            "time": req.time,
            "timezone": req.timezone,
            "mode": req.mode,
            "target": f"{req.username}@{req.host}:{req.port}{req.remote_path}",
            "next_run": next_run,
            "note": "NAS export runs daily at the specified time. Persisted — survives API restarts.",
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/downlink/guardian/nas-backup/schedule")
def get_nas_schedule(current_user=Depends(auth.get_current_user)):
    """Return the current NAS backup schedule, or indicate none is set."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )

    job = _scheduler.get_job("daily_nas_backup")
    if not job:
        return {"scheduled": False, "schedule": None, "next_run": None}

    schedule_data = None
    if os.path.exists(NAS_SCHEDULE_FILE):
        try:
            with open(NAS_SCHEDULE_FILE) as f:
                saved = json.load(f)
            # never expose password in response
            schedule_data = {k: v for k, v in saved.items() if k != "password"}
        except Exception:
            pass

    return {
        "scheduled": True,
        "schedule": schedule_data,
        "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
    }


@app.delete("/downlink/guardian/nas-backup/schedule")
def delete_nas_schedule(current_user=Depends(auth.get_current_user)):
    """Remove the scheduled NAS backup."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APScheduler not installed. Run: pip install apscheduler",
        )

    job = _scheduler.get_job("daily_nas_backup")
    if job:
        _scheduler.remove_job("daily_nas_backup")
    if os.path.exists(NAS_SCHEDULE_FILE):
        try:
            os.remove(NAS_SCHEDULE_FILE)
        except OSError as e:
            logging.warning(f"Could not remove NAS schedule file: {e}")
    return {"status": "NAS schedule removed"}


# ── Counts & metadata ──────────────────────────────────

@app.get("/downlink/guardian/backup/sync-status")
def sync_status(current_user=Depends(auth.get_current_user)):
    """Compare Production DB vs Backup DB row counts, sync state, and last sync time."""
    try:
        with managed_conn(get_source_conn) as (_conn, cur):
            cur.execute("SELECT COUNT(*) FROM messages")
            production_count = cur.fetchone()[0]

        last_synced_time = None
        with managed_conn(get_target_conn) as (_conn, cur):
            cur.execute("SELECT COUNT(*) FROM messages")
            backup_count = cur.fetchone()[0]
            cur.execute("SELECT last_synced_time FROM backup_metadata WHERE id = TRUE")
            row = cur.fetchone()
            if row and row[0]:
                last_synced_time = row[0].isoformat()

        difference = production_count - backup_count
        in_sync = difference == 0

        next_run = None
        if _SCHEDULER_AVAILABLE and _scheduler and _scheduler.running:
            job = _scheduler.get_job("daily_backup")
            if job and job.next_run_time:
                next_run = job.next_run_time.isoformat()

        if in_sync:
            message = "Backup is up to date."
        elif next_run:
            message = (
                f"Backup is out of sync by {difference:,} rows. "
                f"Next auto-backup scheduled at {next_run}. "
                f"To sync now: POST /downlink/guardian/backup."
            )
        else:
            message = (
                f"Backup is out of sync by {difference:,} rows. "
                f"No schedule set — sync manually via POST /downlink/guardian/backup."
            )

        return {
            "production_count": production_count,
            "backup_count": backup_count,
            "difference": difference,
            "in_sync": in_sync,
            "last_synced_time": last_synced_time,
            "next_scheduled_backup": next_run,
            "message": message,
        }

    except psycopg2.Error as pe:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(pe),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal Server Error: {e}",
        )



@app.get("/downlink/guardian/backup/history")
def backup_history(limit: int = Query(default=20, ge=1, le=1000), current_user=Depends(auth.get_current_user)):
    """Return last N backup run records (newest first). Default 20, max 1000."""
    if not os.path.exists(BACKUP_HISTORY_FILE):
        return {"total": 0, "history": []}
    try:
        with open(BACKUP_HISTORY_FILE) as f:
            history = json.load(f)
        records = list(reversed(history))[:limit]
        return {"total": len(records), "history": records}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/downlink/guardian/nas/history")
def nas_history(limit: int = Query(default=20, ge=1, le=1000), current_user=Depends(auth.get_current_user)):
    """Return last N NAS export run records (newest first). Default 20, max 1000."""
    if not os.path.exists(NAS_HISTORY_FILE):
        return {"total": 0, "history": []}
    try:
        with open(NAS_HISTORY_FILE) as f:
            history = json.load(f)
        records = list(reversed(history))[:limit]
        return {"total": len(records), "history": records}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/downlink/guardian/nas-config")
def get_nas_configs(current_user=Depends(auth.get_current_user)):
    """Return all saved NAS server configs sorted by last used (newest first)."""
    configs = list(_load_nas_configs().values())
    configs.sort(key=lambda x: x.get("last_used", ""), reverse=True)
    return {"total": len(configs), "servers": configs}




# ── Secure export (Production DB → AES-256-GCM → SHA256 → SFTP → External Server) ──

@app.post("/downlink/guardian/secure-export")
def api_secure_export(remote: RemoteConfig, current_user=Depends(auth.get_current_user)):
    """
    Encrypt all messages with AES-256-GCM, generate SHA256 checksum per batch,
    and transfer to any external server via SFTP.
    Requires BACKUP_ENCRYPTION_KEY env var on the server.
    """
    start = datetime.now(timezone.utc)
    try:
        result = secure_export(
            host=remote.host,
            port=remote.port,
            username=remote.username,
            password=remote.password,
            remote_path=remote.remote_path,
            limit=200000,
        )
        _save_nas_config(remote.host, remote.port, remote.username, remote.remote_path)
        _append_history(NAS_HISTORY_FILE, {
            "start_time": start.isoformat(),
            "status": "SUCCESS",
            "duration_seconds": result.get("duration_seconds"),
            "total_rows": result.get("total_rows"),
            "total_batches": result.get("total_batches"),
            "target": f"{remote.username}@{remote.host}:{remote.port}{remote.remote_path}",
        })
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        _append_history(NAS_HISTORY_FILE, {
            "start_time": start.isoformat(),
            "status": "FAILED",
            "duration_seconds": round((datetime.now(timezone.utc) - start).total_seconds(), 2),
            "total_rows": None,
            "total_batches": None,
            "target": f"{remote.username}@{remote.host}:{remote.port}{remote.remote_path}",
        })
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ── Secure import → Backup DB (External Server → Verify SHA256 → Decrypt → TimescaleDB) ──

@app.post("/downlink/guardian/secure-import/backup-db")
def api_secure_import_backup(remote: RemoteConfig, current_user=Depends(auth.get_current_user)):
    """
    Download encrypted batches from NAS, verify SHA256, decrypt, and insert into
    TimescaleDB (backup DB). Hard cap: 50,000 rows. Use the schedule endpoint for full imports.
    """
    try:
        return secure_import(
            host=remote.host,
            port=remote.port,
            username=remote.username,
            password=remote.password,
            remote_path=remote.remote_path,
            target="backup",
            limit=50000,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ── Secure import → Production DB (External Server → Verify SHA256 → Decrypt → Magistrala) ──

@app.post("/downlink/guardian/secure-import/production-db")
def api_secure_import_production(remote: RemoteConfig, current_user=Depends(auth.get_current_user)):
    """
    Download encrypted batches from NAS, verify SHA256, decrypt, and insert into
    Production DB (magistrala). Hard cap: 50,000 rows. Use the schedule endpoint for full imports.
    """
    try:
        return secure_import(
            host=remote.host,
            port=remote.port,
            username=remote.username,
            password=remote.password,
            remote_path=remote.remote_path,
            target="production",
            limit=50000,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ── Secure import schedule — backup-db ─────────────────────────────────────────

def _import_schedule_post(req: ImportScheduleRequest, target: str,
                          schedule_file: str, job_id: str,
                          current_user) -> dict:
    """Shared logic for both import schedule POST endpoints."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="APScheduler not installed. Run: pip install apscheduler")

    existing = _scheduler.get_job(job_id)
    if existing:
        saved = {}
        if os.path.exists(schedule_file):
            try:
                with open(schedule_file) as f:
                    saved = json.load(f)
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": f"An import schedule for {target} already exists. "
                           f"DELETE /downlink/guardian/secure-import/{target}/schedule first.",
                "current_schedule": {k: v for k, v in saved.items() if k not in ("password", "user_id")},
                "next_run": existing.next_run_time.isoformat() if existing.next_run_time else None,
            },
        )

    start_dt, end_dt = _validate_import_request(req)

    try:
        ssh, sftp = sftp_connect(req.host, req.port, req.username, req.password)
        sftp.close()
        ssh.close()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"SSH connection test failed: {e}")

    try:
        kwargs = {}
        enc_password = base64.b64encode(encrypt(req.password.encode(), load_key())).decode()
        persist = {
            "time": req.time, "timezone": req.timezone,
            "host": req.host, "port": req.port,
            "username": req.username, "password": enc_password,
            "remote_base_path": req.remote_path,
            "mode": req.mode, "user_id": current_user.id,
        }
        if req.folder:
            persist["folder"] = req.folder

        if req.mode == "limit":
            kwargs["limit"] = req.limit
            persist["limit"] = req.limit
        elif req.mode == "hours":
            kwargs["hours"] = req.hours
            persist["hours"] = req.hours
        elif req.mode == "range":
            kwargs["start_dt"] = start_dt
            kwargs["end_dt"] = end_dt
            persist["start_dt"] = start_dt.isoformat()
            persist["end_dt"] = end_dt.isoformat()

        _apply_import_schedule(
            req.time, req.timezone, target,
            req.host, req.port, req.username, req.password,
            req.remote_path, req.mode, folder=req.folder, **kwargs,
        )
        with open(schedule_file, "w") as f:
            json.dump(persist, f, indent=2)

        job = _scheduler.get_job(job_id)
        next_run = job.next_run_time.isoformat() if job and job.next_run_time else None

        return {
            "status": "Scheduled",
            "target": target,
            "time": req.time,
            "timezone": req.timezone,
            "mode": req.mode,
            "nas": f"{req.username}@{req.host}:{req.port}{req.remote_path}",
            "next_run": next_run,
            "note": "Imports from the latest export_* folder on NAS daily. Persisted — survives API restarts.",
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/downlink/guardian/secure-import/backup-db/schedule")
def set_import_backup_schedule(req: ImportScheduleRequest, current_user=Depends(auth.get_current_user)):
    """Schedule daily NAS → TimescaleDB import. 409 if schedule already exists — DELETE it first.
    mode: full (default) | limit | hours | range. Picks the latest export_* folder automatically.
    """
    return _import_schedule_post(req, "backup",
                                 IMPORT_BACKUP_SCHEDULE_FILE, "daily_import_backup", current_user)


@app.get("/downlink/guardian/secure-import/backup-db/schedule")
def get_import_backup_schedule(current_user=Depends(auth.get_current_user)):
    """Return the current NAS → backup-db import schedule, or indicate none is set."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="APScheduler not installed.")
    job = _scheduler.get_job("daily_import_backup")
    schedule_data = None
    if os.path.exists(IMPORT_BACKUP_SCHEDULE_FILE):
        try:
            with open(IMPORT_BACKUP_SCHEDULE_FILE) as f:
                saved = json.load(f)
            schedule_data = {k: v for k, v in saved.items() if k not in ("password", "user_id")}
        except Exception:
            pass
    return {
        "scheduled": bool(job),
        "schedule": schedule_data,
        "next_run": job.next_run_time.isoformat() if job and job.next_run_time else None,
    }


@app.delete("/downlink/guardian/secure-import/backup-db/schedule")
def delete_import_backup_schedule(current_user=Depends(auth.get_current_user)):
    """Remove the scheduled NAS → backup-db import."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="APScheduler not installed.")
    job = _scheduler.get_job("daily_import_backup")
    if job:
        _scheduler.remove_job("daily_import_backup")
    if os.path.exists(IMPORT_BACKUP_SCHEDULE_FILE):
        try:
            os.remove(IMPORT_BACKUP_SCHEDULE_FILE)
        except OSError as e:
            logging.warning(f"Could not remove import backup schedule file: {e}")
    return {"status": "Import backup schedule removed"}


# ── Secure import schedule — production-db ──────────────────────────────────────

@app.post("/downlink/guardian/secure-import/production-db/schedule")
def set_import_production_schedule(req: ImportScheduleRequest, current_user=Depends(auth.get_current_user)):
    """Schedule daily NAS → Production DB import. 409 if schedule already exists — DELETE it first.
    mode: full (default) | limit | hours | range. Picks the latest export_* folder automatically.
    """
    return _import_schedule_post(req, "production",
                                 IMPORT_PRODUCTION_SCHEDULE_FILE, "daily_import_production", current_user)


@app.get("/downlink/guardian/secure-import/production-db/schedule")
def get_import_production_schedule(current_user=Depends(auth.get_current_user)):
    """Return the current NAS → production-db import schedule, or indicate none is set."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="APScheduler not installed.")
    job = _scheduler.get_job("daily_import_production")
    schedule_data = None
    if os.path.exists(IMPORT_PRODUCTION_SCHEDULE_FILE):
        try:
            with open(IMPORT_PRODUCTION_SCHEDULE_FILE) as f:
                saved = json.load(f)
            schedule_data = {k: v for k, v in saved.items() if k not in ("password", "user_id")}
        except Exception:
            pass
    return {
        "scheduled": bool(job),
        "schedule": schedule_data,
        "next_run": job.next_run_time.isoformat() if job and job.next_run_time else None,
    }


@app.delete("/downlink/guardian/secure-import/production-db/schedule")
def delete_import_production_schedule(current_user=Depends(auth.get_current_user)):
    """Remove the scheduled NAS → production-db import."""
    if not _SCHEDULER_AVAILABLE:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="APScheduler not installed.")
    job = _scheduler.get_job("daily_import_production")
    if job:
        _scheduler.remove_job("daily_import_production")
    if os.path.exists(IMPORT_PRODUCTION_SCHEDULE_FILE):
        try:
            os.remove(IMPORT_PRODUCTION_SCHEDULE_FILE)
        except OSError as e:
            logging.warning(f"Could not remove import production schedule file: {e}")
    return {"status": "Import production schedule removed"}


# ── List all exports on NAS ─────────────────────────────────────────────────

class ListExportsRequest(BaseModel):
    host: str = Field(..., description="Remote server hostname or IP address")
    port: int = Field(22, ge=1, le=65535, description="SSH port")
    username: str = Field(..., description="SSH username")
    password: str = Field(..., description="SSH password")
    remote_path: str = Field(..., description="Base backup folder on remote server")


@app.post("/downlink/guardian/secure-export/list")
def api_list_exports(req: ListExportsRequest, current_user=Depends(auth.get_current_user)):
    """
    List all export folders under remote_path, with date, row count and batch count
    from each manifest.json. Use the returned export_path to pass into import or preview.
    """
    try:
        ssh, sftp = sftp_connect(req.host, req.port, req.username, req.password)
        exports = []

        try:
            entries = sftp.listdir_attr(req.remote_path)
            export_dirs = sorted(
                [e.filename for e in entries if e.filename.startswith("export_")],
                reverse=True,
            )

            for folder in export_dirs:
                full_path = f"{req.remote_path.rstrip('/')}/{folder}"
                manifest_path = f"{full_path}/manifest.json"
                try:
                    with sftp.open(manifest_path, "r") as f:
                        manifest = json.load(f)
                    exports.append({
                        "folder": folder,
                        "export_path": full_path,
                        "exported_at": manifest.get("exported_at"),
                        "total_rows": manifest.get("total_rows"),
                        "total_batches": manifest.get("total_batches"),
                    })
                except Exception:
                    exports.append({
                        "folder": folder,
                        "export_path": full_path,
                        "exported_at": None,
                        "total_rows": None,
                        "total_batches": None,
                        "note": "manifest.json missing or unreadable",
                    })
        finally:
            sftp.close()
            ssh.close()

        return {"total": len(exports), "exports": exports}

    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# ── Preview encrypted batch from NAS (no DB write) ─────────────────────────

class PreviewRequest(BaseModel):
    host: str = Field(..., description="Remote server hostname or IP address")
    port: int = Field(22, ge=1, le=65535, description="SSH port")
    username: str = Field(..., description="SSH username")
    password: str = Field(..., description="SSH password")
    remote_path: str = Field(..., description="Folder on remote server containing the backup")
    batch: int = Field(0, ge=0, description="Batch index to preview (0-based)")
    rows: int = Field(10, ge=1, le=1000, description="Number of rows to return")


@app.post("/downlink/guardian/secure-export/preview")
def api_preview_batch(req: PreviewRequest, current_user=Depends(auth.get_current_user)):
    """
    Download a single encrypted batch from the remote server, verify SHA256,
    decrypt, and return up to N rows as JSON — no DB write.
    Useful for inspecting what is stored on the NAS.
    """
    try:
        key = load_key()
        ssh, sftp = sftp_connect(req.host, req.port, req.username, req.password)

        try:
            # Read manifest to get checksum for the requested batch
            with sftp.open(f"{req.remote_path}/manifest.json", "r") as f:
                manifest = json.load(f)

            batches = manifest.get("batches", [])
            if req.batch >= len(batches):
                raise ValueError(
                    f"Batch {req.batch} does not exist — "
                    f"manifest has {len(batches)} batch(es) (0-based index)"
                )

            entry = batches[req.batch]
            batch_file = entry["file"]
            expected_checksum = entry["checksum"]

            with sftp.open(f"{req.remote_path}/{batch_file}", "rb") as f:
                encrypted = f.read()

        finally:
            sftp.close()
            ssh.close()

        # Verify integrity
        actual_checksum = sha256_hex(encrypted)
        if actual_checksum != expected_checksum:
            raise ValueError(
                f"SHA256 mismatch on {batch_file}: "
                f"expected {expected_checksum}, got {actual_checksum}"
            )

        # Decrypt
        plaintext = gzip.decompress(decrypt(encrypted, key))
        reader = csv.DictReader(io.StringIO(plaintext.decode("utf-8")))
        rows = [dict(r) for _, r in zip(range(req.rows), reader)]

        return {
            "batch": req.batch,
            "file": batch_file,
            "total_rows_in_batch": entry["rows"],
            "rows_returned": len(rows),
            "checksum_verified": True,
            "columns": COLUMNS,
            "data": rows,
        }

    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

