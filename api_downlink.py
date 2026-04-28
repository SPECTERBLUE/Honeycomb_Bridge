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
from fastapi import Query
from fastapi.encoders import jsonable_encoder
from Notifications.worker import run_notification_worker
from Notifications.db_notification.models import Notification, NotificationAction
from Notifications.schema import CloseNotificationRequest, NotificationResponse
from Notifications.db_notification.crud import get_notifications, get_last_notification_timestamp, close_notification, get_notifications_by_status
from captcha_utils import (
    redis_client,
    generate_captcha_text,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    decrypt_aes_gcm_downlink_login
)

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
            "http://localhost:9002/users/reset-without-token",
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
            train_service = TrainService()
            result = await train_service.train(
                csv_path=payload.dataset_path,
                target_column=payload.target_column,
                user_model_name=payload.model_name,
                algorithm=payload.model_type,
                horizon=payload.horizon
            )
            await redis_client.set(key, json.dumps({
                "status": "completed",
                "model_name": payload.model_name,
                "target_column": payload.target_column,
                "metrics": result["metrics"],
                "metadata": result["metadata"]
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
            )
 
            await redis_client.set(key, json.dumps({
                "status": "completed",
                "model_name": payload.model_name,
                "target_column": payload.target_column,
                "metrics": result["metrics"],
                "metadata": result["metadata"]
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