import threading
import logging
import config
import grpc
import uvicorn
import os
from scheduler import start_scheduler
from event_fetcher_parse import initialize_key_rotation, start_mqtt_client
from captcha_utils import init_redis
import asyncio
# Load the .env file from auth folder
from dotenv import load_dotenv
from pathlib import Path
env_path = Path('.') / 'auth' / '.env'
load_dotenv(dotenv_path=env_path)



# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Replace with actual values
channel = grpc.insecure_channel(config.CHIRPSTACK_HOST)  # Set up your gRPC channel here
auth_token = config.AUTH_METADATA  # Set your authentication token here

def run_api():
    """Function to run FastAPI server in a separate thread."""
    uvicorn.run("api_downlink:app", host="0.0.0.0", port=4567, reload=False)

def start_redis_thread():
    """Wrapper to start Redis connection check in a separate thread."""
    async def run_redis():
        await init_redis()

    def thread_target():
        asyncio.run(run_redis())

    redis_thread = threading.Thread(target=thread_target, daemon=True)
    redis_thread.start()
    logger.info("Redis init thread started.")
    return redis_thread

if __name__ == "__main__":
    try:
        from api_downlink import models, database, auth
        from Notifications.db_notification import models as notification_models  
       
        logger.info("Initializing database...")
        models.Base.metadata.create_all(bind=database.engine)

        # Create default admin if not exists
        def create_default_admin():
            db = database.SessionLocal()
            try:
                email = os.getenv("DEFAULT_ADMIN_EMAIL")
                secret = os.getenv("DEFAULT_ADMIN_SECRET")

                if not email or not secret:
                    logger.warning("DEFAULT_ADMIN_EMAIL or DEFAULT_ADMIN_SECRET not set!")
                    return

                user = db.query(models.User).filter(models.User.email == email).first()
                if user:
                    logger.info("Default admin already exists.")
                else:
                    hashed_secret = auth.get_password_hash(secret)
                    new_admin = models.User(email=email, secret=hashed_secret)
                    db.add(new_admin)
                    db.commit()
                    logger.info("Default admin created.")
            finally:
                db.close()

        create_default_admin()

        logger.info("Starting API server...")
        api_thread = threading.Thread(target=run_api, daemon=True)
        api_thread.start()

        logger.info("Starting device scheduler...")
        scheduler_thread = threading.Thread(target=start_scheduler, daemon=True)
        scheduler_thread.start()

        logger.info("Initializing key rotation...")
        key_rotation_thread = threading.Thread(target=initialize_key_rotation, args=(channel, auth_token), daemon=True)
        key_rotation_thread.start()

        logger.info("Starting MQTT event listener...")
        start_mqtt_client()  # Runs in the main thread

        logger.info("Starting Redis listener...")
        start_redis_thread()

    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
    except Exception as e:
        logger.exception(f"Unexpected error in main: {e}")
