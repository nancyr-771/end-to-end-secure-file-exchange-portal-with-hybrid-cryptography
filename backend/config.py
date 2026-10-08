import os
from datetime import timedelta

# Load .env file manually or via dotenv if available
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
env_path = os.path.join(base_dir, '.env')
if os.path.exists(env_path):
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    k, v = k.strip(), v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception:
        pass

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'secure-file-portal-super-secret-jwt-key-2026')
    JWT_EXPIRATION_HOURS = int(os.environ.get('JWT_EXPIRATION_HOURS', 24))
    
    # MongoDB Config
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    DB_NAME = os.environ.get('DB_NAME', 'fileexchange')
    
    # Storage
    BASE_DIR = base_dir
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
    DATA_FOLDER = os.path.join(BASE_DIR, 'data')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 500 * 1024 * 1024))  # 500 MB max payload limit
    
    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')

