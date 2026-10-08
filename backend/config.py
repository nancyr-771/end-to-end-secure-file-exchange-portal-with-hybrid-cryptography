import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'secure-file-portal-super-secret-jwt-key-2026')
    JWT_EXPIRATION_HOURS = int(os.environ.get('JWT_EXPIRATION_HOURS', 24))
    
    # MongoDB Config
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    DB_NAME = os.environ.get('DB_NAME', 'fileexchange')
    
    # Storage
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    DATA_FOLDER = os.path.join(BASE_DIR, 'data')
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500 MB max payload limit
    
    # CORS
    CORS_ORIGINS = "*"
