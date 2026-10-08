import time
import jwt
import bcrypt
from functools import wraps
from flask import request, jsonify
from backend.config import Config
from backend.models import db

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False

def generate_jwt_token(user_id: str, email: str, name: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "name": name,
        "iat": int(time.time()),
        "exp": int(time.time() + (Config.JWT_EXPIRATION_HOURS * 3600))
    }
    token = jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")
    return token

def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check Authorization Header: Bearer <token>
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        
        # Also check cookie if header is absent
        if not token:
            token = request.cookies.get("jwt_token")
            
        if not token:
            return jsonify({"success": False, "message": "Authentication token missing"}), 401
            
        decoded = decode_jwt_token(token)
        if "error" in decoded:
            return jsonify({"success": False, "message": decoded["error"]}), 401
            
        user = db.get_user_by_id(decoded["sub"])
        if not user:
            return jsonify({"success": False, "message": "User not found or deleted"}), 401
            
        return f(current_user=user, *args, **kwargs)
    return decorated

def get_authenticated_user_optional():
    """Extracts authenticated user if JWT token is present and valid, otherwise returns None without throwing 401."""
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    if not token:
        token = request.cookies.get("jwt_token")
    if not token:
        token = request.args.get("token")
        
    if not token:
        return None
        
    decoded = decode_jwt_token(token)
    if not decoded or "error" in decoded:
        return None
        
    return db.get_user_by_id(decoded.get("sub"))
