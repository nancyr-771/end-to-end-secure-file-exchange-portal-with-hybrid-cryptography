import os
import time
import uuid
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

from backend.config import Config
from backend.models import db
from backend.auth import hash_password, verify_password, generate_jwt_token, token_required
from backend.crypto_helpers import validate_x25519_public_key, validate_ed25519_public_key

app = Flask(__name__, static_folder=os.path.join(Config.BASE_DIR, 'frontend'), static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# ----------------- STATIC FRONTEND ROUTES -----------------
@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/download/<share_uuid>')
def serve_download_page(share_uuid):
    return send_from_directory(app.static_folder, 'download.html')

@app.route('/<path:path>')
def serve_static(path):
    full_path = os.path.join(app.static_folder, path)
    if os.path.exists(full_path):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# ----------------- SYSTEM STATUS & AUDIT -----------------
@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "success": True,
        "database": "MongoDB" if db.is_mongo else "Local Persistent JSON",
        "version": "3.2.0-Production",
        "timestamp": time.time(),
        "cryptographic_primitives": {
            "file_encryption": "XChaCha20-Poly1305 (256-bit Authenticated AEAD)",
            "key_exchange": "X25519 (ECDH Key Agreement)",
            "key_derivation": "HKDF-SHA256 (RFC 5869)",
            "signatures": "Ed25519 (Digital Signatures)",
            "password_protection": "Argon2id / PBKDF2 (100,000 Rounds)",
            "transport": "TLS 1.3 / HTTPS"
        }
    })

@app.route('/api/audit/logs', methods=['GET'])
@token_required
def get_audit_logs(current_user):
    logs = db.get_user_audit_logs(current_user["user_id"], current_user["email"], limit=100)
    return jsonify({"success": True, "logs": logs})

# ----------------- AUTHENTICATION -----------------
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    x25519_pk = data.get("x25519_public_key", "").strip()
    ed25519_pk = data.get("ed25519_public_key", "").strip()
    encrypted_key_vault = data.get("encrypted_key_vault", None)
    
    if not name or not email or not password:
        return jsonify({"success": False, "message": "Name, email, and password are required."}), 400
    
    if not x25519_pk or not ed25519_pk:
        return jsonify({"success": False, "message": "Cryptographic public keys are required."}), 400

    if not validate_x25519_public_key(x25519_pk):
        return jsonify({"success": False, "message": "Invalid Key Exchange public key format."}), 400
        
    if not validate_ed25519_public_key(ed25519_pk):
        return jsonify({"success": False, "message": "Invalid Signing public key format."}), 400
        
    existing_user = db.get_user_by_email(email)
    if existing_user:
        return jsonify({"success": False, "message": "An account with this email already exists."}), 409
        
    user_id = str(uuid.uuid4())
    pw_hash = hash_password(password)
    
    user_doc = {
        "user_id": user_id,
        "name": name,
        "email": email,
        "password_hash": pw_hash,
        "x25519_public_key": x25519_pk,
        "ed25519_public_key": ed25519_pk,
        "encrypted_key_vault": encrypted_key_vault,
        "created_at": time.time()
    }
    
    try:
        db.create_user(user_doc)
        db.log_audit("USER_REGISTERED", {"user_id": user_id, "email": email, "name": name})
        
        token = generate_jwt_token(user_id, email, name)
        return jsonify({
            "success": True,
            "message": "Account created successfully.",
            "token": token,
            "user": {
                "user_id": user_id,
                "name": name,
                "email": email,
                "x25519_public_key": x25519_pk,
                "ed25519_public_key": ed25519_pk,
                "encrypted_key_vault": encrypted_key_vault
            }
        }), 201
    except Exception as e:
        return jsonify({"success": False, "message": f"Registration error: {str(e)}"}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400
        
    user = db.get_user_by_email(email)
    if not user or not verify_password(password, user["password_hash"]):
        db.log_audit("LOGIN_FAILED", {"email": email, "ip": request.remote_addr})
        return jsonify({"success": False, "message": "Invalid email or password."}), 401
        
    token = generate_jwt_token(user["user_id"], user["email"], user["name"])
    db.log_audit("LOGIN_SUCCESS", {"user_id": user["user_id"], "email": email})
    
    return jsonify({
        "success": True,
        "message": "Login successful",
        "token": token,
        "user": {
            "user_id": user["user_id"],
            "name": user["name"],
            "email": user["email"],
            "x25519_public_key": user.get("x25519_public_key", ""),
            "ed25519_public_key": user.get("ed25519_public_key", ""),
            "encrypted_key_vault": user.get("encrypted_key_vault", None)
        }
    })

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({
        "success": True,
        "user": {
            "user_id": current_user["user_id"],
            "name": current_user["name"],
            "email": current_user["email"],
            "x25519_public_key": current_user.get("x25519_public_key", ""),
            "ed25519_public_key": current_user.get("ed25519_public_key", ""),
            "encrypted_key_vault": current_user.get("encrypted_key_vault", None)
        }
    })

# ----------------- DASHBOARD STATS -----------------
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats(current_user):
    files = db.get_files_for_user(current_user["user_id"])
    sent = files.get("sent", [])
    received = files.get("received", [])
    
    now = time.time()
    expiring_soon = 0
    for f in sent + received:
        exp = f.get("expires_at", 0)
        if exp > now and (exp - now) < (24 * 3600):
            expiring_soon += 1
            
    recent = sorted(sent + received, key=lambda x: x.get("created_at", 0), reverse=True)[:5]
    
    return jsonify({
        "success": True,
        "stats": {
            "my_files_count": len(sent),
            "shared_count": len([f for f in sent if f.get("recipient_id") != "public"]),
            "received_count": len(received),
            "expiring_count": expiring_soon
        },
        "recent_files": recent
    })

# ----------------- USERS & PUBLIC KEY DIRECTORY -----------------
@app.route('/api/users', methods=['GET'])
@token_required
def list_users(current_user):
    query = request.args.get('q', '').strip()
    users = db.list_users(query)
    filtered = [u for u in users if u["user_id"] != current_user["user_id"]]
    return jsonify({"success": True, "users": filtered})

# ----------------- FILE UPLOAD (E2EE) -----------------
@app.route('/api/files/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'encrypted_file' not in request.files:
        return jsonify({"success": False, "message": "Encrypted file payload missing."}), 400
        
    file_obj = request.files['encrypted_file']
    filename = secure_filename(request.form.get("filename", "encrypted_file.bin"))
    if not filename:
        filename = "encrypted_file.bin"
        
    recipient_id = request.form.get("recipient_id", "public").strip()
    wrapped_file_key = request.form.get("wrapped_file_key", "").strip()
    ephemeral_public_key = request.form.get("ephemeral_public_key", "").strip()
    signature_ed25519 = request.form.get("signature_ed25519", "").strip()
    is_passphrase_protected = request.form.get("is_passphrase_protected", "false").lower() == "true"
    
    try:
        expiry_hours = float(request.form.get("expiry_hours", 24))
    except ValueError:
        expiry_hours = 24.0
        
    try:
        max_downloads = int(request.form.get("max_downloads", 5))
    except ValueError:
        max_downloads = 5

    if not wrapped_file_key:
        return jsonify({"success": False, "message": "Wrapped file key envelope is required."}), 400

    recipient_email = "Public Link"
    if recipient_id != "public":
        recipient_user = db.get_user_by_id(recipient_id)
        if not recipient_user:
            return jsonify({"success": False, "message": "Recipient user not found."}), 404
        recipient_email = recipient_user["email"]

    file_id = str(uuid.uuid4())
    share_uuid = uuid.uuid4().hex[:12]
    
    saved_filename = f"{file_id}_{share_uuid}.enc"
    saved_filepath = os.path.join(Config.UPLOAD_FOLDER, saved_filename)
    file_obj.save(saved_filepath)
    file_size_bytes = os.path.getsize(saved_filepath)
    
    now = time.time()
    expires_at = (now + (expiry_hours * 3600)) if expiry_hours > 0 else 0
    
    file_record = {
        "file_id": file_id,
        "share_uuid": share_uuid,
        "sender_id": current_user["user_id"],
        "sender_name": current_user["name"],
        "sender_email": current_user["email"],
        "sender_ed25519_pk": current_user.get("ed25519_public_key", ""),
        "sender_x25519_pk": current_user.get("x25519_public_key", ""),
        "recipient_id": recipient_id,
        "recipient_email": recipient_email,
        "filename": filename,
        "file_size": file_size_bytes,
        "encrypted_blob_path": saved_filename,
        "wrapped_file_key": wrapped_file_key,
        "ephemeral_public_key": ephemeral_public_key,
        "signature_ed25519": signature_ed25519,
        "is_passphrase_protected": is_passphrase_protected,
        "expires_at": expires_at,
        "max_downloads": max_downloads,
        "download_count": 0,
        "created_at": now,
        "status": "active"
    }
    
    db.create_file_record(file_record)
    db.log_audit("FILE_UPLOADED", {
        "file_id": file_id,
        "share_uuid": share_uuid,
        "filename": filename,
        "sender": current_user["email"],
        "recipient": recipient_email,
        "size_bytes": file_size_bytes,
        "passphrase_protected": is_passphrase_protected
    })
    
    return jsonify({
        "success": True,
        "message": "File encrypted and uploaded successfully!",
        "share_uuid": share_uuid,
        "file_id": file_id,
        "download_url": f"/download/{share_uuid}",
        "expires_at": expires_at,
        "max_downloads": max_downloads,
        "is_passphrase_protected": is_passphrase_protected
    }), 201

# ----------------- USER DASHBOARD LISTS -----------------
@app.route('/api/files/my-uploads', methods=['GET'])
@token_required
def get_my_uploads(current_user):
    files = db.get_files_for_user(current_user["user_id"])
    return jsonify({"success": True, "uploads": files["sent"]})

@app.route('/api/files/shared-with-me', methods=['GET'])
@token_required
def get_shared_with_me(current_user):
    files = db.get_files_for_user(current_user["user_id"])
    return jsonify({"success": True, "received": files["received"]})

@app.route('/api/files/<file_id>', methods=['DELETE'])
@token_required
def delete_file(current_user, file_id):
    deleted = db.delete_file_record(file_id, current_user["user_id"])
    if not deleted:
        return jsonify({"success": False, "message": "File not found or permission denied."}), 404
        
    blob_path = os.path.join(Config.UPLOAD_FOLDER, deleted.get("encrypted_blob_path", ""))
    if os.path.exists(blob_path):
        try:
            os.remove(blob_path)
        except Exception:
            pass
            
    db.log_audit("FILE_DELETED", {
        "file_id": file_id,
        "filename": deleted.get("filename", ""),
        "sender": current_user["email"]
    })
    return jsonify({"success": True, "message": "File deleted permanently from server storage."})

# ----------------- FILE INFO & DOWNLOAD -----------------
@app.route('/api/files/info/<share_uuid>', methods=['GET'])
def get_file_info(share_uuid):
    file_doc = db.get_file_by_uuid(share_uuid)
    if not file_doc:
        return jsonify({"success": False, "message": "This secure download link was not found or has been deleted."}), 404
        
    now = time.time()
    # Check expiry
    if file_doc.get("expires_at", 0) > 0 and now > file_doc["expires_at"]:
        db.log_audit("EXPIRED_ACCESS_ATTEMPT", {"share_uuid": share_uuid, "filename": file_doc.get("filename", ""), "ip": request.remote_addr})
        return jsonify({
            "success": False,
            "expired": True,
            "message": "This secure link has expired. The file is no longer available."
        }), 410
        
    # Check download limits
    if file_doc.get("max_downloads", 0) > 0 and file_doc.get("download_count", 0) >= file_doc["max_downloads"]:
        return jsonify({
            "success": False,
            "limit_reached": True,
            "message": "Download limit reached. This secure file has already reached its maximum permitted downloads."
        }), 410

    return jsonify({
        "success": True,
        "file": {
            "filename": file_doc["filename"],
            "file_size": file_doc["file_size"],
            "sender_name": file_doc["sender_name"],
            "sender_email": file_doc["sender_email"],
            "sender_ed25519_pk": file_doc.get("sender_ed25519_pk", ""),
            "sender_x25519_pk": file_doc.get("sender_x25519_pk", ""),
            "recipient_id": file_doc.get("recipient_id", "public"),
            "recipient_email": file_doc.get("recipient_email", ""),
            "wrapped_file_key": file_doc.get("wrapped_file_key", ""),
            "ephemeral_public_key": file_doc.get("ephemeral_public_key", ""),
            "signature_ed25519": file_doc.get("signature_ed25519", ""),
            "is_passphrase_protected": file_doc.get("is_passphrase_protected", False),
            "download_count": file_doc.get("download_count", 0),
            "max_downloads": file_doc.get("max_downloads", 0),
            "expires_at": file_doc.get("expires_at", 0),
            "created_at": file_doc.get("created_at", 0)
        }
    })

@app.route('/api/files/download/<share_uuid>', methods=['GET'])
def download_file(share_uuid):
    file_doc = db.get_file_by_uuid(share_uuid)
    if not file_doc:
        return jsonify({"success": False, "message": "File not found."}), 404
        
    now = time.time()
    if file_doc.get("expires_at", 0) > 0 and now > file_doc["expires_at"]:
        return jsonify({"success": False, "message": "This secure link has expired."}), 410
        
    if file_doc.get("max_downloads", 0) > 0 and file_doc.get("download_count", 0) >= file_doc["max_downloads"]:
        return jsonify({"success": False, "message": "Download limit reached."}), 410
        
    blob_filename = file_doc["encrypted_blob_path"]
    full_path = os.path.join(Config.UPLOAD_FOLDER, blob_filename)
    
    if not os.path.exists(full_path):
        return jsonify({"success": False, "message": "Encrypted file data not found on server."}), 404
        
    new_count = file_doc.get("download_count", 0) + 1
    db.increment_download_count(file_doc["file_id"])
    
    db.log_audit("FILE_DOWNLOADED", {
        "file_id": file_doc["file_id"],
        "share_uuid": share_uuid,
        "filename": file_doc["filename"],
        "sender": file_doc["sender_email"],
        "recipient": file_doc.get("recipient_email", ""),
        "download_number": new_count,
        "ip": request.remote_addr
    })
    
    return send_file(
        full_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"{file_doc['filename']}.enc"
    )

if __name__ == '__main__':
    print("==================================================")
    print("  🔒 SECURE FILE EXCHANGE PORTAL - HYBRID E2EE  ")
    print(f"  📂 Storage Directory: {Config.UPLOAD_FOLDER}")
    print(f"  🗄️ Database: {'MongoDB' if db.is_mongo else 'Local Storage'}")
    print("  🌐 Running at: http://127.0.0.1:5000")
    print("==================================================")
    app.run(host='0.0.0.0', port=5000, debug=True)
