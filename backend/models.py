import os
import json
import time
import uuid
import threading
from pymongo import MongoClient
from backend.config import Config

class Database:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(Database, cls).__new__(cls)
                cls._instance._init_db()
            return cls._instance

    def _init_db(self):
        self.is_mongo = False
        self.db = None
        self.data_dir = Config.DATA_FOLDER
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

        try:
            client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=1500)
            client.admin.command('ping')
            self.db = client[Config.DB_NAME]
            self.is_mongo = True
            
            # Setup indexes
            self.db.users.create_index("email", unique=True)
            self.db.users.create_index("user_id", unique=True)
            self.db.files.create_index("file_id", unique=True)
            self.db.files.create_index("share_uuid", unique=True)
            self.db.audit_logs.create_index("timestamp")
            print("[Database] Successfully connected to MongoDB!")
        except Exception as e:
            print(f"[Database] MongoDB unavailable ({e}). Using persistent local storage.")
            self.is_mongo = False
            self.local_store = {
                "users": os.path.join(self.data_dir, "users.json"),
                "files": os.path.join(self.data_dir, "files.json"),
                "audit_logs": os.path.join(self.data_dir, "audit_logs.json")
            }
            for path in self.local_store.values():
                if not os.path.exists(path):
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump([], f)

    def _read_local(self, collection_name):
        path = self.local_store[collection_name]
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _write_local(self, collection_name, data):
        path = self.local_store[collection_name]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # ---------------- USER OPERATIONS ----------------
    def create_user(self, user_data):
        if self.is_mongo:
            res = self.db.users.insert_one(user_data)
            user_data["_id"] = str(res.inserted_id)
            return user_data
        else:
            users = self._read_local("users")
            if any(u["email"].lower() == user_data["email"].lower() for u in users):
                raise ValueError("Email already registered.")
            users.append(user_data)
            self._write_local("users", users)
            return user_data

    def get_user_by_email(self, email):
        if self.is_mongo:
            user = self.db.users.find_one({"email": email.lower()})
            if user:
                user["_id"] = str(user["_id"])
            return user
        else:
            users = self._read_local("users")
            for u in users:
                if u["email"].lower() == email.lower():
                    return u
            return None

    def get_user_by_id(self, user_id):
        if self.is_mongo:
            user = self.db.users.find_one({"user_id": user_id})
            if user:
                user["_id"] = str(user["_id"])
            return user
        else:
            users = self._read_local("users")
            for u in users:
                if u["user_id"] == user_id:
                    return u
            return None

    def list_users(self, query=""):
        if self.is_mongo:
            filt = {}
            if query:
                filt = {"$or": [{"name": {"$regex": query, "$options": "i"}}, {"email": {"$regex": query, "$options": "i"}}]}
            users = list(self.db.users.find(filt, {"password_hash": 0, "encrypted_key_vault": 0}))
            for u in users:
                u["_id"] = str(u["_id"])
            return users
        else:
            users = self._read_local("users")
            res = []
            for u in users:
                if not query or (query.lower() in u["name"].lower() or query.lower() in u["email"].lower()):
                    safe_u = dict(u)
                    safe_u.pop("password_hash", None)
                    safe_u.pop("encrypted_key_vault", None)
                    res.append(safe_u)
            return res

    # ---------------- FILE OPERATIONS ----------------
    def create_file_record(self, file_data):
        if self.is_mongo:
            res = self.db.files.insert_one(file_data)
            file_data["_id"] = str(res.inserted_id)
            return file_data
        else:
            files = self._read_local("files")
            files.append(file_data)
            self._write_local("files", files)
            return file_data

    def get_file_by_uuid(self, share_uuid):
        if self.is_mongo:
            file_doc = self.db.files.find_one({"share_uuid": share_uuid})
            if file_doc:
                file_doc["_id"] = str(file_doc["_id"])
            return file_doc
        else:
            files = self._read_local("files")
            for f in files:
                if f.get("share_uuid") == share_uuid:
                    return f
            return None

    def get_file_by_id(self, file_id):
        if self.is_mongo:
            file_doc = self.db.files.find_one({"file_id": file_id})
            if file_doc:
                file_doc["_id"] = str(file_doc["_id"])
            return file_doc
        else:
            files = self._read_local("files")
            for f in files:
                if f.get("file_id") == file_id:
                    return f
            return None

    def increment_download_count(self, file_id):
        """Atomically increments download_count only if limit not exceeded."""
        if self.is_mongo:
            # Check file first
            file_doc = self.db.files.find_one({"file_id": file_id})
            if not file_doc:
                return False
            max_d = file_doc.get("max_downloads", 0)
            curr_d = file_doc.get("download_count", 0)
            if max_d > 0 and curr_d >= max_d:
                return False
                
            res = self.db.files.update_one(
                {
                    "file_id": file_id,
                    "$or": [
                        {"max_downloads": {"$lte": 0}},
                        {"download_count": {"$lt": max_d}}
                    ]
                },
                {"$inc": {"download_count": 1}}
            )
            return res.modified_count > 0
        else:
            with self._lock:
                files = self._read_local("files")
                for f in files:
                    if f.get("file_id") == file_id:
                        max_d = f.get("max_downloads", 0)
                        curr_d = f.get("download_count", 0)
                        if max_d > 0 and curr_d >= max_d:
                            return False
                        f["download_count"] = curr_d + 1
                        self._write_local("files", files)
                        return True
                return False

    def get_files_for_user(self, user_id):
        if self.is_mongo:
            received = list(self.db.files.find({"recipient_id": user_id}).sort("created_at", -1))
            sent = list(self.db.files.find({"sender_id": user_id}).sort("created_at", -1))
            for f in received + sent:
                f["_id"] = str(f["_id"])
            return {"received": received, "sent": sent}
        else:
            files = self._read_local("files")
            received = [f for f in files if f.get("recipient_id") == user_id]
            sent = [f for f in files if f.get("sender_id") == user_id]
            received.sort(key=lambda x: x.get("created_at", 0), reverse=True)
            sent.sort(key=lambda x: x.get("created_at", 0), reverse=True)
            return {"received": received, "sent": sent}

    def delete_file_record(self, file_id, user_id):
        if self.is_mongo:
            doc = self.db.files.find_one({"file_id": file_id, "sender_id": user_id})
            if doc:
                self.db.files.delete_one({"file_id": file_id})
                return doc
        else:
            files = self._read_local("files")
            found = None
            new_files = []
            for f in files:
                if f.get("file_id") == file_id and f.get("sender_id") == user_id:
                    found = f
                else:
                    new_files.append(f)
            if found:
                self._write_local("files", new_files)
                return found
        return None

    # ---------------- AUDIT LOGS (PRIVACY-PRESERVING & USER-SCOPED) ----------------
    def log_audit(self, event_type, details):
        log_entry = {
            "log_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "event_type": event_type,
            "details": details
        }
        if self.is_mongo:
            self.db.audit_logs.insert_one(log_entry)
        else:
            logs = self._read_local("audit_logs")
            logs.append(log_entry)
            self._write_local("audit_logs", logs[-300:])

    def get_user_audit_logs(self, user_id, user_email, limit=50):
        """Returns ONLY activity logs relevant to the requesting user."""
        if self.is_mongo:
            filt = {
                "$or": [
                    {"details.user_id": user_id},
                    {"details.email": user_email.lower()},
                    {"details.sender": user_email.lower()},
                    {"details.recipient": user_email.lower()}
                ]
            }
            logs = list(self.db.audit_logs.find(filt).sort("timestamp", -1).limit(limit))
            for l in logs:
                l["_id"] = str(l["_id"])
            return logs
        else:
            logs = self._read_local("audit_logs")
            user_logs = []
            u_email_clean = user_email.lower()
            for l in logs:
                d = l.get("details", {})
                if (d.get("user_id") == user_id or 
                    d.get("email", "").lower() == u_email_clean or 
                    d.get("sender", "").lower() == u_email_clean or 
                    d.get("recipient", "").lower() == u_email_clean):
                    user_logs.append(l)
            return sorted(user_logs, key=lambda x: x.get("timestamp", 0), reverse=True)[:limit]

db = Database()
