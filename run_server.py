import os
import sys
import webbrowser
import threading
import time

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app import app
from backend.models import db

def open_browser():
    time.sleep(1.2)
    url = "http://127.0.0.1:5000"
    print(f"\n🚀 Opening browser at {url}...")
    webbrowser.open(url)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  🔒 END-TO-END SECURE FILE EXCHANGE PORTAL")
    print("  🔑 Hybrid Cryptography (XChaCha20-Poly1305 + X25519 + Ed25519)")
    print("="*60)
    print(f"  📁 Base Path : {BASE_DIR}")
    print(f"  🗄️ Database  : {'MongoDB' if db.is_mongo else 'Persistent Local Storage'}")
    print(f"  🌐 URL       : http://127.0.0.1:5000")
    print("="*60 + "\n")

    # Start browser opener in background thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Flask Server
    app.run(host='0.0.0.0', port=5000, debug=False)
