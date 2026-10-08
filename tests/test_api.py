import os
import sys
import io
import unittest
import json
import base64
import time

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app import app
from backend.models import db

class TestFilePortalAPI(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    def test_1_health_status(self):
        """Test system status endpoint."""
        res = self.client.get('/api/status')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("cryptographic_primitives", data)
        print("\n[PASS] API Test 1: System health & crypto status endpoint.")

    def test_2_registration_and_login(self):
        """Test user registration and JWT generation."""
        dummy_pk = base64.b64encode(b"0" * 32).decode('utf-8')
        user_email = f"alice_{int(time.time()*1000)}@example.com"

        reg_payload = {
            "name": "Alice Wonderland",
            "email": user_email,
            "password": "Password123!",
            "x25519_public_key": dummy_pk,
            "ed25519_public_key": dummy_pk
        }

        # 1. Register
        res = self.client.post('/api/auth/register', json=reg_payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("token", data)

        # 2. Login
        login_res = self.client.post('/api/auth/login', json={
            "email": user_email,
            "password": "Password123!"
        })
        self.assertEqual(login_res.status_code, 200)
        login_data = login_res.get_json()
        self.assertTrue(login_data["success"])
        self.assertIn("token", login_data)
        print("[PASS] API Test 2: User Registration & JWT Authentication.")

    def test_3_upload_and_download_limits(self):
        """Test file upload, access limits, and download counts."""
        dummy_pk = base64.b64encode(b"0" * 32).decode('utf-8')
        user_email = f"bob_{int(time.time()*1000)}@example.com"
        reg = self.client.post('/api/auth/register', json={
            "name": "Bob Builder",
            "email": user_email,
            "password": "Password123!",
            "x25519_public_key": dummy_pk,
            "ed25519_public_key": dummy_pk
        }).get_json()
        token = reg["token"]

        # Upload encrypted file with max 1 download
        upload_data = {
            'encrypted_file': (io.BytesIO(b"ENCRYPTED_PAYLOAD_TEST_BYTES"), 'secret.pdf'),
            'filename': 'secret.pdf',
            'recipient_id': 'public',
            'wrapped_file_key': base64.b64encode(b"DUMMY_KEY_32_BYTES_PADDING_1234").decode(),
            'ephemeral_public_key': dummy_pk,
            'signature_ed25519': base64.b64encode(b"SIG").decode(),
            'expiry_hours': '1',
            'max_downloads': '1'
        }

        up_res = self.client.post(
            '/api/files/upload',
            data=upload_data,
            headers={'Authorization': f'Bearer {token}'},
            content_type='multipart/form-data'
        )
        self.assertEqual(up_res.status_code, 201)
        up_data = up_res.get_json()
        share_uuid = up_data["share_uuid"]

        # 1st Download - should succeed
        dl1 = self.client.get(f'/api/files/download/{share_uuid}')
        self.assertEqual(dl1.status_code, 200)

        # 2nd Download - should be rejected because limit is 1
        dl2 = self.client.get(f'/api/files/download/{share_uuid}')
        self.assertEqual(dl2.status_code, 410)
        print("[PASS] API Test 3: Upload, Share UUID, & Download Limit Enforcement.")

if __name__ == '__main__':
    unittest.main(verbosity=2)
