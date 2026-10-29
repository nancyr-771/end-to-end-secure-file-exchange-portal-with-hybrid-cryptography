/**
 * API Client Layer for communicating with Flask Backend
 */

   const API_BASE = (
       location.hostname === 'localhost' ||
       location.hostname === '127.0.0.1' ||
       location.hostname.endsWith('onrender.com')
   ) ? '' : 'https://secure-file-exchange-backend.onrender.com';

class ApiClient {
    constructor() {
        this.token = localStorage.getItem('portal_jwt_token') || null;
    }

    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('portal_jwt_token', token);
        } else {
            localStorage.removeItem('portal_jwt_token');
        }
    }

    getHeaders(isMultipart = false) {
        const headers = {};
        if (!isMultipart) {
            headers['Content-Type'] = 'application/json';
        }
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        return headers;
    }

    async register(name, email, password, x25519_pk, ed25519_pk, encrypted_key_vault) {
        const res = await fetch(`${API_BASE}/api/auth/register`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({
                name,
                email,
                password,
                x25519_public_key: x25519_pk,
                ed25519_public_key: ed25519_pk,
                encrypted_key_vault: encrypted_key_vault
            })
        });
        return res.json();
    }

    async login(email, password) {
        const res = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ email, password })
        });
        return res.json();
    }

    async getMe() {
        const res = await fetch(`${API_BASE}/api/auth/me`, {
            method: 'GET',
            headers: this.getHeaders()
        });
        return res.json();
    }

    async getDashboardStats() {
        const res = await fetch(`${API_BASE}/api/dashboard/stats`, {
            method: 'GET',
            headers: this.getHeaders()
        });
        return res.json();
    }

    async searchUsers(query = '') {
        const res = await fetch(`${API_BASE}/api/users?q=${encodeURIComponent(query)}`, {
            method: 'GET',
            headers: this.getHeaders()
        });
        return res.json();
    }

    async uploadEncryptedFile(formData) {
        const res = await fetch(`${API_BASE}/api/files/upload`, {
            method: 'POST',
            headers: this.getHeaders(true),
            body: formData
        });
        return res.json();
    }

    async getMyUploads() {
        const res = await fetch(`${API_BASE}/api/files/my-uploads`, {
            method: 'GET',
            headers: this.getHeaders()
        });
        return res.json();
    }

    async getSharedWithMe() {
        const res = await fetch(`${API_BASE}/api/files/shared-with-me`, {
            method: 'GET',
            headers: this.getHeaders()
        });
        return res.json();
    }

    async deleteFile(fileId) {
        const res = await fetch(`${API_BASE}/api/files/${fileId}`, {
            method: 'DELETE',
            headers: this.getHeaders()
        });
        return res.json();
    }

    async getFileInfo(shareUuid) {
        const res = await fetch(`${API_BASE}/api/files/info/${shareUuid}`);
        return res.json();
    }

    async downloadEncryptedBlob(shareUuid) {
        const res = await fetch(`${API_BASE}/api/files/download/${shareUuid}`);
        if (!res.ok) {
            const err = await res.json().catch(() => ({ message: "Download failed" }));
            throw new Error(err.message || "Failed to download encrypted file");
        }
        return res.arrayBuffer();
    }

    async getAuditLogs() {
        const res = await fetch(`${API_BASE}/api/audit/logs`, {
            headers: this.getHeaders()
        });
        return res.json();
    }

    async getSystemStatus() {
        const res = await fetch(`${API_BASE}/api/status`);
        return res.json();
    }
}

window.api = new ApiClient();
