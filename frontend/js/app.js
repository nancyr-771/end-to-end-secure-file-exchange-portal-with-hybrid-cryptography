/**
 * SecureFileExchange Application Controller (7-Page Architecture)
 */

const AppState = {
    currentUser: null,
    unlockedKeys: null,
    selectedFile: null,
    activeTab: 'dashboard',
    usersList: [],
    myUploads: [],
    receivedFiles: [],
    selectedFileForModal: null
};

document.addEventListener('DOMContentLoaded', async () => {
    initTabs();
    initUploadDropzone();
    setupEventListeners();
    await checkAuthSession();
});

// ----------------- TOAST NOTIFICATIONS -----------------
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error') icon = '❌';
    if (type === 'warning') icon = '⚠️';

    toast.innerHTML = `<span>${icon}</span><span style="flex:1;">${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ----------------- TAB NAVIGATION -----------------
function initTabs() {
    const tabButtons = document.querySelectorAll('[data-tab]');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            switchTab(targetTab);
        });
    });
}

function switchTab(tabId) {
    AppState.activeTab = tabId;
    
    document.querySelectorAll('[data-tab]').forEach(b => {
        if (b.getAttribute('data-tab') === tabId) {
            b.classList.add('active');
        } else {
            b.classList.remove('active');
        }
    });

    document.querySelectorAll('.view-section').forEach(sec => {
        if (sec.id === `view-${tabId}`) {
            sec.style.display = 'block';
        } else {
            sec.style.display = 'none';
        }
    });

    if (AppState.currentUser) {
        if (tabId === 'dashboard') loadDashboard();
        if (tabId === 'my-files') loadMyFiles();
        if (tabId === 'shared-files') loadSharedFiles();
        if (tabId === 'received-files') loadReceivedFiles();
        if (tabId === 'activity') loadActivityLogs();
        if (tabId === 'upload') loadRecipientsDropdown();
    }
}

// ----------------- AUTHENTICATION -----------------
async function checkAuthSession() {
    const token = localStorage.getItem('portal_jwt_token');
    
    if (token) {
        try {
            const res = await window.api.getMe();
            if (res.success && res.user) {
                AppState.currentUser = res.user;
                
                const sessionVault = sessionStorage.getItem('portal_session_keys');
                if (sessionVault) {
                    try {
                        AppState.unlockedKeys = JSON.parse(sessionVault);
                    } catch (e) {}
                }
                
                renderAuthenticatedUI();
                return;
            }
        } catch (e) {
            console.warn("Session error:", e);
        }
    }
    renderUnauthenticatedUI();
}

function renderAuthenticatedUI() {
    document.getElementById('auth-overlay-view').style.display = 'none';
    document.getElementById('main-app-view').style.display = 'block';
    document.getElementById('nav-main-links').style.display = 'flex';
    document.getElementById('user-profile-badge').style.display = 'flex';
    document.getElementById('user-display-name').textContent = AppState.currentUser.name;
    document.getElementById('user-display-email').textContent = AppState.currentUser.email;

    // Populate settings profile
    const sName = document.getElementById('settings-name');
    const sEmail = document.getElementById('settings-email');
    if (sName) sName.value = AppState.currentUser.name;
    if (sEmail) sEmail.value = AppState.currentUser.email;

    // Greeting
    const hour = new Date().getHours();
    let greeting = "Good morning";
    if (hour >= 12 && hour < 17) greeting = "Good afternoon";
    else if (hour >= 17) greeting = "Good evening";
    document.getElementById('dashboard-greeting').textContent = `${greeting}, ${AppState.currentUser.name}`;

    switchTab('dashboard');
    refreshFileCounters();
}

function renderUnauthenticatedUI() {
    document.getElementById('auth-overlay-view').style.display = 'block';
    document.getElementById('main-app-view').style.display = 'none';
    document.getElementById('nav-main-links').style.display = 'none';
    document.getElementById('user-profile-badge').style.display = 'none';
}

function logout() {
    window.api.setToken(null);
    AppState.currentUser = null;
    AppState.unlockedKeys = null;
    localStorage.removeItem('portal_jwt_token');
    sessionStorage.removeItem('portal_session_keys');
    renderUnauthenticatedUI();
    showToast("Logged out securely.", "info");
}

// ----------------- REGISTRATION & LOGIN -----------------
async function handleRegister(e) {
    if (e) e.preventDefault();
    const name = document.getElementById('reg-name').value.trim();
    const email = document.getElementById('reg-email').value.trim().toLowerCase();
    const password = document.getElementById('reg-password').value;
    const confirmPassword = document.getElementById('reg-confirm-password').value;

    if (!name || !email || !password) {
        showToast("Please fill in all registration fields.", "warning");
        return;
    }

    if (password !== confirmPassword) {
        showToast("Passwords do not match.", "warning");
        return;
    }

    const regBtn = document.getElementById('reg-submit-btn');
    regBtn.disabled = true;
    regBtn.textContent = "⏳ Generating Identity Keys...";

    try {
        const keyBundle = await window.cryptoEngine.generateUserKeypairs();
        const vault = await window.cryptoEngine.protectPrivateKeys(keyBundle, password);

        const res = await window.api.register(
            name,
            email,
            password,
            keyBundle.x25519_public_key,
            keyBundle.ed25519_public_key,
            vault
        );

        if (res.success) {
            window.api.setToken(res.token);
            AppState.currentUser = res.user;
            AppState.unlockedKeys = {
                ecdh_priv: keyBundle._ecdh_priv,
                ecdsa_priv: keyBundle._ecdsa_priv
            };
            sessionStorage.setItem('portal_session_keys', JSON.stringify(AppState.unlockedKeys));
            
            showToast("Account created successfully!", "success");
            renderAuthenticatedUI();
        } else {
            showToast(res.message || "Registration failed.", "error");
        }
    } catch (err) {
        showToast("Error: " + err.message, "error");
    } finally {
        regBtn.disabled = false;
        regBtn.textContent = "Create Account & Generate Keys";
    }
}

async function handleLogin(e) {
    if (e) e.preventDefault();
    const email = document.getElementById('login-email').value.trim().toLowerCase();
    const password = document.getElementById('login-password').value;

    if (!email || !password) {
        showToast("Please enter email and password.", "warning");
        return;
    }

    const loginBtn = document.getElementById('login-submit-btn');
    loginBtn.disabled = true;
    loginBtn.textContent = "⏳ Authenticating...";

    try {
        const res = await window.api.login(email, password);
        if (res.success) {
            window.api.setToken(res.token);
            AppState.currentUser = res.user;

            if (res.user.encrypted_key_vault) {
                try {
                    AppState.unlockedKeys = await window.cryptoEngine.unlockPrivateKeys(res.user.encrypted_key_vault, password);
                    sessionStorage.setItem('portal_session_keys', JSON.stringify(AppState.unlockedKeys));
                } catch (e) {}
            }

            showToast(`Welcome back, ${res.user.name}!`, "success");
            renderAuthenticatedUI();
        } else {
            showToast(res.message || "Login failed.", "error");
        }
    } catch (err) {
        showToast("Login error: " + err.message, "error");
    } finally {
        loginBtn.disabled = false;
        loginBtn.textContent = "Login to Portal";
    }
}

// ----------------- 1. DASHBOARD -----------------
async function loadDashboard() {
    try {
        const res = await window.api.getDashboardStats();
        if (res.success) {
            const stats = res.stats || {};
            document.getElementById('dash-my-files-count').textContent = stats.my_files_count || 0;
            document.getElementById('dash-shared-count').textContent = stats.shared_count || 0;
            document.getElementById('dash-received-count').textContent = stats.received_count || 0;
            document.getElementById('dash-expiring-count').textContent = stats.expiring_count || 0;

            const recentContainer = document.getElementById('dashboard-recent-files-list');
            if (res.recent_files && res.recent_files.length > 0) {
                recentContainer.innerHTML = '';
                res.recent_files.forEach(f => {
                    const isSender = f.sender_id === AppState.currentUser.user_id;
                    const desc = isSender ? `Shared with ${escapeHtml(f.recipient_email)}` : `Received from ${escapeHtml(f.sender_name)}`;
                    const timeAgo = formatTimeAgo(f.created_at);

                    const div = document.createElement('div');
                    div.style.cssText = "display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid rgba(255,255,255,0.05);";
                    div.innerHTML = `
                        <div style="display: flex; align-items: center; gap: 0.75rem;">
                            <span style="font-size: 1.5rem;">📄</span>
                            <div>
                                <div style="font-weight: 600; color: var(--text-main); font-size: 0.9rem;">${escapeHtml(f.filename)}</div>
                                <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.15rem;">Encrypted • ${desc}</div>
                            </div>
                        </div>
                        <span style="font-size: 0.78rem; color: var(--text-dim);">${timeAgo}</span>
                    `;
                    recentContainer.appendChild(div);
                });
            } else {
                recentContainer.innerHTML = '<p style="color: var(--text-muted); padding: 1rem 0;">No files uploaded or received yet.</p>';
            }
        }
    } catch (e) {
        console.error("Dashboard error:", e);
    }
}

// ----------------- 2. UPLOAD FILE -----------------
function initUploadDropzone() {
    const dropzone = document.getElementById('upload-dropzone');
    const fileInput = document.getElementById('file-input');

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) handleFileSelection(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleFileSelection(e.target.files[0]);
    });

    const passCheck = document.getElementById('enable-passphrase-check');
    if (passCheck) {
        passCheck.addEventListener('change', (e) => {
            document.getElementById('custom-passphrase-box').style.display = e.target.checked ? 'block' : 'none';
        });
    }
}

async function handleFileSelection(file) {
    AppState.selectedFile = file;
    document.getElementById('selected-file-name').textContent = file.name;
    document.getElementById('selected-file-size').textContent = `${formatBytes(file.size)} • ${file.type || 'Binary'}`;

    let icon = '📄';
    if (file.type.startsWith('image/')) icon = '🖼️';
    else if (file.type.includes('pdf')) icon = '📕';
    else if (file.type.includes('zip') || file.type.includes('tar')) icon = '📦';
    document.getElementById('selected-file-icon').textContent = icon;

    document.getElementById('file-preview-card').style.display = 'flex';
    document.getElementById('upload-dropzone').style.display = 'none';
    showToast(`Selected "${file.name}"`, "info");
}

function clearSelectedFile() {
    AppState.selectedFile = null;
    document.getElementById('file-input').value = '';
    document.getElementById('file-preview-card').style.display = 'none';
    document.getElementById('upload-dropzone').style.display = 'block';
}

async function loadRecipientsDropdown() {
    const select = document.getElementById('recipient-select');
    if (!select) return;
    select.innerHTML = '<option value="public">🌐 Public Secure Link (UUID)</option>';
    
    try {
        const res = await window.api.searchUsers();
        if (res.success && res.users) {
            AppState.usersList = res.users;
            res.users.forEach(u => {
                const opt = document.createElement('option');
                opt.value = u.user_id;
                opt.textContent = `👤 ${u.name} (${u.email})`;
                select.appendChild(opt);
            });
        }
    } catch (e) {}
}

async function executeE2EEUpload() {
    if (!AppState.selectedFile) {
        showToast("Please select a file to upload.", "warning");
        return;
    }

    const recipientId = document.getElementById('recipient-select').value;
    const expiryHours = document.getElementById('expiry-select').value;
    const maxDownloads = document.getElementById('max-downloads-input').value;
    const isPassEnabled = document.getElementById('enable-passphrase-check')?.checked || false;
    const customPassphrase = isPassEnabled ? document.getElementById('custom-passphrase-input')?.value.trim() : null;

    const uploadBtn = document.getElementById('start-upload-btn');
    uploadBtn.disabled = true;
    resetStepper();
    document.getElementById('upload-stepper-panel').style.display = 'block';

    try {
        updateStep(1, 'active', 'Reading file bytes...');
        const fileBuffer = await AppState.selectedFile.arrayBuffer();
        updateStep(1, 'completed', `File loaded (${formatBytes(AppState.selectedFile.size)})`);

        updateStep(2, 'active', 'Generating 256-bit key & X25519 agreement...');
        let recipientEcdhPub = null;
        if (recipientId !== 'public') {
            const recipientUser = AppState.usersList.find(u => u.user_id === recipientId);
            if (!recipientUser) throw new Error("Recipient public key not found.");
            recipientEcdhPub = recipientUser.x25519_public_key;
        }
        updateStep(2, 'completed', 'File key & key agreement ready');

        updateStep(3, 'active', 'Encrypting payload & generating Ed25519 signature...');
        const senderSignPriv = AppState.unlockedKeys ? AppState.unlockedKeys.ecdsa_priv : null;
        const cryptoResult = await window.cryptoEngine.encryptFileE2EE(
            fileBuffer,
            recipientEcdhPub,
            senderSignPriv,
            customPassphrase
        );
        updateStep(3, 'completed', 'XChaCha20-Poly1305 encryption complete');

        updateStep(4, 'active', 'Uploading ciphertext & creating share link...');
        const formData = new FormData();
        const encryptedBlob = new Blob([cryptoResult.encryptedBlob], { type: 'application/octet-stream' });
        formData.append('encrypted_file', encryptedBlob, AppState.selectedFile.name);
        formData.append('filename', AppState.selectedFile.name);
        formData.append('recipient_id', recipientId);
        formData.append('wrapped_file_key', cryptoResult.wrappedFileKey);
        formData.append('ephemeral_public_key', cryptoResult.ephemeralPublicKey);
        formData.append('signature_ed25519', cryptoResult.signatureEd25519);
        formData.append('expiry_hours', expiryHours);
        formData.append('max_downloads', maxDownloads);
        formData.append('is_passphrase_protected', isPassEnabled ? "true" : "false");

        const uploadRes = await window.api.uploadEncryptedFile(formData);

        if (uploadRes.success) {
            updateStep(4, 'completed', 'Upload complete! Share link ready.');
            
            let finalLink = `${window.location.origin}/download/${uploadRes.share_uuid}`;
            if (recipientId === 'public' && !isPassEnabled) {
                finalLink += `#key=${encodeURIComponent(cryptoResult.rawFileKeyB64)}`;
            }

            displayShareResultModal(finalLink, uploadRes.expires_at, uploadRes.max_downloads, isPassEnabled);
            showToast("File encrypted & uploaded successfully!", "success");
            clearSelectedFile();
            refreshFileCounters();
        } else {
            throw new Error(uploadRes.message || "Upload failed.");
        }
    } catch (err) {
        showToast("Upload Error: " + err.message, "error");
    } finally {
        uploadBtn.disabled = false;
    }
}

function resetStepper() {
    for (let i = 1; i <= 4; i++) {
        const el = document.getElementById(`step-${i}`);
        if (el) el.className = 'step-item';
    }
}

function updateStep(stepNum, status, text) {
    const el = document.getElementById(`step-${stepNum}`);
    if (!el) return;
    el.className = `step-item ${status}`;
    const desc = el.querySelector('.step-desc');
    if (desc && text) desc.textContent = text;
}

// ----------------- 3. MY FILES -----------------
async function loadMyFiles() {
    const tbody = document.getElementById('my-files-tbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">Loading your files...</td></tr>';

    try {
        const res = await window.api.getMyUploads();
        if (res.success && res.uploads) {
            AppState.myUploads = res.uploads;
            renderMyFilesTable(res.uploads);
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--accent-rose);">Error: ${e.message}</td></tr>`;
    }
}

function renderMyFilesTable(files) {
    const tbody = document.getElementById('my-files-tbody');
    if (!files || files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 3rem;">No files uploaded yet.</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    files.forEach(f => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escapeHtml(f.filename)}</strong></td>
            <td>${formatBytes(f.file_size)}</td>
            <td><span class="badge badge-success">Encrypted</span></td>
            <td>${new Date(f.created_at * 1000).toLocaleDateString()}</td>
            <td>
                <button onclick="openFileDetailsModal('${f.file_id}')" class="btn btn-secondary" style="padding: 0.3rem 0.65rem; font-size: 0.8rem;">⋮ Details</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ----------------- 4. SHARED FILES -----------------
async function loadSharedFiles() {
    const tbody = document.getElementById('shared-files-tbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">Loading shared files...</td></tr>';

    try {
        const res = await window.api.getMyUploads();
        if (res.success && res.uploads) {
            if (res.uploads.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 3rem;">No shared files found.</td></tr>';
                return;
            }
            tbody.innerHTML = '';
            res.uploads.forEach(f => {
                const tr = document.createElement('tr');
                const isExpired = f.expires_at > 0 && Date.now() / 1000 > f.expires_at;
                const isExhausted = f.max_downloads > 0 && f.download_count >= f.max_downloads;
                
                let expiryText = f.expires_at > 0 ? formatTimeRemaining(f.expires_at) : 'Never';
                if (isExpired) expiryText = '<span style="color: var(--accent-rose);">Expired</span>';

                tr.innerHTML = `
                    <td><strong>${escapeHtml(f.filename)}</strong></td>
                    <td>${escapeHtml(f.recipient_email)}</td>
                    <td>${expiryText}</td>
                    <td><span class="badge badge-info">${f.download_count} / ${f.max_downloads || '∞'}</span></td>
                    <td>
                        <button onclick="copyDirectLink('${f.share_uuid}')" class="btn btn-primary" style="padding: 0.35rem 0.7rem; font-size: 0.8rem;">Copy Secure Link</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--accent-rose);">Error: ${e.message}</td></tr>`;
    }
}

// ----------------- 5. RECEIVED FILES -----------------
async function loadReceivedFiles() {
    const tbody = document.getElementById('received-files-tbody');
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">Loading received files...</td></tr>';

    try {
        const res = await window.api.getSharedWithMe();
        if (res.success && res.received) {
            AppState.receivedFiles = res.received;
            if (res.received.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 3rem;">No files received yet.</td></tr>';
                return;
            }
            tbody.innerHTML = '';
            res.received.forEach(f => {
                const tr = document.createElement('tr');
                const isExpired = f.expires_at > 0 && Date.now() / 1000 > f.expires_at;
                const isExhausted = f.max_downloads > 0 && f.download_count >= f.max_downloads;
                
                let statusBadge = '<span class="badge badge-success">Active</span>';
                if (isExpired) statusBadge = '<span class="badge badge-danger">Expired</span>';
                else if (isExhausted) statusBadge = '<span class="badge badge-warning">Limit Reached</span>';

                tr.innerHTML = `
                    <td><strong>${escapeHtml(f.filename)}</strong></td>
                    <td>${formatBytes(f.file_size)}</td>
                    <td>${escapeHtml(f.sender_name)} <span style="color:var(--text-dim); font-size:0.75rem;">(${escapeHtml(f.sender_email)})</span></td>
                    <td><span class="badge badge-info">${f.download_count} / ${f.max_downloads || '∞'}</span></td>
                    <td>${statusBadge}</td>
                    <td>
                        <a href="/download/${f.share_uuid}" target="_blank" class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.8rem;">🔓 Decrypt</a>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--accent-rose);">Error: ${e.message}</td></tr>`;
    }
}

// ----------------- 6. ACTIVITY LOGS -----------------
async function loadActivityLogs() {
    const container = document.getElementById('audit-logs-container');
    container.innerHTML = '<p style="color:var(--text-muted);">Loading security activity...</p>';
    try {
        const res = await window.api.getAuditLogs();
        if (res.success && res.logs && res.logs.length > 0) {
            container.innerHTML = '';
            res.logs.forEach(l => {
                const card = document.createElement('div');
                card.className = 'timeline-card';
                
                let icon = '✓';
                let iconColor = 'var(--accent-emerald)';
                let title = l.event_type;
                let desc = '';
                const d = l.details || {};

                if (l.event_type === 'USER_REGISTERED') {
                    title = 'Account registered';
                    desc = `Identity generated for ${d.name || d.email}`;
                } else if (l.event_type === 'LOGIN_SUCCESS') {
                    title = 'Successful login';
                    desc = `Authenticated from browser session`;
                } else if (l.event_type === 'LOGIN_FAILED') {
                    icon = '⚠';
                    iconColor = 'var(--accent-rose)';
                    title = 'Failed login attempt';
                    desc = `Invalid password attempt`;
                } else if (l.event_type === 'FILE_UPLOADED') {
                    title = 'File uploaded';
                    desc = `${d.filename || 'File'} • Shared with ${d.recipient}`;
                } else if (l.event_type === 'FILE_DOWNLOADED') {
                    title = 'File downloaded';
                    desc = `${d.filename || 'File'} • Download #${d.download_number || 1}`;
                } else if (l.event_type === 'EXPIRED_ACCESS_ATTEMPT') {
                    icon = '⚠';
                    iconColor = 'var(--accent-amber)';
                    title = 'Expired link access attempted';
                    desc = `${d.filename || 'File'}`;
                } else if (l.event_type === 'FILE_DELETED') {
                    title = 'File deleted';
                    desc = `${d.filename || 'File'} removed from storage`;
                }

                card.innerHTML = `
                    <div class="timeline-icon" style="color: ${iconColor}; font-weight: bold;">${icon}</div>
                    <div style="flex:1;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong style="color:var(--text-main); font-size:0.95rem;">${escapeHtml(title)}</strong>
                            <span style="color:var(--text-dim); font-size:0.75rem;">${new Date(l.timestamp * 1000).toLocaleTimeString()}</span>
                        </div>
                        <p style="color:var(--text-muted); font-size:0.83rem; margin-top:0.25rem;">${escapeHtml(desc)}</p>
                    </div>
                `;
                container.appendChild(card);
            });
        } else {
            container.innerHTML = '<p style="color:var(--text-muted); padding:2rem; text-align:center;">No activity recorded yet.</p>';
        }
    } catch (e) {
        container.innerHTML = `<p style="color:var(--accent-rose);">Error: ${e.message}</p>`;
    }
}

// ----------------- FILE DETAILS MODAL -----------------
function openFileDetailsModal(fileId) {
    const file = AppState.myUploads.find(f => f.file_id === fileId);
    if (!file) return;

    AppState.selectedFileForModal = file;
    document.getElementById('modal-file-name').textContent = file.filename;
    document.getElementById('modal-file-size').textContent = formatBytes(file.file_size);
    document.getElementById('modal-file-created').textContent = new Date(file.created_at * 1000).toLocaleString();
    document.getElementById('modal-file-expires').textContent = file.expires_at > 0 ? new Date(file.expires_at * 1000).toLocaleString() : 'Never';
    document.getElementById('modal-file-downloads').textContent = `${file.download_count} / ${file.max_downloads || '∞'}`;

    document.getElementById('modal-copy-link-btn').onclick = () => copyDirectLink(file.share_uuid);
    document.getElementById('modal-delete-btn').onclick = () => handleDeleteFile(file.file_id);

    document.getElementById('file-details-modal').style.display = 'flex';
}

function closeFileDetailsModal() {
    document.getElementById('file-details-modal').style.display = 'none';
}

async function handleDeleteFile(fileId) {
    if (!confirm("Are you sure you want to permanently delete this file?")) return;
    try {
        const res = await window.api.deleteFile(fileId);
        if (res.success) {
            showToast("File deleted permanently.", "info");
            closeFileDetailsModal();
            loadMyFiles();
            refreshFileCounters();
        } else {
            showToast(res.message, "error");
        }
    } catch (e) {
        showToast("Delete failed: " + e.message, "error");
    }
}

// ----------------- SHARE RESULT MODAL -----------------
function displayShareResultModal(url, expiresAt, maxDownloads, isPassphraseProtected = false) {
    const modal = document.getElementById('share-result-modal');
    document.getElementById('share-link-input').value = url;
    document.getElementById('share-meta-expiry').textContent = expiresAt > 0 ? new Date(expiresAt * 1000).toLocaleString() : 'Never';
    document.getElementById('share-meta-limits').textContent = maxDownloads > 0 ? `${maxDownloads} downloads` : 'Unlimited';
    
    const passNotice = document.getElementById('share-meta-pass-notice');
    if (passNotice) passNotice.style.display = isPassphraseProtected ? 'block' : 'none';

    document.getElementById('open-share-link-btn').onclick = () => window.open(url, '_blank');
    modal.style.display = 'flex';
}

function copyShareLink() {
    const input = document.getElementById('share-link-input');
    input.select();
    navigator.clipboard.writeText(input.value);
    showToast("Link copied to clipboard!", "success");
}

function copyDirectLink(uuid) {
    const link = `${window.location.origin}/download/${uuid}`;
    navigator.clipboard.writeText(link);
    showToast("Secure link copied!", "success");
}

async function refreshFileCounters() {
    try {
        const res = await window.api.getDashboardStats();
        if (res.success && res.stats) {
            const badge = document.getElementById('nav-received-count');
            if (badge) badge.textContent = res.stats.received_count || 0;
        }
    } catch (e) {}
}

// ----------------- EVENT LISTENERS -----------------
function setupEventListeners() {
    document.getElementById('form-register').addEventListener('submit', handleRegister);
    document.getElementById('form-login').addEventListener('submit', handleLogin);
    document.getElementById('logout-btn').addEventListener('click', logout);
    document.getElementById('start-upload-btn').addEventListener('click', executeE2EEUpload);
    document.getElementById('remove-file-btn').addEventListener('click', clearSelectedFile);
    document.getElementById('copy-link-btn').addEventListener('click', copyShareLink);
    document.getElementById('close-share-modal-btn').addEventListener('click', () => {
        document.getElementById('share-result-modal').style.display = 'none';
    });

    document.getElementById('show-reg-btn').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('login-card').style.display = 'none';
        document.getElementById('register-card').style.display = 'block';
    });
    document.getElementById('show-login-btn').addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('register-card').style.display = 'none';
        document.getElementById('login-card').style.display = 'block';
    });

    document.getElementById('modal-close-btn').addEventListener('click', closeFileDetailsModal);

    // Search filter on My Files
    const searchInput = document.getElementById('my-files-search');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const filtered = AppState.myUploads.filter(f => f.filename.toLowerCase().includes(query));
            renderMyFilesTable(filtered);
        });
    }
}

// ----------------- UTILITIES -----------------
function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function formatTimeRemaining(expiresAt) {
    const diff = expiresAt - (Date.now() / 1000);
    if (diff <= 0) return 'Expired';
    const hours = Math.floor(diff / 3600);
    if (hours < 24) return `${hours} hours`;
    const days = Math.floor(hours / 24);
    return `${days} days`;
}

function formatTimeAgo(timestamp) {
    const diff = (Date.now() / 1000) - timestamp;
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
    return `${Math.floor(diff / 86400)} days ago`;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
