// static/app.js

// Charger les IDs sauvegardés au démarrage
window.onload = function() {
    const savedUserId = localStorage.getItem('userId');
    const savedBucketId = localStorage.getItem('bucketId');
    
    if (savedUserId) document.getElementById('userId').value = savedUserId;
    if (savedBucketId) document.getElementById('bucketId').value = savedBucketId;
};

function saveUserId() {
    const userId = document.getElementById('userId').value;
    localStorage.setItem('userId', userId);
    showStatus('User ID saved!');
}

function getConfig() {
    return {
        userId: document.getElementById('userId').value,
        bucketId: document.getElementById('bucketId').value
    };
}

async function apiCall(action, data = {}) {
    const config = getConfig();
    
    if (!config.userId) {
        showError('Please enter a User ID');
        return;
    }
    
    const payload = {
        user_id: config.userId,
        bucket_id: config.bucketId || undefined,
        action: action,
        ...data
    };
    
    try {
        const response = await fetch('/api/proxy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        showError(`Error: ${error.message}`);
        throw error;
    }
}

async function listBuckets() {
    try {
        const data = await apiCall('list_buckets');
        displayBuckets(data.buckets || []);
        showStatus('Buckets loaded');
    } catch (e) {
        console.error(e);
    }
}

async function listObjects() {
    const config = getConfig();
    if (!config.bucketId) {
        showError('Please enter a Bucket ID');
        return;
    }
    
    try {
        const data = await apiCall('list_objects');
        displayObjects(data.contents || []);
        showStatus('Objects loaded');
    } catch (e) {
        console.error(e);
    }
}

async function listUsers() {
    try {
        const data = await apiCall('list_users');
        displayUsers(data);
        showStatus('Users loaded (Admin only)');
    } catch (e) {
        console.error(e);
    }
}

function showGetObject() {
    document.getElementById('objectActions').style.display = 'block';
    document.getElementById('actionButton').textContent = 'Download';
    document.getElementById('actionButton').onclick = getObject;
}

function showDeleteObject() {
    document.getElementById('objectActions').style.display = 'block';
    document.getElementById('actionButton').textContent = 'Delete';
    document.getElementById('actionButton').onclick = deleteObject;
}

async function getObject() {
    const key = document.getElementById('objectKey').value;
    if (!key) {
        showError('Please enter an object key');
        return;
    }
    
    try {
        const data = await apiCall('get_object', { key });
        displayRaw(`Object: ${key}\n\n${JSON.stringify(data, null, 2)}`);
        showStatus(`Object retrieved: ${key}`);
    } catch (e) {
        console.error(e);
    }
}

async function deleteObject() {
    const key = document.getElementById('objectKey').value;
    if (!key) {
        showError('Please enter an object key');
        return;
    }
    
    if (!confirm(`Delete object: ${key}?`)) return;
    
    try {
        await apiCall('delete_object', { key });
        showStatus(`Deleted: ${key}`);
        document.getElementById('objectKey').value = '';
    } catch (e) {
        console.error(e);
    }
}

// Display functions
function displayBuckets(buckets) {
    const results = document.getElementById('results');
    if (buckets.length === 0) {
        results.innerHTML = '<p class="placeholder">No buckets found</p>';
        return;
    }
    
    results.innerHTML = buckets.map(bucket => `
        <div class="bucket-item ${bucket.is_online ? 'online' : 'offline'}">
            <strong>📦 ${bucket.name}</strong>
            <span class="status-badge ${bucket.is_online ? 'status-online' : 'status-offline'}">
                ${bucket.is_online ? 'ONLINE' : 'OFFLINE'}
            </span>
            <br>
            <small>Created: ${new Date(bucket.creation_date).toLocaleString()}</small>
            ${bucket.last_seen ? `<br><small>Last seen: ${new Date(bucket.last_seen).toLocaleString()}</small>` : ''}
        </div>
    `).join('');
}

function displayObjects(objects) {
    const results = document.getElementById('results');
    if (objects.length === 0) {
        results.innerHTML = '<p class="placeholder">No objects found</p>';
        return;
    }
    
    results.innerHTML = objects.map(obj => `
        <div class="object-item">
            <strong>📄 ${obj.key}</strong><br>
            <small>Size: ${formatBytes(obj.size)} | ETag: ${obj.etag}</small><br>
            <small>Modified: ${new Date(obj.last_modified).toLocaleString()}</small>
        </div>
    `).join('');
}

function displayUsers(users) {
    const results = document.getElementById('results');
    if (!users || users.length === 0) {
        results.innerHTML = '<p class="placeholder">No users found</p>';
        return;
    }
    
    results.innerHTML = users.map(user => `
        <div class="user-item">
            <strong>👤 ${user.name}</strong>
            ${user.is_admin ? '<span class="status-badge status-online">ADMIN</span>' : ''}
            <br>
            <small>ID: ${user.user_id}</small><br>
            <small>Permissions: ${user.permissions_count || 0} buckets</small>
        </div>
    `).join('');
}

function displayRaw(text) {
    document.getElementById('results').innerHTML = `<pre>${escapeHtml(text)}</pre>`;
}

function showStatus(message) {
    document.getElementById('resultStatus').textContent = `✅ ${message}`;
}

function showError(message) {
    const results = document.getElementById('results');
    results.innerHTML = `<div class="error">❌ ${message}</div>`;
    document.getElementById('resultStatus').textContent = '';
}

function clearResults() {
    document.getElementById('results').innerHTML = '<p class="placeholder">Results will appear here...</p>';
    document.getElementById('resultStatus').textContent = '';
    document.getElementById('objectActions').style.display = 'none';
}

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
// Ajouter ces fonctions à app.js

// === FONCTIONS POUR LA GESTION DES EXTENSIONS BANNIES ===

async function listBannedExtensions() {
    try {
        const data = await apiCall('list_banned_extensions');
        displayBannedExtensions(data.extensions || []);
        showStatus(`Loaded ${data.extensions ? data.extensions.length : 0} banned extensions`);
    } catch (e) {
        console.error(e);
    }
}

function showAddExtension() {
    hideAllSections();
    document.getElementById('addExtensionSection').style.display = 'block';
    document.getElementById('newExtension').value = '';
    document.getElementById('newExtension').focus();
}

function showRemoveExtension() {
    hideAllSections();
    document.getElementById('removeExtensionSection').style.display = 'block';
    document.getElementById('extensionToRemove').value = '';
    document.getElementById('extensionToRemove').focus();
    // Optionnel: charger et afficher la liste actuelle
    listBannedExtensions();
}

async function addBannedExtension() {
    const extension = document.getElementById('newExtension').value.trim();
    if (!extension) {
        showError('Please enter an extension');
        return;
    }
    
    try {
        const result = await apiCall('add_banned_extension', { extension });
        
        if (result.status === 'added') {
            showStatus(`Extension ${result.extension} has been banned`);
            document.getElementById('newExtension').value = '';
            // Recharger la liste
            await listBannedExtensions();
        } else if (result.status === 'already_exists') {
            showError(`Extension ${result.extension} is already banned`);
        }
    } catch (e) {
        console.error(e);
        showError('Failed to ban extension');
    }
}

async function removeBannedExtension() {
    const extension = document.getElementById('extensionToRemove').value.trim();
    if (!extension) {
        showError('Please enter an extension');
        return;
    }
    
    if (!confirm(`Remove ${extension} from banned extensions?`)) {
        return;
    }
    
    try {
        await apiCall('remove_banned_extension', { extension });
        showStatus(`Extension ${extension} has been unbanned`);
        document.getElementById('extensionToRemove').value = '';
        // Recharger la liste
        await listBannedExtensions();
    } catch (e) {
        console.error(e);
        showError('Failed to unban extension');
    }
}

function displayBannedExtensions(extensions) {
    const results = document.getElementById('results');
    
    if (!extensions || extensions.length === 0) {
        results.innerHTML = `
            <div class="policy-stats">
                <h4>No Banned Extensions</h4>
                <p>All file types are currently allowed</p>
            </div>
        `;
        return;
    }
    
    // Trier les extensions pour un meilleur affichage
    extensions.sort();
    
    // Créer une vue détaillée
    results.innerHTML = `
        <div class="policy-stats">
            <h4>Security Policy</h4>
            <div class="count">${extensions.length} Banned Extensions</div>
        </div>
        <div class="extension-list">
            ${extensions.map(ext => `
                <div class="extension-pill" title="Click to remove" onclick="quickRemoveExtension('${ext}')">
                    ${ext}
                </div>
            `).join('')}
        </div>
        <div class="info-box" style="margin-top: 20px;">
            <p><strong>Policy Notes:</strong></p>
            <p>• Extensions are checked anywhere in filename (blocks double extensions)</p>
            <p>• Changes are immediately applied to all connected agents</p>
            <p>• Agents will refresh their file manifests when policy changes</p>
        </div>
    `;
}

// Fonction pour retirer rapidement une extension en cliquant dessus
async function quickRemoveExtension(extension) {
    if (!confirm(`Remove ${extension} from banned extensions?`)) {
        return;
    }
    
    try {
        await apiCall('remove_banned_extension', { extension });
        showStatus(`Extension ${extension} has been unbanned`);
        await listBannedExtensions();
    } catch (e) {
        console.error(e);
        showError('Failed to unban extension');
    }
}

// Fonction helper pour cacher toutes les sections
function hideAllSections() {
    document.getElementById('objectActions').style.display = 'none';
    document.getElementById('permissionsSection').style.display = 'none';
    document.getElementById('setPermissionsSection').style.display = 'none';
    document.getElementById('addExtensionSection').style.display = 'none';
    document.getElementById('removeExtensionSection').style.display = 'none';
}

// Modifier clearResults pour utiliser hideAllSections
function clearResults() {
    document.getElementById('results').innerHTML = '<p class="placeholder">Results will appear here...</p>';
    document.getElementById('resultStatus').textContent = '';
    hideAllSections();
}

// Optionnel: Raccourcis clavier
document.addEventListener('keydown', function(event) {
    // Échap pour fermer les sections
    if (event.key === 'Escape') {
        hideAllSections();
    }
    
    // Enter pour valider dans les champs d'extension
    if (event.key === 'Enter') {
        if (document.getElementById('addExtensionSection').style.display !== 'none') {
            addBannedExtension();
        } else if (document.getElementById('removeExtensionSection').style.display !== 'none') {
            removeBannedExtension();
        }
    }
});
// === FONCTIONS POUR LA GESTION DES UTILISATEURS ===

// Afficher les sections
function showCreateUser() {
    hideAllSections();
    document.getElementById('createUserSection').style.display = 'block';
    document.getElementById('newUserName').value = '';
    document.getElementById('newUserIsAdmin').checked = false;
}

function showDeleteUser() {
    hideAllSections();
    document.getElementById('deleteUserSection').style.display = 'block';
    document.getElementById('deleteUserId').value = '';
}

function showUserPermissions() {
    hideAllSections();
    document.getElementById('viewPermissionsSection').style.display = 'block';
    document.getElementById('viewPermUserId').value = '';
}

function showGrantPermission() {
    hideAllSections();
    document.getElementById('grantPermissionSection').style.display = 'block';
    // Pré-remplir avec les IDs sauvegardés si disponibles
    document.getElementById('grantUserId').value = '';
    document.getElementById('grantBucketId').value = document.getElementById('bucketId').value || '';
}

function showRevokePermission() {
    hideAllSections();
    document.getElementById('revokePermissionSection').style.display = 'block';
    document.getElementById('revokeUserId').value = '';
    document.getElementById('revokeBucketId').value = document.getElementById('bucketId').value || '';
}

// Actions sur les utilisateurs
async function listAllUsers() {
    try {
        const data = await apiCall('list_users');
        displayUsersDetailed(data);
        showStatus('Users loaded');
    } catch (e) {
        console.error(e);
        showError('Failed to load users - Admin access required');
    }
}

async function createUser() {
    const name = document.getElementById('newUserName').value.trim();
    const isAdmin = document.getElementById('newUserIsAdmin').checked;
    
    if (!name) {
        showError('Please enter a username');
        return;
    }
    
    try {
        const result = await apiCall('create_user', {
            name: name,
            is_admin: isAdmin
        });
        
        showStatus(`User created: ${result.name} (ID: ${result.user_id})`);
        displayUserCreated(result);
        document.getElementById('newUserName').value = '';
        document.getElementById('newUserIsAdmin').checked = false;
    } catch (e) {
        console.error(e);
        showError('Failed to create user');
    }
}

async function deleteUser() {
    const userId = document.getElementById('deleteUserId').value.trim();
    
    if (!userId) {
        showError('Please enter a User ID');
        return;
    }
    
    if (!confirm(`Delete user ${userId}? This action cannot be undone.`)) {
        return;
    }
    
    try {
        await apiCall('delete_user', { target_user_id: userId });
        showStatus(`User ${userId} deleted successfully`);
        document.getElementById('deleteUserId').value = '';
    } catch (e) {
        console.error(e);
        showError('Failed to delete user');
    }
}

async function viewUserPermissions() {
    const userId = document.getElementById('viewPermUserId').value.trim();
    
    if (!userId) {
        showError('Please enter a User ID');
        return;
    }
    
    try {
        const data = await apiCall('list_permissions', {
            target_user_id: userId
        });
        displayUserPermissions(data, userId);
        showStatus(`Permissions loaded for user ${userId}`);
    } catch (e) {
        console.error(e);
        showError('Failed to load permissions');
    }
}

async function grantPermission() {
    const userId = document.getElementById('grantUserId').value.trim();
    const bucketId = document.getElementById('grantBucketId').value.trim();
    
    if (!userId || !bucketId) {
        showError('Please enter both User ID and Bucket ID');
        return;
    }
    
    const permissions = {
        target_user_id: userId,
        target_bucket_id: bucketId,
        read: document.getElementById('grantRead').checked,
        write: document.getElementById('grantWrite').checked,
        delete: document.getElementById('grantDelete').checked
    };
    
    try {
        await apiCall('set_permissions', permissions);
        showStatus(`Permissions granted to user ${userId} for bucket ${bucketId}`);
        // Clear the form
        document.getElementById('grantRead').checked = true;
        document.getElementById('grantWrite').checked = false;
        document.getElementById('grantDelete').checked = false;
    } catch (e) {
        console.error(e);
        showError('Failed to grant permissions');
    }
}

async function revokePermission() {
    const userId = document.getElementById('revokeUserId').value.trim();
    const bucketId = document.getElementById('revokeBucketId').value.trim();
    
    if (!userId || !bucketId) {
        showError('Please enter both User ID and Bucket ID');
        return;
    }
    
    if (!confirm(`Revoke all permissions for user ${userId} on bucket ${bucketId}?`)) {
        return;
    }
    
    try {
        await apiCall('revoke_permission', {
            target_user_id: userId,
            target_bucket_id: bucketId
        });
        showStatus(`Permissions revoked for user ${userId} on bucket ${bucketId}`);
    } catch (e) {
        console.error(e);
        showError('Failed to revoke permissions');
    }
}

// Fonctions d'affichage améliorées
function displayUsersDetailed(users) {
    const results = document.getElementById('results');
    if (!users || users.length === 0) {
        results.innerHTML = '<p class="placeholder">No users found</p>';
        return;
    }
    
    results.innerHTML = `
        <h3>Total Users: ${users.length}</h3>
        ${users.map(user => `
            <div class="user-card ${user.is_admin ? 'admin' : ''}">
                <div class="user-card-header">
                    <span class="user-card-title">
                        👤 ${user.name}
                        ${user.is_admin ? '<span class="status-badge status-online">ADMIN</span>' : ''}
                    </span>
                    <span class="user-id-copy" onclick="copyToClipboard('${user.user_id}')" title="Click to copy">
                        📋 Copy ID
                    </span>
                </div>
                <div class="user-card-body">
                    <strong>ID:</strong> ${user.user_id}<br>
                    <strong>Permissions:</strong> ${user.permissions_count || 0} buckets<br>
                    <button class="btn-small" onclick="document.getElementById('viewPermUserId').value='${user.user_id}';viewUserPermissions()">
                        View Permissions
                    </button>
                </div>
            </div>
        `).join('')}
    `;
}

function displayUserCreated(user) {
    const results = document.getElementById('results');
    results.innerHTML = `
        <div class="success-box">
            <h3>✅ User Created Successfully!</h3>
            <div class="user-card ${user.is_admin ? 'admin' : ''}">
                <p><strong>Name:</strong> ${user.name}</p>
                <p><strong>ID:</strong> <span class="user-id-copy" onclick="copyToClipboard('${user.user_id}')">${user.user_id}</span></p>
                <p><strong>Type:</strong> ${user.is_admin ? 'Administrator' : 'Standard User'}</p>
            </div>
            <p class="info-box">💡 Save this User ID - it's required for all operations!</p>
        </div>
    `;
}

function displayUserPermissions(permissions, userId) {
    const results = document.getElementById('results');
    if (!permissions || permissions.length === 0) {
        results.innerHTML = `
            <h3>User: ${userId}</h3>
            <p class="placeholder">No permissions found for this user</p>
        `;
        return;
    }
    
    results.innerHTML = `
        <h3>Permissions for User: ${userId}</h3>
        ${permissions.map(perm => `
            <div class="permission-card">
                <strong>📦 Bucket: ${perm.bucket_name || perm.bucket_id}</strong>
                ${perm.is_online !== undefined ? 
                    `<span class="status-badge ${perm.is_online ? 'status-online' : 'status-offline'}">
                        ${perm.is_online ? 'ONLINE' : 'OFFLINE'}
                    </span>` : ''}
                <br>
                <small>ID: ${perm.bucket_id}</small>
                <div class="permission-badges">
                    ${perm.read ? '<span class="permission-badge perm-read">READ</span>' : ''}
                    ${perm.write ? '<span class="permission-badge perm-write">WRITE</span>' : ''}
                    ${perm.delete ? '<span class="permission-badge perm-delete">DELETE</span>' : ''}
                </div>
            </div>
        `).join('')}
    `;
}

// Fonction helper pour copier dans le presse-papier
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showStatus('ID copied to clipboard!');
    }).catch(() => {
        // Fallback pour les anciens navigateurs
        const input = document.createElement('input');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showStatus('ID copied to clipboard!');
    });
}

// Mise à jour de hideAllSections pour inclure les nouvelles sections
function hideAllSections() {
    document.getElementById('objectActions').style.display = 'none';
    document.getElementById('addExtensionSection').style.display = 'none';
    document.getElementById('removeExtensionSection').style.display = 'none';
    document.getElementById('createUserSection').style.display = 'none';
    document.getElementById('deleteUserSection').style.display = 'none';
    document.getElementById('viewPermissionsSection').style.display = 'none';
    document.getElementById('grantPermissionSection').style.display = 'none';
    document.getElementById('revokePermissionSection').style.display = 'none';
}

// Ajouter la classe success-box dans les styles si pas déjà fait
const styleSheet = document.styleSheets[0];
if (styleSheet && !document.querySelector('.success-box')) {
    styleSheet.insertRule(`
        .success-box {
            background: #d1fae5;
            border: 2px solid #10b981;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }
    `, styleSheet.cssRules.length);
}


// === FONCTIONS POUR UPLOAD/DOWNLOAD D'OBJETS (VERSION CORRIGÉE) ===

// Afficher le formulaire d'upload
function showUploadObject() {
    const bucketId = document.getElementById('bucketId').value;
    if (!bucketId) {
        showError('Please enter a Bucket ID first');
        return;
    }
    
    hideAllSections();
    
    // Créer dynamiquement le formulaire d'upload
    const results = document.getElementById('results');
    results.innerHTML = `
        <div class="upload-section">
            <h3>📤 Upload File to Bucket</h3>
            <p>Bucket ID: <code>${bucketId}</code></p>
            <div class="input-group">
                <label for="uploadPath">File path in bucket:</label>
                <input type="text" id="uploadPath" placeholder="documents/myfile.txt" value="">
            </div>
            <div class="input-group">
                <label for="fileInput">Select file:</label>
                <input type="file" id="fileInput" onchange="updateUploadPath(this)">
            </div>
            <div class="input-group">
                <label>Or enter text directly:</label>
                <textarea id="textContent" rows="5" placeholder="Enter text content here..."></textarea>
            </div>
            <button class="btn btn-success" onclick="uploadFile()">📤 Upload</button>
            <button class="btn btn-small" onclick="clearResults()">Cancel</button>
        </div>
    `;
}

// Mettre à jour le chemin avec le nom du fichier sélectionné
function updateUploadPath(input) {
    if (input.files && input.files[0]) {
        const fileName = input.files[0].name;
        const pathInput = document.getElementById('uploadPath');
        if (!pathInput.value || pathInput.value === '') {
            pathInput.value = fileName;
        }
    }
}

// Upload un fichier ou du texte
async function uploadFile() {
    const bucketId = document.getElementById('bucketId').value;
    const uploadPath = document.getElementById('uploadPath').value;
    const fileInput = document.getElementById('fileInput');
    const textContent = document.getElementById('textContent').value;
    
    if (!bucketId || !uploadPath) {
        showError('Please enter a file path');
        return;
    }
    
    if (!fileInput.files[0] && !textContent) {
        showError('Please select a file or enter text content');
        return;
    }
    
    try {
        let content;
        let isBase64 = false;
        
        if (fileInput.files[0]) {
            // Upload d'un fichier
            const file = fileInput.files[0];
            console.log('Uploading file:', file.name, 'Size:', file.size);
            
            // Lire le fichier comme base64
            content = await readFileAsBase64(file);
            isBase64 = true;
        } else {
            // Upload de texte direct
            content = btoa(textContent); // Encoder en base64
            isBase64 = true;
        }
        
        console.log('Sending upload request for:', uploadPath);
        
        // Utiliser apiCall avec les bons paramètres
        const result = await apiCall('put_object', {
            key: uploadPath,
            content: content,
            base64: isBase64
        });
        
        showStatus(`✅ File uploaded successfully: ${uploadPath}`);
        // Rafraîchir la liste des objets
        setTimeout(() => listObjects(), 500);
        
    } catch (e) {
        console.error('Upload error:', e);
        showError(`Failed to upload file: ${e.message || e}`);
    }
}

// Helper pour lire un fichier en base64
function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function(e) {
            // Convertir ArrayBuffer en base64
            const bytes = new Uint8Array(e.target.result);
            let binary = '';
            bytes.forEach(byte => binary += String.fromCharCode(byte));
            resolve(btoa(binary));
        };
        reader.onerror = reject;
        reader.readAsArrayBuffer(file);
    });
}

// Télécharger un fichier (version corrigée)
async function downloadObject(key) {
    const bucketId = document.getElementById('bucketId').value;
    const userId = document.getElementById('userId').value;
    
    if (!bucketId) {
        showError('Please enter a Bucket ID');
        return;
    }
    
    try {
        console.log('Downloading:', key);
        
        // Faire la requête directement
        const response = await fetch('/api/proxy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: userId,
                bucket_id: bucketId,
                action: 'get_object',
                key: key
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        // Récupérer le contenu
        const data = await response.json();
        
        // Si c'est du contenu base64
        if (data.content) {
            const binary = atob(data.content);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            const blob = new Blob([bytes]);
            
            // Créer un lien de téléchargement
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = key.split('/').pop();
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showStatus(`✅ Downloaded: ${key}`);
        } else {
            // Fallback pour du texte simple
            const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = key.split('/').pop();
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }
        
    } catch (e) {
        console.error('Download error:', e);
        showError(`Failed to download: ${e.message}`);
    }
}

// Test rapide d'upload de texte
async function quickTestUpload() {
    const bucketId = document.getElementById('bucketId').value;
    if (!bucketId) {
        showError('Please set a Bucket ID first');
        return;
    }
    
    try {
        const testContent = btoa('Test content from RustyKey frontend');
        const result = await apiCall('put_object', {
            key: 'test.txt',
            content: testContent,
            base64: true
        });
        
        showStatus('✅ Test file uploaded successfully!');
        listObjects();
    } catch (e) {
        console.error('Test upload failed:', e);
        showError('Test upload failed');
    }
}

// Ajouter dans app.js
async function listAgents() {
    try {
        const data = await apiCall('list_agents');
        displayAgents(data);
        showStatus('Agents loaded');
    } catch (e) {
        console.error(e);
        showError('Failed to load agents - Admin access required');
    }
}

function displayAgents(agents) {
    const results = document.getElementById('results');
    if (!agents || agents.length === 0) {
        results.innerHTML = '<p class="placeholder">No agents connected</p>';
        return;
    }
    
    results.innerHTML = `
        <h3>Connected Agents: ${agents.length}</h3>
        ${agents.map(agent => `
            <div class="agent-card ${agent.is_online ? 'online' : 'offline'}">
                <div class="agent-header">
                    <strong>🤖 ${agent.description || agent.agent_id}</strong>
                    <span class="status-badge ${agent.is_online ? 'status-online' : 'status-offline'}">
                        ${agent.is_online ? 'ONLINE' : 'OFFLINE'}
                    </span>
                </div>
                <small>ID: ${agent.agent_id}</small><br>
                <small>Created: ${new Date(agent.created_at).toLocaleString()}</small><br>
                <small>Last seen: ${new Date(agent.last_seen).toLocaleString()}</small><br>
                <small>Active buckets: ${agent.active_buckets ? agent.active_buckets.length : 0}</small>
            </div>
        `).join('')}
    `;
}


// === FONCTIONS POUR VIRUSTOTAL ===

function showCheckHash() {
    hideAllSections();
    document.getElementById('checkHashSection').style.display = 'block';
    document.getElementById('hashToCheck').value = '';
    document.getElementById('hashToCheck').focus();
}

function showCheckObject() {
    const bucketId = document.getElementById('bucketId').value;
    if (!bucketId) {
        showError('Please enter a Bucket ID first');
        return;
    }
    
    hideAllSections();
    document.getElementById('checkObjectSection').style.display = 'block';
    document.getElementById('objectToScan').value = '';
    document.getElementById('objectToScan').focus();
}

async function checkFileHash() {
    const hash = document.getElementById('hashToCheck').value.trim();
    
    if (!hash) {
        showError('Please enter a file hash');
        return;
    }
    
    // Validation basique du format du hash
    if (hash.length !== 32 && hash.length !== 40 && hash.length !== 64) {
        showError('Invalid hash format. Expected MD5 (32), SHA1 (40), or SHA256 (64) characters');
        return;
    }
    
    try {
        showStatus('Checking hash with VirusTotal...');
        
        const result = await apiCall('check_file_hash', { hash });
        displayVirusTotalResult(result);
        
    } catch (e) {
        console.error('VirusTotal check failed:', e);
        showError('Failed to check hash - Admin access required');
    }
}

async function checkBucketObject() {
    const bucketId = document.getElementById('bucketId').value;
    const objectPath = document.getElementById('objectToScan').value.trim();
    
    if (!bucketId) {
        showError('Please enter a Bucket ID');
        return;
    }
    
    if (!objectPath) {
        showError('Please enter an object path');
        return;
    }
    
    try {
        showStatus('Scanning object with VirusTotal...');
        
        const result = await apiCall('check_object_safety', {
            bucket_id: bucketId,
            object_key: objectPath
        });
        
        displayObjectScanResult(result);
        
    } catch (e) {
        console.error('Object scan failed:', e);
        showError('Failed to scan object - Admin access required');
    }
}

function displayVirusTotalResult(result) {
    const results = document.getElementById('results');
    
    const isSafe = result.is_safe;
    const statusClass = isSafe ? 'virustotal-safe' : 'virustotal-danger';
    const statusIcon = isSafe ? '✅' : '⚠️';
    const statusText = isSafe ? 'SAFE' : 'MALICIOUS';
    
    let content = `
        <div class="virustotal-result ${statusClass}">
            <h3>${statusIcon} File Status: ${statusText}</h3>
            <p><strong>Hash:</strong> <code>${result.hash}</code></p>
            <p><strong>Detection Ratio:</strong> ${result.detection_ratio || '0/0'}</p>
            <p><strong>${result.message}</strong></p>
    `;
    
    if (result.total > 0) {
        content += `
            <div class="detection-stats">
                <div class="stat-item">
                    <span class="stat-number" style="color: #ef4444;">${result.positives}</span>
                    <span class="stat-label">Detections</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number" style="color: #10b981;">${result.total - result.positives}</span>
                    <span class="stat-label">Clean</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">${result.total}</span>
                    <span class="stat-label">Total Engines</span>
                </div>
            </div>
        `;
    }
    
    if (result.scan_date) {
        content += `<p class="scan-date">Last scanned: ${new Date(result.scan_date).toLocaleString()}</p>`;
    }
    
    if (result.permalink) {
        content += `<a href="${result.permalink}" target="_blank" class="virustotal-link">View Full Report on VirusTotal →</a>`;
    }
    
    content += `</div>`;
    
    results.innerHTML = content;
    
    if (!isSafe) {
        showStatus('⚠️ WARNING: File detected as malicious!');
    } else {
        showStatus('✅ File is safe');
    }
}

function displayObjectScanResult(result) {
    const results = document.getElementById('results');
    
    const isSafe = result.is_safe !== false;
    const statusClass = isSafe ? 'virustotal-safe' : 'virustotal-danger';
    const statusIcon = isSafe ? '✅' : '⚠️';
    
    let content = `
        <div class="virustotal-result ${statusClass}">
            <h3>${statusIcon} Object Scan Result</h3>
            <p><strong>Object:</strong> <code>${result.object}</code></p>
            <p><strong>Hash:</strong> <code>${result.hash}</code></p>
    `;
    
    if (result.detections) {
        content += `<p><strong>Detections:</strong> ${result.detections}</p>`;
    }
    
    if (result.scan_date) {
        content += `<p class="scan-date">Last scanned: ${new Date(result.scan_date).toLocaleString()}</p>`;
    }
    
    if (result.message) {
        content += `<p>${result.message}</p>`;
    }
    
    if (result.permalink) {
        content += `<a href="${result.permalink}" target="_blank" class="virustotal-link">View Full Report on VirusTotal →</a>`;
    }
    
    content += `</div>`;
    
    results.innerHTML = content;
    
    if (!isSafe) {
        showStatus('⚠️ WARNING: Object may be malicious!');
    } else {
        showStatus('✅ Object appears safe');
    }
}

// Mise à jour de hideAllSections pour inclure les nouvelles sections
function hideAllSections() {
    document.getElementById('objectActions').style.display = 'none';
    document.getElementById('addExtensionSection').style.display = 'none';
    document.getElementById('removeExtensionSection').style.display = 'none';
    document.getElementById('createUserSection').style.display = 'none';
    document.getElementById('deleteUserSection').style.display = 'none';
    document.getElementById('viewPermissionsSection').style.display = 'none';
    document.getElementById('grantPermissionSection').style.display = 'none';
    document.getElementById('revokePermissionSection').style.display = 'none';
    document.getElementById('checkHashSection').style.display = 'none';
    document.getElementById('checkObjectSection').style.display = 'none';
}

// === FONCTION POUR SUPPRIMER DIRECTEMENT UN OBJET ===
async function deleteObjectDirect(encodedObjectKey) {
    const objectKey = decodeURIComponent(encodedObjectKey);  // Décoder le key
    const bucketId = document.getElementById('bucketId').value;
    if (!bucketId) {
        showError('Bucket ID is missing');
        return;
    }
    if (!confirm(`Delete object: ${objectKey}?`)) {
        return;
    }
    try {
        await apiCall('delete_object', { 
            key: objectKey  // Utiliser le key décodé
        });
        
        showStatus(`✅ Deleted: ${objectKey}`);
        
        // Rafraîchir la liste des objets après suppression
        setTimeout(() => listObjects(), 500);
        
    } catch (e) {
        console.error('Delete failed:', e);
        showError(`Failed to delete ${objectKey}`);
    }
}

// === AMÉLIORER displayObjects pour avoir tous les boutons fonctionnels ===

function displayObjects(objects) {
    const results = document.getElementById('results');
    if (objects.length === 0) {
        results.innerHTML = '<p class="placeholder">No objects found</p>';
        return;
    }
    
    results.innerHTML = `
        <div class="objects-header">
            <h3>Objects in Bucket (${objects.length})</h3>
            <button class="btn btn-primary btn-small" onclick="showUploadObject()">
                ⬆️ Upload File
            </button>
        </div>
        ${objects.map(obj => {
            // Encoder le key pour gérer les caractères spéciaux
            const encodedKey = encodeURIComponent(obj.key);
            
            return `
            <div class="object-item">
                <div class="object-info">
                    <strong>📄 ${escapeHtml(obj.key)}</strong><br>
                    <small>
                        Size: ${formatBytes(obj.size || 0)} | 
                        ETag: ${obj.etag ? obj.etag.substring(0, 8) + '...' : 'N/A'}
                    </small><br>
                    <small>Modified: ${obj.last_modified ? new Date(obj.last_modified).toLocaleString() : 'Unknown'}</small>
                </div>
                <div class="object-actions">
                    <button class="btn-small btn-virustotal" onclick="scanObjectQuick('${encodedKey}')" title="Scan with VirusTotal">
                        🛡️
                    </button>
                    <button class="btn-small btn-info" onclick="downloadObject('${encodedKey}')" title="Download">
                        ⬇️
                    </button>
                    <button class="btn-small btn-danger" onclick="deleteObjectDirect('${encodedKey}')" title="Delete">
                        🗑️
                    </button>
                </div>
            </div>
            `;
        }).join('')}
    `;
}

// Mettre à jour scanObjectQuick pour décoder le key
async function scanObjectQuick(encodedObjectKey) {
    const objectKey = decodeURIComponent(encodedObjectKey);
    const bucketId = document.getElementById('bucketId').value;
    
    if (!bucketId) {
        showError('Bucket ID is missing');
        return;
    }
    
    try {
        showStatus(`Scanning ${objectKey} with VirusTotal...`);
        
        const result = await apiCall('check_object_safety', {
            bucket_id: bucketId,
            object_key: objectKey
        });
        
        displayObjectScanResult(result);
        
    } catch (e) {
        console.error('Quick scan failed:', e);
        showError('Failed to scan object');
    }
}

// Mettre à jour downloadObject pour décoder le key
async function downloadObject(encodedKey) {
    const key = decodeURIComponent(encodedKey);
    const bucketId = document.getElementById('bucketId').value;
    const userId = document.getElementById('userId').value;
    
    if (!bucketId) {
        showError('Please enter a Bucket ID');
        return;
    }
    
    try {
        console.log('Downloading:', key);
        
        // Faire la requête directement
        const response = await fetch('/api/proxy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },  // CORRIGÉ ICI
            body: JSON.stringify({
                user_id: userId,
                bucket_id: bucketId,
                action: 'get_object',
                key: key
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        // Récupérer le contenu
        const data = await response.json();
        
        // Si c'est du contenu base64
        if (data.content) {
            const binary = atob(data.content);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            const blob = new Blob([bytes]);
            
            // Créer un lien de téléchargement
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = key.split('/').pop();
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showStatus(`✅ Downloaded: ${key}`);
        } else {
            // Fallback pour du texte simple
            const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = key.split('/').pop();
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }
        
    } catch (e) {
        console.error('Download error:', e);
        showError(`Failed to download: ${e.message}`);
    }
}

// Fonction helper pour échapper les caractères HTML (si pas déjà définie)
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

async function cleanAllBuckets() {
    if (!confirm('This will remove all files with banned extensions from all buckets. Continue?')) {
        return;
    }
    
    try {
        const result = await apiCall('clean_buckets');
        showStatus(`✅ Cleaned ${result.objects_removed} objects from ${result.buckets_affected} buckets`);
        
        // Rafraîchir la liste des objets si un bucket est ouvert
        if (document.getElementById('bucketId').value) {
            setTimeout(() => listObjects(), 500);
        }
    } catch (e) {
        console.error(e);
        showError('Failed to clean buckets');
    }
}