// Admin Panel JavaScript
class LicenseManager {
    constructor() {
        this.adminPassword = '';
        this.baseUrl = window.location.origin + '/activationserver';
        this.currentAction = null;
        this.currentLicenseKey = null;
        this.selectedLicenses = new Set();
        this.autoRefreshInterval = null;
        this.previousStats = {};
        
        // Set minimum date to today for expiry date input
        const today = new Date().toISOString().split('T')[0];
        const expiryInput = document.getElementById('expiry-date');
        if (expiryInput) {
            expiryInput.min = today;
            // Set default to 1 year from now
            const nextYear = new Date();
            nextYear.setFullYear(nextYear.getFullYear() + 1);
            expiryInput.value = nextYear.toISOString().split('T')[0];
        }
        
        // Initialize auto-refresh
        this.setupAutoRefresh();
    }

    // Authentication
    async login() {
        const password = document.getElementById('admin-password').value;
        if (!password) {
            this.showError('login-error', 'Please enter admin password');
            return;
        }

        try {
            // Test admin access with a simple request
            const response = await fetch(`${this.baseUrl}/admin/activations?admin=${password}`);
            
            if (response.ok) {
                this.adminPassword = password;
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                this.loadDashboard();
            } else {
                this.showError('login-error', 'Invalid admin password');
            }
        } catch (error) {
            this.showError('login-error', 'Connection error: ' + error.message);
        }
    }

    logout() {
        this.adminPassword = '';
        document.getElementById('login-section').style.display = 'flex';
        document.getElementById('dashboard').style.display = 'none';
        document.getElementById('admin-password').value = '';
        this.clearError('login-error');
    }

    // Dashboard loading
    async loadDashboard() {
        await Promise.all([
            this.loadStatistics(),
            this.refreshActiveLicenses(),
            this.refreshRevokedLicenses()
        ]);
    }

    // Statistics
    async loadStatistics() {
        try {
            const [activationsResponse, revokedResponse] = await Promise.all([
                fetch(`${this.baseUrl}/admin/activations?admin=${this.adminPassword}`),
                fetch(`${this.baseUrl}/admin/revoked?admin=${this.adminPassword}`)
            ]);

            const activations = await activationsResponse.json();
            const revoked = await revokedResponse.json();

            const activeCount = Object.keys(activations).length;
            const revokedCount = Object.keys(revoked).length;
            const totalCount = activeCount + revokedCount;

            // Count expiring licenses (within 30 days)
            const expiringCount = this.countExpiringLicenses(activations);

            document.getElementById('active-count').textContent = activeCount;
            document.getElementById('revoked-count').textContent = revokedCount;
            document.getElementById('total-count').textContent = totalCount;
            document.getElementById('expiring-count').textContent = expiringCount;

        } catch (error) {
            console.error('Error loading statistics:', error);
        }
    }

    countExpiringLicenses(activations) {
        const thirtyDaysFromNow = new Date();
        thirtyDaysFromNow.setDate(thirtyDaysFromNow.getDate() + 30);

        let count = 0;
        for (const [licenseKey] of Object.entries(activations)) {
            const expiry = this.extractExpiryFromLicense(licenseKey);
            if (expiry && expiry <= thirtyDaysFromNow) {
                count++;
            }
        }
        return count;
    }

    // License management
    async refreshActiveLicenses() {
        try {
            const response = await fetch(`${this.baseUrl}/admin/activations?admin=${this.adminPassword}`);
            const activations = await response.json();

            const tbody = document.getElementById('active-licenses-body');
            tbody.innerHTML = '';

            for (const [licenseKey, data] of Object.entries(activations)) {
                const row = this.createActiveLicenseRow(licenseKey, data);
                tbody.appendChild(row);
            }

        } catch (error) {
            console.error('Error loading active licenses:', error);
        }
    }

    async refreshRevokedLicenses() {
        try {
            const response = await fetch(`${this.baseUrl}/admin/revoked?admin=${this.adminPassword}`);
            const revoked = await response.json();

            const tbody = document.getElementById('revoked-licenses-body');
            tbody.innerHTML = '';

            for (const [licenseKey, revokedDate] of Object.entries(revoked)) {
                const row = this.createRevokedLicenseRow(licenseKey, revokedDate);
                tbody.appendChild(row);
            }

        } catch (error) {
            console.error('Error loading revoked licenses:', error);
        }
    }

    createActiveLicenseRow(licenseKey, data) {
        const row = document.createElement('tr');
        
        const expiryDate = this.extractExpiryFromLicense(licenseKey);
        const status = this.getLicenseStatus(expiryDate);
        
        row.innerHTML = `
            <td>
                <input type="checkbox" class="license-checkbox" value="${licenseKey}" onchange="licenseManager.updateSelection(this)">
            </td>
            <td><span class="license-key">${licenseKey}</span></td>
            <td>${data.hardware_id || 'N/A'}</td>
            <td>${new Date(data.time).toLocaleString()}</td>
            <td>${expiryDate ? expiryDate.toLocaleDateString() : 'Invalid'}</td>
            <td><span class="status-badge ${status.class}">${status.text}</span></td>
            <td>
                <button class="action-btn view-btn" onclick="licenseManager.viewLicenseDetails('${licenseKey}')">View</button>
                <button class="action-btn revoke-btn" onclick="licenseManager.confirmRevokeLicense('${licenseKey}')">Revoke</button>
                <button class="action-btn kill-btn" onclick="licenseManager.activateKillSwitchForLicense('${data.hardware_id}')">Kill</button>
            </td>
        `;
        
        return row;
    }

    updateSelection(checkbox) {
        if (checkbox.checked) {
            this.selectedLicenses.add(checkbox.value);
        } else {
            this.selectedLicenses.delete(checkbox.value);
        }
        this.updateSelectionInfo();
    }

    async activateKillSwitchForLicense(hardwareId) {
        if (!confirm(`Activate kill switch for device ${hardwareId}?`)) {
            return;
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/admin/kill-switch?admin=${this.adminPassword}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hardware_id: hardwareId, terminate: true })
            });
            
            const result = await response.json();
            if (response.ok) {
                alert(`Kill switch activated for ${hardwareId}`);
            } else {
                alert(`Error: ${result.message}`);
            }
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    }

    createRevokedLicenseRow(licenseKey, revokedDate) {
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td><span class="license-key">${licenseKey}</span></td>
            <td>${new Date(revokedDate).toLocaleString()}</td>
            <td>
                <button class="action-btn view-btn" onclick="licenseManager.viewLicenseDetails('${licenseKey}')">View</button>
                <button class="action-btn restore-btn" onclick="licenseManager.confirmRestoreLicense('${licenseKey}')">Restore</button>
            </td>
        `;
        
        return row;
    }

    // License generation
    async generateLicense() {
        const hardwareId = document.getElementById('hardware-id').value.trim();
        const expiryDate = document.getElementById('expiry-date').value;
        const licenseCount = parseInt(document.getElementById('license-count').value);

        if (!expiryDate) {
            alert('Please select an expiry date');
            return;
        }

        if (licenseCount < 1 || licenseCount > 100) {
            alert('License count must be between 1 and 100');
            return;
        }

        // Validate that the expiry date is in the future
        const today = new Date();
        const expiry = new Date(expiryDate);
        if (expiry <= today) {
            alert('Expiry date must be in the future');
            return;
        }

        try {
            const response = await fetch(`${this.baseUrl}/admin/generate?admin=${this.adminPassword}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    hardware_id: hardwareId || null,
                    expiry_date: expiryDate,
                    count: licenseCount
                })
            });

            const result = await response.json();

            if (response.ok) {
                this.displayGeneratedLicenses(result.licenses);
                this.loadStatistics();
                // Clear form
                document.getElementById('hardware-id').value = '';
                document.getElementById('license-count').value = '1';
            } else {
                alert('Error generating licenses: ' + result.message);
            }

        } catch (error) {
            alert('Error generating licenses: ' + error.message);
        }
    }

    displayGeneratedLicenses(licenses) {
        const container = document.getElementById('generated-licenses');
        container.innerHTML = `
            <h3>Generated Licenses</h3>
            <div class="licenses-list">
                ${licenses.map(license => `
                    <div class="generated-license">
                        <span class="license-key">${license}</span>
                        <button onclick="navigator.clipboard.writeText('${license}')">Copy</button>
                    </div>
                `).join('')}
            </div>
        `;
        container.style.display = 'block';
        
        // Auto-hide after 30 seconds
        setTimeout(() => {
            container.style.display = 'none';
        }, 30000);
    }

    // License actions
    confirmRevokeLicense(licenseKey) {
        this.currentLicenseKey = licenseKey;
        this.currentAction = 'revoke';
        document.getElementById('confirm-message').textContent = 
            `Are you sure you want to revoke license: ${licenseKey}?`;
        document.getElementById('confirm-modal').style.display = 'block';
    }

    confirmRestoreLicense(licenseKey) {
        this.currentLicenseKey = licenseKey;
        this.currentAction = 'restore';
        document.getElementById('confirm-message').textContent = 
            `Are you sure you want to restore license: ${licenseKey}?`;
        document.getElementById('confirm-modal').style.display = 'block';
    }

    async confirmAction() {
        if (this.currentAction === 'revoke') {
            await this.revokeLicense(this.currentLicenseKey);
        } else if (this.currentAction === 'restore') {
            await this.restoreLicense(this.currentLicenseKey);
        }
        this.closeConfirmModal();
    }

    async revokeLicense(licenseKey) {
        try {
            const response = await fetch(`${this.baseUrl}/admin/revoke?admin=${this.adminPassword}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ license_key: licenseKey })
            });

            if (response.ok) {
                await this.loadDashboard();
            } else {
                const result = await response.json();
                alert('Error revoking license: ' + result.message);
            }

        } catch (error) {
            alert('Error revoking license: ' + error.message);
        }
    }

    async restoreLicense(licenseKey) {
        try {
            const response = await fetch(`${this.baseUrl}/admin/restore?admin=${this.adminPassword}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ license_key: licenseKey })
            });

            if (response.ok) {
                await this.loadDashboard();
            } else {
                const result = await response.json();
                alert('Error restoring license: ' + result.message);
            }

        } catch (error) {
            alert('Error restoring license: ' + error.message);
        }
    }

    viewLicenseDetails(licenseKey) {
        const expiryDate = this.extractExpiryFromLicense(licenseKey);
        const status = this.getLicenseStatus(expiryDate);
        
        const parts = licenseKey.split('-');
        const reversedId = parts[1];
        const expiry = parts[2];
        
        const details = `
            <p><strong>License Key:</strong> <span class="license-key">${licenseKey}</span></p>
            <p><strong>Expected Hardware ID:</strong> ${reversedId.split("").reverse().join("")}</p>
            <p><strong>Expiry Date:</strong> ${expiryDate ? expiryDate.toLocaleDateString() : 'Invalid'}</p>
            <p><strong>Status:</strong> <span class="status-badge ${status.class}">${status.text}</span></p>
            <p><strong>Raw Expiry:</strong> ${expiry}</p>
        `;
        
        document.getElementById('license-details').innerHTML = details;
        document.getElementById('license-modal').style.display = 'block';
    }

    // Utility functions
    extractExpiryFromLicense(licenseKey) {
        try {
            const parts = licenseKey.split('-');
            if (parts.length !== 4) return null;
            
            const expiry = parts[2];
            const year = expiry.slice(0, 4);
            const month = expiry.slice(4, 6);
            const day = expiry.slice(6, 8);
            
            return new Date(year, month - 1, day);
        } catch (error) {
            return null;
        }
    }

    getLicenseStatus(expiryDate) {
        if (!expiryDate) {
            return { class: 'status-expired', text: 'Invalid' };
        }

        const now = new Date();
        const thirtyDaysFromNow = new Date();
        thirtyDaysFromNow.setDate(now.getDate() + 30);

        if (expiryDate < now) {
            return { class: 'status-expired', text: 'Expired' };
        } else if (expiryDate <= thirtyDaysFromNow) {
            return { class: 'status-expiring', text: 'Expiring Soon' };
        } else {
            return { class: 'status-active', text: 'Active' };
        }
    }

    // UI helpers
    showError(elementId, message) {
        const element = document.getElementById(elementId);
        element.textContent = message;
        element.style.display = 'block';
    }

    clearError(elementId) {
        const element = document.getElementById(elementId);
        element.textContent = '';
        element.style.display = 'none';
    }

    closeConfirmModal() {
        document.getElementById('confirm-modal').style.display = 'none';
        this.currentAction = null;
        this.currentLicenseKey = null;
    }

    closeLicenseModal() {
        document.getElementById('license-modal').style.display = 'none';
    }

    // Search/filter functionality
    filterTable(tableId, searchValue) {
        const table = document.getElementById(tableId);
        const tbody = table.querySelector('tbody');
        const rows = tbody.getElementsByTagName('tr');

        for (let row of rows) {
            const text = row.textContent.toLowerCase();
            if (text.includes(searchValue.toLowerCase())) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        }
    }

    // Enhanced features
    setupAutoRefresh() {
        const autoRefreshCheckbox = document.getElementById('auto-refresh');
        if (autoRefreshCheckbox) {
            autoRefreshCheckbox.addEventListener('change', (e) => {
                if (e.target.checked) {
                    this.startAutoRefresh();
                } else {
                    this.stopAutoRefresh();
                }
            });
            
            // Start auto-refresh by default
            if (autoRefreshCheckbox.checked) {
                this.startAutoRefresh();
            }
        }
    }

    startAutoRefresh() {
        this.stopAutoRefresh(); // Clear any existing interval
        this.autoRefreshInterval = setInterval(() => {
            this.refreshAll();
        }, 30000); // 30 seconds
    }

    stopAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
            this.autoRefreshInterval = null;
        }
    }

    async refreshAll() {
        await this.loadDashboard();
        document.getElementById('last-updated-time').textContent = new Date().toLocaleTimeString();
    }

    // Bulk operations
    selectAllActive() {
        const activeRows = document.querySelectorAll('#active-table tbody tr');
        activeRows.forEach(row => {
            const checkbox = row.querySelector('.license-checkbox');
            if (checkbox) {
                checkbox.checked = true;
                this.selectedLicenses.add(checkbox.value);
            }
        });
        this.updateSelectionInfo();
    }

    selectAllRevoked() {
        const revokedRows = document.querySelectorAll('#revoked-table tbody tr');
        revokedRows.forEach(row => {
            const checkbox = row.querySelector('.license-checkbox');
            if (checkbox) {
                checkbox.checked = true;
                this.selectedLicenses.add(checkbox.value);
            }
        });
        this.updateSelectionInfo();
    }

    selectExpiring() {
        const activeRows = document.querySelectorAll('#active-table tbody tr');
        activeRows.forEach(row => {
            const statusBadge = row.querySelector('.status-expiring');
            if (statusBadge) {
                const checkbox = row.querySelector('.license-checkbox');
                if (checkbox) {
                    checkbox.checked = true;
                    this.selectedLicenses.add(checkbox.value);
                }
            }
        });
        this.updateSelectionInfo();
    }

    clearSelection() {
        this.selectedLicenses.clear();
        document.querySelectorAll('.license-checkbox').forEach(checkbox => {
            checkbox.checked = false;
        });
        this.updateSelectionInfo();
    }

    updateSelectionInfo() {
        document.getElementById('selected-count').textContent = this.selectedLicenses.size;
    }

    // Advanced filtering
    applyFilters() {
        const statusFilter = document.getElementById('status-filter').value;
        const dateFrom = document.getElementById('date-from').value;
        const dateTo = document.getElementById('date-to').value;
        const hardwareFilter = document.getElementById('hardware-filter').value.toLowerCase();

        const allRows = document.querySelectorAll('#active-table tbody tr, #revoked-table tbody tr');
        
        allRows.forEach(row => {
            let show = true;
            
            // Status filter
            if (statusFilter !== 'all') {
                const statusBadge = row.querySelector('.status-badge');
                if (statusBadge) {
                    const status = statusBadge.className;
                    if (statusFilter === 'active' && !status.includes('status-active')) show = false;
                    if (statusFilter === 'revoked' && !row.closest('#revoked-table')) show = false;
                    if (statusFilter === 'expiring' && !status.includes('status-expiring')) show = false;
                    if (statusFilter === 'expired' && !status.includes('status-expired')) show = false;
                }
            }
            
            // Hardware ID filter
            if (hardwareFilter && !row.textContent.toLowerCase().includes(hardwareFilter)) {
                show = false;
            }
            
            row.style.display = show ? '' : 'none';
        });
    }

    clearFilters() {
        document.getElementById('status-filter').value = 'all';
        document.getElementById('date-from').value = '';
        document.getElementById('date-to').value = '';
        document.getElementById('hardware-filter').value = '';
        this.applyFilters();
    }

    saveFilters() {
        const filters = {
            status: document.getElementById('status-filter').value,
            dateFrom: document.getElementById('date-from').value,
            dateTo: document.getElementById('date-to').value,
            hardware: document.getElementById('hardware-filter').value
        };
        localStorage.setItem('adminFilters', JSON.stringify(filters));
        alert('Filters saved successfully!');
    }
}

// Initialize the license manager
const licenseManager = new LicenseManager();

// Global functions for HTML onclick handlers
function login() {
    licenseManager.login();
}

function logout() {
    licenseManager.logout();
}

function generateLicense() {
    licenseManager.generateLicense();
}

function refreshActiveLicenses() {
    licenseManager.refreshActiveLicenses();
}

function refreshRevokedLicenses() {
    licenseManager.refreshRevokedLicenses();
}

function confirmAction() {
    licenseManager.confirmAction();
}

function closeConfirmModal() {
    licenseManager.closeConfirmModal();
}

function closeLicenseModal() {
    licenseManager.closeLicenseModal();
}

function filterTable(tableId, searchValue) {
    licenseManager.filterTable(tableId, searchValue);
}

// Kill switch functions
async function activateKillSwitch() {
    const hardwareId = document.getElementById('target-hardware-id').value.trim();
    if (!hardwareId) {
        alert('Please enter a hardware ID');
        return;
    }
    
    if (!confirm(`🚨 CRITICAL: This will IMMEDIATELY TERMINATE the application on device ${hardwareId}. Continue?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${licenseManager.baseUrl}/admin/kill-switch?admin=${licenseManager.adminPassword}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hardware_id: hardwareId, terminate: true })
        });
        
        const result = await response.json();
        if (response.ok) {
            alert(`✅ Kill switch activated for ${hardwareId}. Application will terminate within 30 seconds.`);
            document.getElementById('target-hardware-id').value = '';
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

async function deactivateKillSwitch() {
    const hardwareId = document.getElementById('target-hardware-id').value.trim();
    if (!hardwareId) {
        alert('Please enter a hardware ID');
        return;
    }
    
    try {
        const response = await fetch(`${licenseManager.baseUrl}/admin/kill-switch?admin=${licenseManager.adminPassword}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hardware_id: hardwareId, terminate: false })
        });
        
        const result = await response.json();
        if (response.ok) {
            alert(`✅ Kill switch deactivated for ${hardwareId}. Access restored.`);
            document.getElementById('target-hardware-id').value = '';
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

async function killAllDevices() {
    if (!confirm('🚨 EMERGENCY: This will IMMEDIATELY TERMINATE ALL running applications on ALL devices. This cannot be undone easily. Continue?')) {
        return;
    }
    
    if (!confirm('🔴 FINAL WARNING: You are about to kill ALL active applications. Type "KILL ALL" to confirm.')) {
        return;
    }
    
    try {
        const response = await fetch(`${licenseManager.baseUrl}/admin/kill-switch-all?admin=${licenseManager.adminPassword}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ terminate: true })
        });
        
        const result = await response.json();
        if (response.ok) {
            alert(`🔴 EMERGENCY ACTIVATED: ${result.message}. All applications will terminate within 30 seconds.`);
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

async function allowAllDevices() {
    try {
        const response = await fetch(`${licenseManager.baseUrl}/admin/kill-switch-all?admin=${licenseManager.adminPassword}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ terminate: false })
        });
        
        const result = await response.json();
        if (response.ok) {
            alert(`✅ ACCESS RESTORED: ${result.message}. All kill switches deactivated.`);
        } else {
            alert(`Error: ${result.message}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

// Enhanced control functions
async function checkKillSwitchStatus() {
    const hardwareId = document.getElementById('target-hardware-id').value.trim();
    if (!hardwareId) {
        alert('Please enter a hardware ID');
        return;
    }
    
    try {
        const response = await fetch(`${licenseManager.baseUrl}/kill-switch-status?hardware_id=${hardwareId}`);
        const result = await response.json();
        
        const statusDiv = document.getElementById('device-status');
        const statusLight = document.getElementById('status-light');
        const statusText = document.getElementById('status-text');
        
        if (response.ok) {
            statusDiv.style.display = 'block';
            if (result.terminate) {
                statusLight.className = 'status-light killed';
                statusText.textContent = 'Kill Switch ACTIVE - Application will terminate';
            } else {
                statusLight.className = 'status-light online';
                statusText.textContent = 'Device is ALLOWED - Normal operation';
            }
        } else {
            statusDiv.style.display = 'block';
            statusLight.className = 'status-light offline';
            statusText.textContent = 'Unable to check status';
        }
    } catch (error) {
        alert(`Error checking status: ${error.message}`);
    }
}

// Bulk operation functions
async function bulkRevokeLicenses() {
    if (licenseManager.selectedLicenses.size === 0) {
        alert('Please select licenses first');
        return;
    }
    
    if (!confirm(`Revoke ${licenseManager.selectedLicenses.size} selected licenses?`)) {
        return;
    }
    
    let success = 0;
    let failed = 0;
    
    for (const licenseKey of licenseManager.selectedLicenses) {
        try {
            const response = await fetch(`${licenseManager.baseUrl}/admin/revoke?admin=${licenseManager.adminPassword}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ license_key: licenseKey })
            });
            
            if (response.ok) success++;
            else failed++;
        } catch (error) {
            failed++;
        }
    }
    
    alert(`Bulk revocation complete: ${success} succeeded, ${failed} failed`);
    licenseManager.clearSelection();
    licenseManager.refreshAll();
}

async function bulkRestoreLicenses() {
    if (licenseManager.selectedLicenses.size === 0) {
        alert('Please select licenses first');
        return;
    }
    
    if (!confirm(`Restore ${licenseManager.selectedLicenses.size} selected licenses?`)) {
        return;
    }
    
    let success = 0;
    let failed = 0;
    
    for (const licenseKey of licenseManager.selectedLicenses) {
        try {
            const response = await fetch(`${licenseManager.baseUrl}/admin/restore?admin=${licenseManager.adminPassword}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ license_key: licenseKey })
            });
            
            if (response.ok) success++;
            else failed++;
        } catch (error) {
            failed++;
        }
    }
    
    alert(`Bulk restoration complete: ${success} succeeded, ${failed} failed`);
    licenseManager.clearSelection();
    licenseManager.refreshAll();
}

function bulkExportLicenses() {
    if (licenseManager.selectedLicenses.size === 0) {
        alert('Please select licenses first');
        return;
    }
    
    const exportData = Array.from(licenseManager.selectedLicenses).join('\n');
    const blob = new Blob([exportData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `licenses_export_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    alert(`Exported ${licenseManager.selectedLicenses.size} licenses`);
}

// Close modals when clicking outside
window.onclick = function(event) {
    const confirmModal = document.getElementById('confirm-modal');
    const licenseModal = document.getElementById('license-modal');
    
    if (event.target === confirmModal) {
        closeConfirmModal();
    }
    if (event.target === licenseModal) {
        closeLicenseModal();
    }
}

// Handle Enter key in login form
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('admin-password');
    if (passwordInput) {
        passwordInput.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                login();
            }
        });
    }
    
    // Set default expiry date for quick license generation
    const quickExpiryInput = document.getElementById('quick-expiry');
    if (quickExpiryInput) {
        const today = new Date().toISOString().split('T')[0];
        quickExpiryInput.min = today;
        // Set default to 1 year from now
        const nextYear = new Date();
        nextYear.setFullYear(nextYear.getFullYear() + 1);
        quickExpiryInput.value = nextYear.toISOString().split('T')[0];
    }
    
    // Update status bar periodically
    setInterval(updateAdminStatusBar, 5000);
    updateAdminStatusBar();
});

// ==================== SIMPLIFIED ADMIN FUNCTIONS ====================

// Quick License Generation
async function quickGenerateLicense() {
    const expiryDate = document.getElementById('quick-expiry').value;
    const count = parseInt(document.getElementById('quick-count').value) || 1;
    
    if (!expiryDate) {
        showNotification('Please select an expiry date', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${licenseManager.baseUrl}/admin/generate?admin=${licenseManager.adminPassword}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                expiryDate: expiryDate,
                count: count
            })
        });
        
        const result = await response.json();
        if (response.ok) {
            showNotification(`Generated ${count} license(s) successfully!`, 'success');
            updateLastAdminAction(`Generated ${count} license(s)`);
            
            // Show licenses in a simple format
            const licensesList = result.licenses.join('\n');
            const textarea = document.createElement('textarea');
            textarea.value = licensesList;
            textarea.style.cssText = 'position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); z-index:10000; width:500px; height:200px; padding:10px; border:2px solid #2196f3; border-radius:8px; background:white;';
            document.body.appendChild(textarea);
            textarea.select();
            
            setTimeout(() => {
                document.body.removeChild(textarea);
            }, 5000);
            
        } else {
            showNotification(result.message || 'Failed to generate licenses', 'error');
        }
    } catch (error) {
        showNotification('Error generating licenses: ' + error.message, 'error');
    }
}

// Device Control Functions
async function killDevice() {
    const hardwareId = document.getElementById('device-hardware-id').value.trim();
    if (!hardwareId) {
        showNotification('Please enter a hardware ID', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${licenseManager.baseUrl}/admin/kill-device?admin=${licenseManager.adminPassword}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                hardwareId: hardwareId
            })
        });
        
        const result = await response.json();
        if (response.ok) {
            showNotification(`Device ${hardwareId.substring(0, 8)}... killed`, 'success');
            updateLastAdminAction(`Killed device ${hardwareId.substring(0, 8)}...`);
        } else {
            showNotification(result.message || 'Failed to kill device', 'error');
        }
    } catch (error) {
        showNotification('Error killing device: ' + error.message, 'error');
    }
}

async function allowDevice() {
    const hardwareId = document.getElementById('device-hardware-id').value.trim();
    if (!hardwareId) {
        showNotification('Please enter a hardware ID', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${licenseManager.baseUrl}/admin/allow-device?admin=${licenseManager.adminPassword}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                hardwareId: hardwareId
            })
        });
        
        const result = await response.json();
        if (response.ok) {
            showNotification(`Device ${hardwareId.substring(0, 8)}... allowed`, 'success');
            updateLastAdminAction(`Allowed device ${hardwareId.substring(0, 8)}...`);
        } else {
            showNotification(result.message || 'Failed to allow device', 'error');
        }
    } catch (error) {
        showNotification('Error allowing device: ' + error.message, 'error');
    }
}

// Emergency Functions
async function confirmKillAll() {
    if (!confirm('🚨 EMERGENCY ACTION\n\nThis will immediately terminate ALL user sessions.\n\nAre you absolutely sure?')) {
        return;
    }
    
    try {
        const response = await fetch(`${licenseManager.baseUrl}/admin/kill-all?admin=${licenseManager.adminPassword}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        
        const result = await response.json();
        if (response.ok) {
            showNotification('🔴 ALL USERS TERMINATED', 'error');
            updateLastAdminAction('EMERGENCY: Killed all users');
        } else {
            showNotification(result.message || 'Failed to kill all users', 'error');
        }
    } catch (error) {
        showNotification('Error in emergency kill: ' + error.message, 'error');
    }
}

// Bulk Operations
async function bulkRevoke() {
    const licenseText = document.getElementById('bulk-licenses').value.trim();
    if (!licenseText) {
        showNotification('Please enter license keys to revoke', 'error');
        return;
    }
    
    const licenses = licenseText.split('\n').filter(l => l.trim()).map(l => l.trim());
    
    try {
        let successCount = 0;
        let errorCount = 0;
        
        for (const licenseKey of licenses) {
            const response = await fetch(`${licenseManager.baseUrl}/admin/revoke?admin=${licenseManager.adminPassword}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    license_key: licenseKey
                })
            });
            
            if (response.ok) {
                successCount++;
            } else {
                errorCount++;
            }
        }
        
        showNotification(`Bulk revoke: ${successCount} success, ${errorCount} errors`, 
                        errorCount > 0 ? 'warning' : 'success');
        updateLastAdminAction(`Bulk revoked ${successCount} licenses`);
        
    } catch (error) {
        showNotification('Error in bulk revoke: ' + error.message, 'error');
    }
}

async function bulkRestore() {
    const licenseText = document.getElementById('bulk-licenses').value.trim();
    if (!licenseText) {
        showNotification('Please enter license keys to restore', 'error');
        return;
    }
    
    const licenses = licenseText.split('\n').filter(l => l.trim()).map(l => l.trim());
    
    try {
        let successCount = 0;
        let errorCount = 0;
        
        for (const licenseKey of licenses) {
            const response = await fetch(`${licenseManager.baseUrl}/admin/restore?admin=${licenseManager.adminPassword}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    license_key: licenseKey
                })
            });
            
            if (response.ok) {
                successCount++;
            } else {
                errorCount++;
            }
        }
        
        showNotification(`Bulk restore: ${successCount} success, ${errorCount} errors`, 
                        errorCount > 0 ? 'warning' : 'success');
        updateLastAdminAction(`Bulk restored ${successCount} licenses`);
        
    } catch (error) {
        showNotification('Error in bulk restore: ' + error.message, 'error');
    }
}

// Status Bar Updates
async function updateAdminStatusBar() {
    try {
        // Update kill count
        const killResponse = await fetch(`${licenseManager.baseUrl}/kill-status`);
        if (killResponse.ok) {
            const killData = await killResponse.json();
            const killCount = Object.keys(killData.killedDevices || {}).length;
            const killCountElement = document.getElementById('kill-count');
            if (killCountElement) {
                killCountElement.textContent = `${killCount} Active Kills`;
            }
        }
    } catch (error) {
        // Silent error handling for status updates
    }
}

function updateLastAdminAction(action) {
    const element = document.getElementById('last-admin-action');
    if (element) {
        element.textContent = action;
        setTimeout(() => {
            element.textContent = 'No Recent Actions';
        }, 30000); // Clear after 30 seconds
    }
}

// Notification System
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 10000;
        padding: 12px 20px;
        border-radius: 8px;
        color: white;
        font-weight: 500;
        max-width: 400px;
        word-wrap: break-word;
        animation: slideInRight 0.3s ease;
    `;
    
    switch (type) {
        case 'success':
            notification.style.background = 'linear-gradient(145deg, #4caf50, #388e3c)';
            break;
        case 'error':
            notification.style.background = 'linear-gradient(145deg, #f44336, #d32f2f)';
            break;
        case 'warning':
            notification.style.background = 'linear-gradient(145deg, #ff9800, #f57c00)';
            break;
        default:
            notification.style.background = 'linear-gradient(145deg, #2196f3, #1976d2)';
    }
    
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                document.body.removeChild(notification);
            }
        }, 300);
    }, 4000);
}