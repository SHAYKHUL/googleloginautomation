// server.js
const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const bodyParser = require('body-parser');

const SECRET_KEY = "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890"; // Must match your app and generator
const RATE_LIMIT = 10; // requests per minute
const ADMIN_PASSWORD = "1234";
const BASE_PATH = '/activationserver'; // <-- all routes mounted here

const ACTIVATION_LOG = path.join(__dirname, 'activations.json');
const REVOKED_LOG = path.join(__dirname, 'revoked_keys.json');

const app = express();
app.use(bodyParser.json());

let rateLimit = {};

// --- Helper Functions ---
function generateLicenseKey(hardwareId = null, expiryDate) {
    // If no hardware ID provided, generate a random one
    if (!hardwareId) {
        hardwareId = crypto.randomBytes(8).toString('hex');
    }
    
    const reversedId = hardwareId.split("").reverse().join("");
    const expiryString = expiryDate.replace(/-/g, ''); // Format: YYYYMMDD
    const signature = generateLicenseSignature(hardwareId, expiryString);
    
    return `CALC-${reversedId}-${expiryString}-${signature}`;
}

function loadJson(file) {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
        return {};
    }
}

function saveJson(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function getActivations() {
    return loadJson(ACTIVATION_LOG);
}

function getRevoked() {
    return loadJson(REVOKED_LOG);
}

function addActivation(licenseKey, hardwareId) {
    const activations = getActivations();
    activations[licenseKey] = { hardware_id: hardwareId, time: new Date().toISOString() };
    saveJson(ACTIVATION_LOG, activations);
}

function revokeLicense(licenseKey) {
    const revoked = getRevoked();
    revoked[licenseKey] = new Date().toISOString();
    saveJson(REVOKED_LOG, revoked);
}

function isRevoked(licenseKey) {
    const revoked = getRevoked();
    return revoked.hasOwnProperty(licenseKey);
}

function restoreLicense(licenseKey) {
    const revoked = getRevoked();
    delete revoked[licenseKey];
    saveJson(REVOKED_LOG, revoked);
}

function generateLicenseSignature(hardwareId, expiryDate) {
    const msg = `${hardwareId.split("").reverse().join("")}-${expiryDate}`;
    const hmac = crypto.createHmac('sha256', SECRET_KEY);
    hmac.update(msg);
    return hmac.digest('hex').slice(0, 16);
}

function validateLicenseKey(key, hardwareId) {
    try {
        if (!key.startsWith("CALC-")) return false;
        const parts = key.split("-");
        if (parts.length !== 4) return false;
        const reversedId = parts[1];
        const expiry = parts[2];
        const sig = parts[3];
        if (reversedId !== hardwareId.split("").reverse().join("")) return false;

        const expiryDate = new Date(
            expiry.slice(0,4) + '-' + expiry.slice(4,6) + '-' + expiry.slice(6,8)
        );
        if (expiryDate < new Date()) return false;

        const expectedSig = generateLicenseSignature(hardwareId, expiry);
        return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig));
    } catch (err) {
        return false;
    }
}

// --- Rate Limiting ---
function checkRateLimit(ip) {
    const window = Math.floor(Date.now() / 60000);
    const key = `${ip}:${window}`;
    rateLimit[key] = rateLimit[key] || 0;
    if (rateLimit[key] >= RATE_LIMIT) return false;
    rateLimit[key]++;
    return true;
}

// --- Admin Middleware ---
function requireAdmin(req, res, next) {
    if (req.query.admin !== ADMIN_PASSWORD) {
        return res.status(403).json({ status: 'error', message: 'Forbidden' });
    }
    next();
}

// --- Routes ---

// Serve static files for admin panel (CSS, JS, etc.)
app.use(`${BASE_PATH}`, express.static(__dirname, {
    setHeaders: (res, path) => {
        if (path.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css');
        } else if (path.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript');
        }
    }
}));

// Admin panel route
app.get(`${BASE_PATH}/admin`, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Default route for hosting panel checks
app.get(`${BASE_PATH}/`, (req, res) => {
    res.type('html');
    res.send('<h1>Activation Server Running</h1><p><a href="/activationserver/admin">Admin Panel</a></p>');
});

// Optional quick ping route
app.get(`${BASE_PATH}/ping`, (req, res) => {
    res.send('pong');
});

// Health check
app.get(`${BASE_PATH}/health`, (req, res) => {
    res.json({ status: 'ok' });
});

// Activation endpoint
app.post(`${BASE_PATH}/activate`, (req, res) => {
    const ip = req.ip;
    if (!checkRateLimit(ip)) {
        return res.status(429).json({ status: 'error', message: 'Rate limit exceeded' });
    }

    const { hardware_id, license_key } = req.body;
    if (!hardware_id || !license_key) {
        return res.status(400).json({ status: 'error', message: 'Missing data' });
    }

    // DEBUG: Print activations.json path and contents
    console.log('DEBUG: ACTIVATION_LOG path:', ACTIVATION_LOG);
    try {
        const raw = fs.readFileSync(ACTIVATION_LOG, 'utf8');
        console.log('DEBUG: activations.json contents:', raw);
    } catch (e) {
        console.log('DEBUG: Could not read activations.json:', e.message);
    }

    if (isRevoked(license_key)) {
        return res.status(403).json({ status: 'error', message: 'License revoked' });
    }

    if (!validateLicenseKey(license_key, hardware_id)) {
        return res.status(403).json({ status: 'error', message: 'Invalid or expired license' });
    }

    const activations = getActivations();
    if (activations.hasOwnProperty(license_key)) {
        // If the license is already activated for the same hardware_id, allow re-activation (user lost file)
        if (activations[license_key].hardware_id === hardware_id) {
            // Optionally update the activation time
            activations[license_key].time = new Date().toISOString();
            saveJson(ACTIVATION_LOG, activations);
            return res.json({ status: 'ok', message: 'Re-activation successful (same device)' });
        } else {
            return res.status(403).json({ status: 'error', message: 'License already activated on another device' });
        }
    }

    addActivation(license_key, hardware_id);
    res.json({ status: 'ok', message: 'Activation successful' });
});

// Admin routes
app.get(`${BASE_PATH}/admin/activations`, requireAdmin, (req, res) => {
    res.json(getActivations());
});

app.post(`${BASE_PATH}/admin/revoke`, requireAdmin, (req, res) => {
    const { license_key } = req.body;
    if (!license_key) return res.status(400).json({ status: 'error', message: 'Missing license_key' });
    revokeLicense(license_key);
    res.json({ status: 'ok', message: 'License revoked' });
});

app.get(`${BASE_PATH}/admin/revoked`, requireAdmin, (req, res) => {
    res.json(getRevoked());
});

// Generate new licenses
app.post(`${BASE_PATH}/admin/generate`, requireAdmin, (req, res) => {
    const { hardware_id, expiry_date, count = 1 } = req.body;
    
    if (!expiry_date) {
        return res.status(400).json({ status: 'error', message: 'Missing expiry_date' });
    }
    
    if (count < 1 || count > 100) {
        return res.status(400).json({ status: 'error', message: 'Count must be between 1 and 100' });
    }
    
    try {
        const licenses = [];
        for (let i = 0; i < count; i++) {
            const license = generateLicenseKey(hardware_id, expiry_date);
            licenses.push(license);
        }
        
        res.json({ status: 'ok', licenses: licenses, message: `Generated ${count} license(s)` });
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Failed to generate licenses: ' + error.message });
    }
});

// Restore revoked license
app.post(`${BASE_PATH}/admin/restore`, requireAdmin, (req, res) => {
    const { license_key } = req.body;
    if (!license_key) return res.status(400).json({ status: 'error', message: 'Missing license_key' });
    
    if (!isRevoked(license_key)) {
        return res.status(400).json({ status: 'error', message: 'License is not revoked' });
    }
    
    restoreLicense(license_key);
    res.json({ status: 'ok', message: 'License restored' });
});

// Get license statistics
app.get(`${BASE_PATH}/admin/stats`, requireAdmin, (req, res) => {
    const activations = getActivations();
    const revoked = getRevoked();
    
    const stats = {
        active_licenses: Object.keys(activations).length,
        revoked_licenses: Object.keys(revoked).length,
        total_licenses: Object.keys(activations).length + Object.keys(revoked).length
    };
    
    res.json(stats);
});

// Admin kill switch for immediate termination
let killSwitchTargets = {}; // Format: { hardware_id: true/false }

app.get(`${BASE_PATH}/kill-switch-status`, (req, res) => {
    const { hardware_id } = req.query;
    if (!hardware_id) {
        return res.status(400).json({ status: 'error', message: 'Missing hardware_id' });
    }
    
    const terminate = killSwitchTargets[hardware_id] || false;
    res.json({ terminate: terminate });
});

app.post(`${BASE_PATH}/admin/kill-switch`, requireAdmin, (req, res) => {
    const { hardware_id, terminate } = req.body;
    if (!hardware_id) {
        return res.status(400).json({ status: 'error', message: 'Missing hardware_id' });
    }
    
    killSwitchTargets[hardware_id] = terminate === true;
    const action = terminate ? 'activated' : 'deactivated';
    res.json({ status: 'ok', message: `Kill switch ${action} for ${hardware_id}` });
});

// Kill switch for all devices
app.post(`${BASE_PATH}/admin/kill-switch-all`, requireAdmin, (req, res) => {
    const { terminate } = req.body;
    const activations = getActivations();
    
    let count = 0;
    for (const [licenseKey, data] of Object.entries(activations)) {
        if (data.hardware_id) {
            killSwitchTargets[data.hardware_id] = terminate === true;
            count++;
        }
    }
    
    const action = terminate ? 'activated' : 'deactivated';
    res.json({ status: 'ok', message: `Kill switch ${action} for ${count} devices` });
});

// ==================== SIMPLIFIED ADMIN ENDPOINTS ====================

// Kill specific device (for simplified interface)
app.post(`${BASE_PATH}/admin/kill-device`, requireAdmin, (req, res) => {
    const { hardwareId } = req.body;
    
    if (!hardwareId) {
        return res.status(400).json({ status: 'error', message: 'Hardware ID is required' });
    }
    
    killSwitchTargets[hardwareId] = true;
    res.json({ status: 'ok', message: `Device ${hardwareId} killed successfully` });
});

// Allow specific device (for simplified interface)
app.post(`${BASE_PATH}/admin/allow-device`, requireAdmin, (req, res) => {
    const { hardwareId } = req.body;
    
    if (!hardwareId) {
        return res.status(400).json({ status: 'error', message: 'Hardware ID is required' });
    }
    
    killSwitchTargets[hardwareId] = false;
    res.json({ status: 'ok', message: `Device ${hardwareId} allowed successfully` });
});

// Kill all users (for simplified interface)
app.post(`${BASE_PATH}/admin/kill-all`, requireAdmin, (req, res) => {
    const activations = getActivations();
    
    let count = 0;
    for (const [licenseKey, data] of Object.entries(activations)) {
        if (data.hardware_id) {
            killSwitchTargets[data.hardware_id] = true;
            count++;
        }
    }
    
    res.json({ status: 'ok', message: `Emergency kill activated for ${count} devices` });
});

// Quick license generation (for simplified interface)
app.post(`${BASE_PATH}/admin/generate`, requireAdmin, (req, res) => {
    const { expiryDate, count = 1, hardwareId = null } = req.body;
    
    if (!expiryDate) {
        return res.status(400).json({ status: 'error', message: 'Expiry date is required' });
    }
    
    if (count < 1 || count > 100) {
        return res.status(400).json({ status: 'error', message: 'Count must be between 1 and 100' });
    }
    
    try {
        const licenses = [];
        for (let i = 0; i < count; i++) {
            const license = generateLicenseKey(hardwareId, expiryDate.replace(/-/g, ''));
            licenses.push(license);
        }
        
        res.json({ status: 'ok', licenses: licenses });
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Failed to generate licenses' });
    }
});

// Get kill switch status with device count (for simplified interface)
app.get(`${BASE_PATH}/kill-status`, (req, res) => {
    const killedDevices = {};
    for (const [deviceId, isKilled] of Object.entries(killSwitchTargets)) {
        if (isKilled) {
            killedDevices[deviceId] = true;
        }
    }
    
    res.json({ 
        status: 'ok', 
        killedDevices: killedDevices,
        killCount: Object.keys(killedDevices).length 
    });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Activation server running on port ${PORT} at base path ${BASE_PATH}`);
});
