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

// Default route for hosting panel checks
app.get(`${BASE_PATH}/`, (req, res) => {
    res.type('html');
    res.send('<h1>Activation Server Running</h1>');
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
        return res.status(403).json({ status: 'error', message: 'License already activated' });
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

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Activation server running on port ${PORT} at base path ${BASE_PATH}`);
});
