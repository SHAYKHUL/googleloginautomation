// fullAutomation.js
const { chromium } = require('playwright');
const fs = require('fs').promises;
const path = require('path');
const csv = require('csv-parser');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const pLimit = require('p-limit');
const { existsSync } = require('fs');

// --- 1. Stealth Setup ---
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());

// --- 2. Configuration & Constants ---
const INPUT_CSV = 'accounts.csv';
const SUCCESS_CSV = 'successful_accounts.csv';
const FAILED_CSV = 'failed_accounts.csv';
const GOOGLE_BASE_URL = 'https://myaccount.google.com';

// Balanced Parameters for Speed and Accuracy
const MAX_CONCURRENT_BROWSERS = 8;
const BATCH_SIZE = 150;
const ROBUST_TIMEOUT = 25000; // 25 seconds
const WAIT_UNTIL_MODE = 'domcontentloaded';

// --- 3. Core Utilities ---

const log = (email, message, type = 'INFO') => {
    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });
    const context = email === 'SYSTEM' ? 'SYSTEM' : email;
    const logMessage = `[${timestamp}] [${type.toUpperCase()}] [${context}] ${message}`;
    console.log(logMessage);
};

const initializeCsv = async (filePath, header) => {
    if (!existsSync(filePath)) {
        const writer = createCsvWriter({ path: filePath, header });
        await writer.writeRecords([]);
    }
};

const loadAccounts = async () => {
    if (!existsSync(INPUT_CSV)) {
        throw new Error(`Input file not found: ${INPUT_CSV}`);
    }
    const accounts = [];
    const stream = require('fs').createReadStream(INPUT_CSV).pipe(csv());

    for await (const row of stream) {
        const email = row.Email || row.email;
        const password = row.Password || row.password;
        if (email && password) {
            accounts.push({ email: email.trim(), password: password.trim() });
        }
    }
    return accounts;
};

const getCsvWriter = (filePath, header) => createCsvWriter({
    path: filePath,
    header,
    append: true,
});

const saveSuccess = async (record) => {
    const writer = getCsvWriter(SUCCESS_CSV, [
        { id: 'email', title: 'Email' }, { id: 'password', title: 'Password' },
        { id: 'appPassword', title: 'App Password' }, { id: 'backupCode1', title: 'Backup Code 1' },
        { id: 'backupCode2', title: 'Backup Code 2' }, { id: 'generatedAt', title: 'Generated At' },
    ]);
    await writer.writeRecords([record]);
};

const saveFailure = async (email, password, reason) => {
    const writer = getCsvWriter(FAILED_CSV, [
        { id: 'email', title: 'Email' }, { id: 'password', title: 'Password' },
        { id: 'reason', title: 'Failure Reason' }, { id: 'failedAt', title: 'Failed At' },
    ]);
    await writer.writeRecords([{ email, password, reason, failedAt: new Date().toISOString() }]);
};

// --- 4. High-Accuracy Playwright Interaction (Language-Proofed) ---

const smartClick = async (page, selectors, description) => {
    const selectorList = Array.isArray(selectors) ? selectors : [selectors];
    
    for (const selector of selectorList) {
        try {
            const locator = page.locator(selector);
            await locator.waitFor({ state: 'visible', timeout: 5000 });
            await locator.click({ timeout: 5000 });
            log('SYSTEM', `✅ Clicked ${description} using selector: ${selector}`);
            return true;
        } catch (e) {
            // Try next selector
        }
    }
    
    // Fallback: Force click
    try {
        const fallbackLocator = page.locator(selectorList[0]);
        await fallbackLocator.click({ force: true, timeout: 5000 });
        log('SYSTEM', `✅ Clicked ${description} with FORCE click.`);
        return true;
    } catch (e) {
        throw new Error(`Critical failure: Could not click ${description}.`);
    }
};

const collectBackupCodes = async (page, email) => {
    const codes = [];
    // Navigate with forced English language
    await page.goto(`${GOOGLE_BASE_URL}/two-step-verification/backup-codes?hl=en`, { waitUntil: WAIT_UNTIL_MODE });
    log(email, "Collecting backup codes...");

    // 4.1. Handle "Get codes" button (using forced English text)
    try {
        const getCodesSelectors = ['button:has-text("Get backup codes", { exact: false })', 'button[data-mdc-dialog-action="getBackupCodes"]'];
        await page.waitForTimeout(1000); 

        for (const selector of getCodesSelectors) {
            const btn = page.locator(selector);
            if (await btn.isVisible()) {
                await smartClick(page, selector, 'Get backup codes button');
                await page.waitForTimeout(2000); 
                break;
            }
        }
    } catch (error) { /* skip */ }

    // 4.2. Scrape for codes
    const codeSelectors = ['.backup-code', 'code'];

    for (const selector of codeSelectors) {
        try {
            const elements = await page.locator(selector).allTextContents();
            for (const text of elements) {
                const cleanCode = text.replace(/[-\s]/g, '').trim();
                if (cleanCode.length >= 8 && cleanCode.length <= 12 && /^[a-zA-Z0-9]+$/.test(cleanCode)) {
                    if (!codes.includes(cleanCode)) {
                        codes.push(cleanCode);
                        if (codes.length >= 2) return codes.slice(0, 2);
                    }
                }
            }
        } catch (e) { /* Ignore */ }
    }

    if (codes.length === 0) {
        log(email, "❌ Could not find any backup codes.");
    }

    return codes.slice(0, 2);
};


// --- 5. Automation Worker Function (Language-Agnostic Workflow) ---

const automateAccount = async (account) => {
    const { email, password } = account;
    let context, page;

    try {
        // 5.1. Launch Stealth Browser with Language Forced
        const browserInstance = await puppeteer.launch({ 
            headless: true,
            executablePath: chromium.executablePath(),
            args: [
                '--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', 
                '--lang=en-US' // 🔑 CRITICAL: Force Chrome UI language
            ]
        });
        
        context = await chromium.connect({ wsEndpoint: browserInstance.wsEndpoint() });
        page = await context.newPage();
        
        await page.evaluateOnNewDocument(() => { Object.defineProperty(navigator, 'webdriver', { get: () => undefined }); });
        page.setDefaultTimeout(ROBUST_TIMEOUT);
        
        log(email, 'Browser context launched. Language forced to English.');

        // 5.2. Login (Force page language: ?hl=en)
        await page.goto('https://accounts.google.com/signin?hl=en', { waitUntil: WAIT_UNTIL_MODE });
        
        await page.locator('input[type="email"], input[name="identifier"]').fill(email);
        await smartClick(page, ['button:has-text("Next"), #identifierNext'], 'Email Next Button');
        
        await page.locator('input[type="password"], input[name="Passwd"]').waitFor({ state: 'visible' });
        await page.locator('input[type="password"], input[name="Passwd"]').fill(password);
        await smartClick(page, ['button:has-text("Next"), #passwordNext'], 'Password Next Button');
        
        await page.waitForURL(/myaccount\.google\.com/, { timeout: ROBUST_TIMEOUT });
        log(email, '✅ Login successful.');

        // 5.3. 2FA Setup Initiation (Force page language: ?hl=en)
        await page.goto(`${GOOGLE_BASE_URL}/signinoptions/twosv?hl=en`, { waitUntil: WAIT_UNTIL_MODE });
        
        const turnOnSelectors = ['button:has-text("Get started", { exact: false })', 'button:has-text("Turn on", { exact: false })'];
        await smartClick(page, turnOnSelectors, '2FA Get Started/Turn On Button');

        // 5.4. Phone Input (Add Random Phone Number)
        await page.waitForTimeout(2000); 
        const area = Math.floor(Math.random() * (999 - 200 + 1) + 200);
        const prefix = Math.floor(Math.random() * (999 - 200 + 1) + 200);
        const line = Math.floor(Math.random() * (9999 - 1000 + 1) + 1000);
        const phoneNumber = `(${area}) ${prefix}-${line}`;

        await page.locator('input[type="tel"], input[inputmode="tel"]').fill(phoneNumber);
        const nextSelectors = ['button:has-text("Next", { exact: false })', 'button[data-mdc-dialog-action="next"]'];
        await smartClick(page, nextSelectors, 'Phone Input Next Button');

        // Handle Save/Confirm modal
        try {
            const saveSelectors = ['button:has-text("Save", { exact: false })', 'button[data-mdc-dialog-action*="save"]'];
            await smartClick(page, saveSelectors, 'Phone Confirmation Save Button');
        } catch (e) { /* skip */ }
        
        // 5.5. App Password Generation (Force page language: ?hl=en)
        await page.goto(`${GOOGLE_BASE_URL}/apppasswords?hl=en`, { waitUntil: WAIT_UNTIL_MODE });

        // Handle re-authentication check
        try {
            const reauthInput = page.locator('input[type="password"]');
            await reauthInput.waitFor({ state: 'visible', timeout: 5000 });
            await reauthInput.fill(password);
            await smartClick(page, 'button:has-text("Next")', 'Security Check Next Button');
            await page.waitForURL(/apppasswords/, { timeout: ROBUST_TIMEOUT });
        } catch (e) { /* No re-auth needed */ }

        await page.locator('input[aria-label="Select app"]').fill('AutomationService'); 
        await smartClick(page, ['button:has-text("Create")'], 'Create App Password Button');

        const appPasswordLocator = page.locator('.v2CTKd.KaSAf strong');
        await appPasswordLocator.waitFor({ state: 'visible', timeout: 10000 });
        const appPassword = (await appPasswordLocator.innerText()).replace(/\s/g, '');

        if (!appPassword || appPassword.length !== 16) {
            throw new Error('App Password extraction failed or incorrect length.');
        }
        log(email, `🔑 Generated App Password: ${appPassword}`);

        // 5.6. Collect Backup Codes
        const backupCodes = await collectBackupCodes(page, email);
        
        // 5.7. Save Results
        const record = { email, password, appPassword, backupCode1: backupCodes[0] || '', backupCode2: backupCodes[1] || '', generatedAt: new Date().toISOString() };
        await saveSuccess(record);
        log(email, `✅ SUCCESS! All credentials saved.`);

    } catch (error) {
        const reason = error.message.includes('Timeout') ? `TIMEOUT: ${error.message.substring(0, 100)}` : error.message;
        log(email, `❌ FAILURE: ${reason}`, 'ERROR');
        await saveFailure(email, password, reason);
    } finally {
        if (context) await context.close();
        log(email, 'Browser context closed.');
    }
};


// --- 6. Batch Processing and Orchestration ---

const main = async () => {
    log('SYSTEM', `--- FULL COMPLETE GOOGLE AUTOMATION CORE ---`);
    log('SYSTEM', `Max Concurrent: ${MAX_CONCURRENT_BROWSERS} | Batch Size: ${BATCH_SIZE}`);
    log('SYSTEM', `Language enforced: English (en) for high reliability.`);

    try {
        await initializeCsv(SUCCESS_CSV, []);
        await initializeCsv(FAILED_CSV, []);
        
        const accounts = await loadAccounts();
        if (accounts.length === 0) {
            log('SYSTEM', `No accounts found in ${INPUT_CSV}. Exiting.`);
            return;
        }

        log('SYSTEM', `Loaded ${accounts.length} total accounts. Starting batch process...`);

        const totalBatches = Math.ceil(accounts.length / BATCH_SIZE);
        let processedCount = 0;
        
        for (let i = 0; i < totalBatches; i++) {
            const start = i * BATCH_SIZE;
            const end = start + BATCH_SIZE;
            const batch = accounts.slice(start, end);

            log('SYSTEM', `\n🚀 Starting Batch ${i + 1} of ${totalBatches} (${batch.length} accounts)...`);
            
            const limit = pLimit(MAX_CONCURRENT_BROWSERS);
            const promises = batch.map(account => limit(() => automateAccount(account)));

            await Promise.all(promises);

            processedCount += batch.length;
            log('SYSTEM', `✅ Batch ${i + 1} completed. Total processed: ${processedCount}/${accounts.length}`);
            
            if (i < totalBatches - 1) {
                 log('SYSTEM', `😴 Waiting 5 seconds before starting the next batch...`);
                 await new Promise(resolve => setTimeout(resolve, 5000));
            }
        }

        log('SYSTEM', `\n--- ALL BATCHES COMPLETE ---`);
        log('SYSTEM', `Results saved to: ${SUCCESS_CSV} and ${FAILED_CSV}`);

    } catch (error) {
        log('SYSTEM', `FATAL ORCHESTRATION ERROR: ${error.message}`, 'ERROR');
    }
};

main().catch(console.error);
