// fullAutomation.js
const { chromium } = require('playwright');
const fs = require('fs').promises;
const path = require('path');
const csv = require('csv-parser');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const pLimit = require('p-limit');
const { existsSync } = require('fs');
const { execSync } = require('child_process');

// --- 1. Stealth Setup (Playwright Only) ---
// Using Playwright's built-in stealth capabilities

// --- 2. Configuration & Constants ---
const INPUT_CSV = 'accounts.csv';
const SUCCESS_CSV = 'successful_accounts.csv';
const FAILED_CSV = 'failed_accounts.csv';
const GOOGLE_BASE_URL = 'https://myaccount.google.com';

// User Configuration Limits (must be defined first)
const MIN_WORKERS = 1;
const MAX_WORKERS = 20;
const RECOMMENDED_WORKERS = 8;

// High-Speed Optimized Parameters (User Configurable)
let MAX_CONCURRENT_BROWSERS = 8; // Default value, can be changed by user
const BATCH_SIZE = 150;
const ROBUST_TIMEOUT = 10000; // Reduced to 10s for speed
const WAIT_UNTIL_MODE = 'domcontentloaded'; // Faster page loading
const FAST_TIMEOUT = 5000; // Quick operations

// Parse command line arguments for browser count
const args = process.argv.slice(2);
const browserCountIndex = args.indexOf('--browsers');
if (browserCountIndex !== -1 && args[browserCountIndex + 1]) {
    const browserCount = parseInt(args[browserCountIndex + 1]);
    if (!isNaN(browserCount) && browserCount >= MIN_WORKERS && browserCount <= MAX_WORKERS) {
        MAX_CONCURRENT_BROWSERS = browserCount;
        console.log(`🎯 Using ${browserCount} concurrent browsers from GUI configuration`);
    }
}

// Also check environment variable (alternative method)
if (process.env.BROWSER_COUNT) {
    const envBrowserCount = parseInt(process.env.BROWSER_COUNT);
    if (!isNaN(envBrowserCount) && envBrowserCount >= MIN_WORKERS && envBrowserCount <= MAX_WORKERS) {
        MAX_CONCURRENT_BROWSERS = envBrowserCount;
        console.log(`🎯 Using ${envBrowserCount} concurrent browsers from environment`);
    }
}

// --- 3. Core Utilities & User Interface ---

// Console Colors for Windows
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    bgRed: '\x1b[41m',
    bgGreen: '\x1b[42m',
    bgYellow: '\x1b[43m'
};

// Enhanced logging with colors and emojis
const log = (email, message, type = 'INFO') => {
    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });
    const context = email === 'SYSTEM' ? 'SYSTEM' : email.split('@')[0]; // Just username for readability
    
    let colorCode = colors.white;
    let emoji = '📝';
    
    switch(type.toUpperCase()) {
        case 'SUCCESS':
            colorCode = colors.green;
            emoji = '✅';
            break;
        case 'ERROR':
            colorCode = colors.red;
            emoji = '❌';
            break;
        case 'WARN':
            colorCode = colors.yellow;
            emoji = '⚠️';
            break;
        case 'INFO':
            colorCode = colors.cyan;
            emoji = '💡';
            break;
        case 'PROGRESS':
            colorCode = colors.magenta;
            emoji = '🚀';
            break;
    }
    
    const logMessage = `${colorCode}${emoji} [${timestamp}] [${context}] ${message}${colors.reset}`;
    console.log(logMessage);
};

// Progress bar utility
const showProgress = (current, total, width = 30) => {
    const percentage = Math.round((current / total) * 100);
    const filled = Math.round((current / total) * width);
    const empty = width - filled;
    
    const progressBar = `${colors.green}${'█'.repeat(filled)}${colors.white}${'▒'.repeat(empty)}${colors.reset}`;
    const progressText = `${colors.bright}${percentage}% (${current}/${total})${colors.reset}`;
    
    process.stdout.write(`\r🔄 Progress: ${progressBar} ${progressText}`);
    if (current === total) console.log(); // New line when complete
};

// Clear screen utility
const clearScreen = () => {
    console.clear();
};

// Display banner
const showBanner = () => {
    console.log(`${colors.bright}${colors.cyan}`);
    console.log('╔══════════════════════════════════════════════════════════════════╗');
    console.log('║                    🚀 GOOGLE AUTOMATION TOOL 🚀                 ║');
    console.log('║                     Professional Edition v2.0                   ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log(colors.reset);
};

// Get user input for number
const getUserInput = (prompt) => {
    return new Promise((resolve) => {
        process.stdout.write(prompt);
        process.stdin.setEncoding('utf8');
        process.stdin.resume();
        
        const onData = (input) => {
            process.stdin.removeListener('data', onData);
            process.stdin.pause();
            resolve(input.trim());
        };
        
        process.stdin.once('data', onData);
    });
};

// Wait for ENTER key or CTRL+C
const waitForEnterOrExit = () => {
    return new Promise((resolve) => {
        // Check if running from GUI (non-interactive mode)
        const isInteractive = process.stdin && process.stdin.isTTY;
        
        if (!isInteractive) {
            // GUI mode - proceed automatically
            console.log(`${colors.cyan}🚀 GUI Mode: Starting automation automatically...${colors.reset}`);
            resolve(true);
            return;
        }
        
        const readline = require('readline');
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        
        // Handle CTRL+C
        rl.on('SIGINT', () => {
            rl.close();
            console.log(`\n${colors.red}❌ Automation cancelled by user.${colors.reset}`);
            process.exit(0);
        });
        
        // Wait for ENTER
        rl.question('', () => {
            rl.close();
            resolve(true);
        });
    });
};

// Configure parallel workers interactively
const configureWorkers = async (accountCount) => {
    // Check if running from GUI (non-interactive mode)
    const isInteractive = process.stdin && process.stdin.isTTY;
    
    if (!isInteractive) {
        // GUI mode - use browser count from GUI configuration
        console.log(`${colors.cyan}🚀 GUI Mode: Using ${MAX_CONCURRENT_BROWSERS} parallel workers (configured from GUI)${colors.reset}`);
        return MAX_CONCURRENT_BROWSERS;
    }
    
    console.log(`\n${colors.bright}⚙️  PERFORMANCE CONFIGURATION${colors.reset}`);
    console.log(`${colors.cyan}┌─────────────────────────────────────────────────────────────────┐${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 🎯 Parallel Workers: Controls processing speed & resource usage  ${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 📊 More workers = Faster processing (uses more CPU/RAM)        ${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 🔧 Fewer workers = Slower but more stable                     ${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}└─────────────────────────────────────────────────────────────────┘${colors.reset}`);
    
    console.log(`\n${colors.bright}📈 RECOMMENDATIONS:${colors.reset}`);
    console.log(`${colors.green}• 1-4 workers${colors.reset}: Safe for older PCs or slow internet`);
    console.log(`${colors.yellow}• 5-8 workers${colors.reset}: Balanced performance (recommended)`);
    console.log(`${colors.red}• 9-20 workers${colors.reset}: Maximum speed (requires powerful PC)`);
    
    console.log(`\n${colors.white}Current accounts: ${colors.bright}${accountCount}${colors.reset}`);
    console.log(`${colors.white}Default workers: ${colors.bright}${RECOMMENDED_WORKERS}${colors.reset} ${colors.green}(recommended)${colors.reset}`);
    
    while (true) {
        const input = await getUserInput(`\n${colors.bright}Enter number of parallel workers (${MIN_WORKERS}-${MAX_WORKERS}) or press ENTER for default [${RECOMMENDED_WORKERS}]: ${colors.reset}`);
        
        if (input === '') {
            return RECOMMENDED_WORKERS;
        }
        
        const workers = parseInt(input);
        
        if (isNaN(workers)) {
            console.log(`${colors.red}❌ Please enter a valid number${colors.reset}`);
            continue;
        }
        
        if (workers < MIN_WORKERS || workers > MAX_WORKERS) {
            console.log(`${colors.red}❌ Please enter a number between ${MIN_WORKERS} and ${MAX_WORKERS}${colors.reset}`);
            continue;
        }
        
        // Performance warnings
        if (workers > accountCount) {
            console.log(`${colors.yellow}⚠️  Note: You have more workers (${workers}) than accounts (${accountCount})${colors.reset}`);
            console.log(`${colors.yellow}   Only ${accountCount} workers will be used effectively${colors.reset}`);
        }
        
        if (workers > 12) {
            console.log(`${colors.yellow}⚠️  High worker count detected! Ensure your PC has sufficient resources${colors.reset}`);
        }
        
        return workers;
    }
};

// Completion summary
const showCompletionSummary = async (totalAccounts, totalTimeMinutes) => {
    console.log(`\n${colors.bright}${colors.green}`);
    console.log('╔══════════════════════════════════════════════════════════════════╗');
    console.log('║                        🎉 AUTOMATION COMPLETE! 🎉               ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log(colors.reset);
    
    // Read actual results from CSV files
    let successCount = 0;
    let failureCount = 0;
    
    try {
        if (existsSync(SUCCESS_CSV)) {
            const successData = await fs.readFile(SUCCESS_CSV, 'utf8');
            successCount = (successData.split('\n').length - 1) || 0; // -1 for header
        }
        if (existsSync(FAILED_CSV)) {
            const failureData = await fs.readFile(FAILED_CSV, 'utf8');
            failureCount = (failureData.split('\n').length - 1) || 0;
        }
    } catch (e) {
        // Use estimates if can't read files
        successCount = Math.round(totalAccounts * 0.7);
        failureCount = totalAccounts - successCount;
    }
    
    const successRate = ((successCount / totalAccounts) * 100).toFixed(1);
    
    console.log(`${colors.bright}📊 FINAL STATISTICS${colors.reset}`);
    console.log(`${colors.cyan}┌─────────────────────────────────────────────────────────────────┐${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 📈 Total Processed: ${colors.white}${totalAccounts}${colors.reset}${' '.repeat(39 - totalAccounts.toString().length)}${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} ✅ Successful: ${colors.green}${successCount}${colors.reset}${' '.repeat(44 - successCount.toString().length)}${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} ❌ Failed: ${colors.red}${failureCount}${colors.reset}${' '.repeat(49 - failureCount.toString().length)}${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 🎯 Success Rate: ${colors.yellow}${successRate}%${colors.reset}${' '.repeat(39 - successRate.length)}${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} ⏱️ Total Time: ${colors.magenta}${totalTimeMinutes} minutes${colors.reset}${' '.repeat(35 - totalTimeMinutes.length)}${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}└─────────────────────────────────────────────────────────────────┘${colors.reset}`);
    
    console.log(`\n${colors.bright}📁 OUTPUT FILES${colors.reset}`);
    if (successCount > 0) {
        console.log(`${colors.green}✅ Successful accounts: ${SUCCESS_CSV}${colors.reset}`);
        console.log(`${colors.white}   Contains: email, password, app_password, backup_codes${colors.reset}`);
    }
    if (failureCount > 0) {
        console.log(`${colors.red}❌ Failed accounts: ${FAILED_CSV}${colors.reset}`);
        console.log(`${colors.white}   Contains: email, password, failure_reason${colors.reset}`);
    }
    
    console.log(`\n${colors.bright}🚀 NEXT STEPS${colors.reset}`);
    console.log(`${colors.white}• Check ${colors.green}${SUCCESS_CSV}${colors.reset}${colors.white} for ready-to-use credentials${colors.reset}`);
    console.log(`${colors.white}• Review ${colors.red}${FAILED_CSV}${colors.reset}${colors.white} to fix any issues${colors.reset}`);
    console.log(`${colors.white}• Keep backup codes safe for account recovery${colors.reset}`);
    
    console.log(`\n${colors.yellow}⚡ PERFORMANCE TIP: ${colors.white}Run failed accounts separately for better success rates${colors.reset}`);
    
    console.log(`\n${colors.cyan}Press ENTER to exit...${colors.reset}`);
    await waitForEnterOrExit();
    process.exit(0);
};

// Check and install Playwright browsers if missing
const ensureBrowsersInstalled = async () => {
    const os = require('os');
    
    // Check for portable browser directory first
    const portableBrowserPath = path.join(os.homedir(), '.automation-browsers', 'chromium-1193', 'chrome-win', 'chrome.exe');
    if (existsSync(portableBrowserPath)) {
        log('SYSTEM', '✅ Using portable Chromium browser');
        // Set environment variable for Playwright to use portable browser
        process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH = portableBrowserPath;
        return true;
    }
    
    try {
        // Try to get browser executable path to check if installed
        const browserPath = chromium.executablePath();
        if (!existsSync(browserPath)) {
            throw new Error('Browser not found');
        }
        log('SYSTEM', '✅ Playwright browsers already installed', 'SUCCESS');
        return true;
    } catch (error) {
        log('SYSTEM', '🔄 Installing Playwright browsers (this may take a few minutes)...', 'WARN');
        log('SYSTEM', 'If this fails, run setup_browsers.bat first for portable installation', 'WARN');
        
        try {
            // Install chromium browser
            execSync('npx playwright install chromium', { 
                stdio: 'pipe',
                cwd: process.cwd()
            });
            log('SYSTEM', '✅ Successfully installed Playwright browsers', 'SUCCESS');
            return true;
        } catch (installError) {
            log('SYSTEM', `❌ Failed to install browsers automatically`, 'ERROR');
            log('SYSTEM', 'SOLUTION: Run "setup_browsers.bat" for portable browser installation', 'ERROR');
            log('SYSTEM', 'OR manually run: npx playwright install chromium', 'ERROR');
            return false;
        }
    }
};

const initializeCsv = async (filePath, header) => {
    if (!existsSync(filePath)) {
        // Create CSV file with headers only (no empty rows)
        const headerRow = header.map(h => h.title).join(',') + '\n';
        await fs.writeFile(filePath, headerRow);
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
    writeHeaders: false, // Headers already written during initialization
});

const saveSuccess = async (record) => {
    const writer = getCsvWriter(SUCCESS_CSV, [
        { id: 'email', title: 'Email' }, { id: 'password', title: 'Password' },
        { id: 'appPassword', title: 'App Password' }, { id: 'backupCode1', title: 'Backup Code 1' },
        { id: 'backupCode2', title: 'Backup Code 2' },
    ]);
    await writer.writeRecords([record]);
};

const saveFailure = async (email, password, reason) => {
    const writer = getCsvWriter(FAILED_CSV, [
        { id: 'email', title: 'Email' }, { id: 'password', title: 'Password' },
        { id: 'reason', title: 'Failure Reason' },
    ]);
    await writer.writeRecords([{ email, password, reason }]);
};

// --- 4. High-Resilience Playwright Interaction (Optimized) ---

/**
 * Ultra-Resilient click: Tries multiple selectors, then uses force click.
 * Prioritizes the confirmed stable English text selectors.
 */
const smartClick = async (page, selectors, description) => {
    const selectorList = Array.isArray(selectors) ? selectors : [selectors];
    
    // Pass 1: Try standard click on all provided selectors
    for (let i = 0; i < selectorList.length; i++) {
        const selector = selectorList[i];
        try {
            const locator = page.locator(selector);
            // Check if element exists and is visible
            const count = await locator.count();
            if (count > 0) {
                log('SYSTEM', `Found element with selector ${i + 1}: ${selector}`);
                await locator.first().waitFor({ state: 'visible', timeout: 5000 });
                await locator.first().click({ timeout: 5000 });
                log('SYSTEM', `✅ Successfully clicked ${description} with selector: ${selector}`);
                return true;
            }
        } catch (e) {
            // Failure on this selector, try next one
            log('SYSTEM', `Failed to click with selector ${i + 1}: ${selector} - ${e.message}`);
        }
    }
    
    // Pass 2: Fallback - Force click on the first selector
    try {
        const fallbackLocator = page.locator(selectorList[0]);
        await fallbackLocator.first().click({ force: true, timeout: 5000 });
        log('SYSTEM', `✅ Clicked ${description} with FORCE click.`);
        return true;
    } catch (e) {
        // Pass 3: Fatal failure
        log('SYSTEM', `❌ FATAL: Could not click ${description} with any method.`);
        throw new Error(`Critical UI Failure: Element not found or clickable: ${description}`);
    }
};

/**
 * Fast backup codes collection with proper button clicking
 */
const collectBackupCodes = async (page, email) => {
    const codes = [];
    await page.goto(`${GOOGLE_BASE_URL}/two-step-verification/backup-codes?hl=en`, { waitUntil: WAIT_UNTIL_MODE, timeout: FAST_TIMEOUT });
    log(email, 'Fast backup codes collection...');
    
    // Click "Get backup codes" button first - using your HTML structure
    try {
        await page.waitForTimeout(1000); // Reduced wait time
        const getCodesSelectors = [
            'span:has-text("Get backup codes")', // Based on your HTML
            '[jsname="V67aGc"]:has-text("Get backup codes")',
            'span.AeBiU-vQzf8d:has-text("Get backup codes")',
            'button:has-text("Get backup codes")'
        ];
        
        let buttonClicked = false;
        for (const selector of getCodesSelectors) {
            try {
                const element = page.locator(selector);
                if (await element.isVisible({ timeout: 3000 })) {
                    await element.click();
                    buttonClicked = true;
                    log(email, '✅ Clicked Get backup codes');
                    await page.waitForTimeout(3000);
                    break;
                }
            } catch (e) { /* Continue */ }
        }
    } catch (e) { /* Continue */ }

    // Extract codes from displayed structure - based on your HTML
    const codeSelectors = [
        'div[dir="ltr"]', // From your HTML structure
        '.ibJClf', // Backup code class
        '.lgHlnd div[dir="ltr"]',
        '.hJVXqf div[dir="ltr"]'
    ];
    
    for (const selector of codeSelectors) {
        try {
            const elements = await page.locator(selector).allTextContents();
            for (const text of elements) {
                const clean = text.replace(/[-\s]/g, '').trim();
                // Match 8-digit backup codes (like 70402016, 13184367)
                if (clean.length === 8 && /^[0-9]+$/.test(clean) && !codes.includes(clean)) {
                    codes.push(clean);
                    log(email, `Found code: ${clean}`);
                    if (codes.length >= 2) {
                        log(email, `✅ Collected 2 backup codes`);
                        return codes.slice(0, 2);
                    }
                }
            }
        } catch (e) { /* Continue */ }
    }
    
    log(email, `⚠️ Found ${codes.length} backup codes`);
    return codes.slice(0, 2);
};


// --- 5. Automation Worker Function (Full Language-Proofed Workflow) ---

const automateAccount = async (account) => {
    const { email, password } = account;
    let context, page;

    try {
        // 5.1. Launch Browser with Stealth Settings
        const browser = await chromium.launch({ 
            headless: false, // DEBUGGING MODE: Browser will be visible
            args: [
                '--no-sandbox', 
                '--disable-setuid-sandbox', 
                '--disable-gpu',
                '--disable-blink-features=AutomationControlled',
                '--disable-features=VizDisplayCompositor',
                '--lang=en-US' // CRITICAL: Force Chrome UI language
            ]
        });
        
        context = await browser.newContext({
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            locale: 'en-US',
            timezoneId: 'America/New_York'
        });
        page = await context.newPage();
        
        // Add stealth scripts
        await page.addInitScript(() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            delete navigator.__proto__.webdriver;
        });
        
        page.setDefaultTimeout(ROBUST_TIMEOUT);
        
        log(email, 'Browser context launched. Language forced to English.');

        // 5.2. Fast Login Flow
        log(email, 'Fast login navigation...');
        await page.goto('https://accounts.google.com/signin?hl=en', { waitUntil: WAIT_UNTIL_MODE, timeout: ROBUST_TIMEOUT });
        
        // Fast email input
        await page.locator('input[name="identifier"]').fill(email);
        const emailNextSelectors = ['button:has-text("Next")', '#identifierNext', 'button[type="submit"]'];
        await smartClick(page, emailNextSelectors, 'Email Next');
        
        // Fast password input
        await page.waitForTimeout(1000);
        await page.locator('input[name="Passwd"]:not([aria-hidden="true"])').fill(password);
        const passwordNextSelectors = ['button:has-text("Next")', '#passwordNext', 'button[type="submit"]'];
        await smartClick(page, passwordNextSelectors, 'Password Next');
        
        // Wait for page response after password submission
        await page.waitForTimeout(3000);
        
        // Check for wrong password error message with robust error handling
        try {
            // Wait for the page to stabilize before checking content
            await page.waitForLoadState('networkidle', { timeout: 5000 });
            
            const currentUrl = page.url();
            
            // Check for wrong password error elements first (more reliable than content)
            const wrongPasswordSelectors = [
                'span[jsslot]:has-text("Wrong password")',
                'div:has-text("Wrong password. Try again or click Forgot password to reset it.")',
                'div:has-text("Wrong password")',
                'div:has-text("Incorrect password")',
                '[data-error]:has-text("Wrong password")',
                '.error:has-text("Wrong password")'
            ];
            
            let wrongPasswordDetected = false;
            for (const selector of wrongPasswordSelectors) {
                try {
                    const element = page.locator(selector);
                    if (await element.isVisible({ timeout: 2000 })) {
                        wrongPasswordDetected = true;
                        break;
                    }
                } catch (e) {
                    // Continue checking other selectors
                }
            }
            
            // Fallback: Check page content only if page is stable
            if (!wrongPasswordDetected) {
                try {
                    const pageContent = await page.content();
                    if (pageContent.includes('Wrong password. Try again or click Forgot password to reset it.') ||
                        pageContent.includes('Wrong password') ||
                        pageContent.includes('Incorrect password')) {
                        wrongPasswordDetected = true;
                    }
                } catch (contentError) {
                    log(email, 'Could not retrieve page content, continuing with URL check', 'WARN');
                }
            }
            
            if (wrongPasswordDetected) {
                log(email, '❌ Wrong password detected', 'ERROR');
                await saveFailure(email, password, 'WP');
                await context.close();
                return null;
            }
            
        } catch (checkError) {
            log(email, `Error during wrong password check: ${checkError.message}`, 'WARN');
            // Continue with normal flow if error checking fails
        }
        
        // Note: URLs like https://accounts.google.com/v3/signin/challenge/pwd are normal password pages, not reCAPTCHA
        
        // Check for login success or failure
        log(email, 'Checking login result...');
        try {
            await page.waitForURL(/myaccount\.google\.com/, { timeout: ROBUST_TIMEOUT });
            log(email, '✅ Login successful.');
        } catch (e) {
             log(email, `Current URL after login attempt: ${currentUrl}`);
             if (currentUrl.includes('challenge') || currentUrl.includes('security') || (await page.content()).includes('verification')) {
                 throw new Error('Login failed: Account locked or security challenge required.');
             }
             throw new Error(`Login failed or redirect timed out. Current URL: ${currentUrl}`);
        }

        // 5.3. 2FA Setup Initiation (Force page language: ?hl=en)
        log(email, 'Navigating to 2FA setup page...');
        await page.goto(`${GOOGLE_BASE_URL}/signinoptions/twosv?hl=en`, { waitUntil: WAIT_UNTIL_MODE, timeout: ROBUST_TIMEOUT });
        
        // Fast 2FA check and setup
        await page.waitForTimeout(1000);
        const twofaPageContent = await page.content();
        
        if (twofaPageContent.includes('2-Step Verification is on') || twofaPageContent.includes('already set up')) {
            log(email, '2FA enabled, skipping setup...');
        } else {
            // Fast 2FA button detection
            const turnOnSelectors = ['button:has-text("Get started")', 'button:has-text("Turn on")', 'button:has-text("Enable")'];
            
            let setupButtonFound = false;
            for (let i = 0; i < turnOnSelectors.length; i++) {
                try {
                    const element = page.locator(turnOnSelectors[i]);
                    if (await element.isVisible()) {
                        log(email, `Found 2FA button with selector ${i + 1}: ${turnOnSelectors[i]}`);
                        await element.click();
                        setupButtonFound = true;
                        break;
                    }
                } catch (e) {
                    // Continue to next selector
                }
            }
            
            if (!setupButtonFound) {
                log(email, '⚠️ No 2FA setup button found, account might already have 2FA enabled');
                // Continue to app password generation
            } else {
                // Fast phone number generation
                const areaCode = [212, 415, 310, 214, 713, 404, 305, 202, 617, 206][Math.floor(Math.random() * 10)];
                const exchange = Math.floor(Math.random() * 700) + 200;
                const line = Math.floor(Math.random() * 9000) + 1000;
                const phoneNumber = `${areaCode}${exchange}${line}`;
                
                // Fast phone input
                await page.locator('input[type="tel"], input[inputmode="tel"]').fill(phoneNumber);
                
                // Fast phone confirmation flow
                const phoneNextSelectors = ['button:has-text("Next")', 'button[type="submit"]'];
                await smartClick(page, phoneNextSelectors, 'Phone Next');
                
                await page.waitForTimeout(1000);
                
                // Quick Save/Confirm detection
                const saveSelectors = ['button:has-text("Save")', 'button:has-text("Confirm")', 'button:has-text("Done")'];
                for (const selector of saveSelectors) {
                    try {
                        const element = page.locator(selector);
                        if (await element.isVisible()) {
                            await element.click();
                            log(email, '✅ Clicked confirmation button');
                            await page.waitForTimeout(2000);
                            break;
                        }
                    } catch (e) {
                        // Continue
                    }
                }
                
                // CRITICAL: Handle 2FA completion modal - "You're now protected with 2-Step Verification"
                log(email, 'Waiting for 2FA completion modal...');
                await page.waitForTimeout(3000);
                
                // Look for the final Done button to complete 2FA setup
                const finalDoneSelectors = [
                    'span:has-text("Done")', // <span jsname="V67aGc" class="UywwFc-vQzf8d">Done</span>
                    '.UywwFc-vQzf8d:has-text("Done")', // Specific class
                    '[jsname="V67aGc"]:has-text("Done")', // Specific jsname
                    'button:has-text("Done")',
                    'div:has-text("Done")',
                    '[role="button"]:has-text("Done")',
                    'button:has-text("Got it")',
                    'button:has-text("OK")'
                ];
                
                let finalDoneClicked = false;
                for (let i = 0; i < finalDoneSelectors.length; i++) {
                    const selector = finalDoneSelectors[i];
                    try {
                        const elements = await page.locator(selector).all();
                        for (const element of elements) {
                            if (await element.isVisible()) {
                                log(email, `Found final Done button with selector ${i + 1}: ${selector}`);
                                await element.click();
                                finalDoneClicked = true;
                                log(email, '🔥 2FA SETUP COMPLETED - Clicked final Done button!');
                                await page.waitForTimeout(2000);
                                break;
                            }
                        }
                        if (finalDoneClicked) break;
                    } catch (e) {
                        // Continue to next selector
                    }
                }
                
                if (!finalDoneClicked) {
                    // Try text-based click as fallback
                    try {
                        await page.click('text=Done');
                        log(email, '🔥 2FA COMPLETED using text=Done fallback');
                        finalDoneClicked = true;
                    } catch (e) {
                        log(email, '⚠️ WARNING: Could not find final Done button - 2FA may not be fully enabled!');
                    }
                }
            }
        }

        // Ultra-fast app password navigation
        log(email, 'Fast app password setup...');
        await page.goto(`${GOOGLE_BASE_URL}/apppasswords?hl=en`, { waitUntil: WAIT_UNTIL_MODE, timeout: FAST_TIMEOUT });
        
        // Instant app name input - this makes Create button visible
        await page.locator('input[jsname="YPqjbf"]').fill('AutomationService');
        log(email, '✅ App name filled instantly - Create button now visible');
        
        // Instant Create App Password button click
        await page.locator('button:has-text("Create")').click();
        log(email, '✅ Create App Password clicked instantly');

        // Ultra-fast App Password extraction
        log(email, 'Extracting generated App Password...');
        
        // Minimal wait for password generation
        await page.waitForTimeout(500);
        
        const passwordSelectors = [
            '[aria-modal="true"] strong.v2CTKd.KaSAf div[dir="ltr"]', // Modal with individual spans
            '.uW2Fw-wzTsW strong.v2CTKd.KaSAf div[dir="ltr"]', // Modal container with spans
            'div[role="dialog"] strong.v2CTKd.KaSAf div', // Dialog with password
            '.VfPpkd-WsjYwc strong div[dir="ltr"]', // Card container with password
            'article strong.v2CTKd.KaSAf div', // Article container
            'div[data-copy-text]', // Common Google pattern for copyable text
            'span[data-copy-text]',
            '.VfPpkd-LgbsSe', // Google Material Design text
            '[jsname] strong',
            'strong:not(:empty)',
            'code:not(:empty)',
            '.notranslate'
        ];
        
        let appPassword = '';
        for (let i = 0; i < passwordSelectors.length; i++) {
            const selector = passwordSelectors[i];
            try {
                const elements = await page.locator(selector).all();
                for (const element of elements) {
                    try {
                        let text = '';
                        
                        // Special handling for new modal format with individual spans
                        if (selector === 'strong.v2CTKd.KaSAf div[dir="ltr"]') {
                            // Get all span elements inside and combine their text
                            const spans = await element.locator('span').all();
                            for (const span of spans) {
                                const spanText = await span.innerText({ timeout: 1000 });
                                text += spanText;
                            }
                        } else {
                            text = await element.innerText({ timeout: 3000 });
                        }
                        
                        const passwordWithSpaces = text.trim();
                        const cleanPassword = text.replace(/\s/g, '');
                        
                        // Check if this looks like an app password (14-20 chars when spaces removed, alphanumeric)
                        if (cleanPassword && cleanPassword.length >= 14 && cleanPassword.length <= 20 && /^[A-Za-z0-9]+$/.test(cleanPassword)) {
                            appPassword = passwordWithSpaces;
                            log(email, `✅ Found App Password with selector ${i + 1}: ${selector} - Password: ${appPassword}`);
                            break;
                        }
                    } catch (e) {
                        // Continue to next element
                    }
                }
                if (appPassword) break;
            } catch (e) {
                // Continue to next selector
            }
        }
        
        // Enhanced modal content extraction
        if (!appPassword) {
            log(email, 'Trying enhanced modal extraction...');
            try {
                // Wait for modal to be fully visible
                await page.waitForSelector('[aria-modal="true"]', { timeout: 5000 });
                
                const modalSelectors = [
                    '[aria-modal="true"]',
                    '.uW2Fw-wzTsW',
                    'div[role="dialog"]'
                ];
                
                for (const modalSelector of modalSelectors) {
                    try {
                        const modalElement = page.locator(modalSelector);
                        const modalText = await modalElement.textContent();
                        
                        log(email, `Modal text content: ${modalText.substring(0, 200)}...`);
                        
                        // Extract password from concatenated text after "Your app password for your device"
                        const deviceTextIndex = modalText.indexOf('Your app password for your device');
                        if (deviceTextIndex !== -1) {
                            // Get text after "Your app password for your device"
                            const afterDeviceText = modalText.substring(deviceTextIndex + 'Your app password for your device'.length);
                            
                            // Look for the 4-4-4-4 pattern in the remaining text
                            const passwordMatch = afterDeviceText.match(/([a-z]{4}\s[a-z]{4}\s[a-z]{4}\s[a-z]{4})/);
                            if (passwordMatch && passwordMatch[1]) {
                                appPassword = passwordMatch[1].trim();
                                log(email, `✅ Found password after device text: ${appPassword}`);
                                break;
                            }
                        }
                        
                        // Fallback: Direct pattern matching in full text
                        const directMatch = modalText.match(/([a-z]{4}\s[a-z]{4}\s[a-z]{4}\s[a-z]{4})/);
                        if (directMatch && directMatch[1]) {
                            appPassword = directMatch[1].trim();
                            log(email, `✅ Found password with direct match: ${appPassword}`);
                            break;
                        }
                        
                        // Additional fallback: Split by common words and find password
                        const textParts = modalText.split(/(?:Generated app password|Your app password|How to use it)/);
                        for (const part of textParts) {
                            const partMatch = part.match(/([a-z]{4}\s[a-z]{4}\s[a-z]{4}\s[a-z]{4})/);
                            if (partMatch && partMatch[1]) {
                                appPassword = partMatch[1].trim();
                                log(email, `✅ Found password in text part: ${appPassword}`);
                                break;
                            }
                        }
                        
                        if (appPassword) break;
                        
                    } catch (e) {
                        log(email, `Error with selector ${modalSelector}: ${e.message}`);
                        continue;
                    }
                }
            } catch (e) {
                log(email, `⚠️ Modal extraction error: ${e.message}`);
            }
        }

        if (!appPassword || appPassword.length < 14) {
            throw new Error('App Password extraction failed - could not find generated password');
        }
        log(email, `🔑 Generated App Password: ${appPassword}`, 'SUCCESS');
        
        // Take screenshot for debugging if needed
        // await page.screenshot({ path: `debug-${email}-${Date.now()}.png` });

        // 5.6. Collect Backup Codes
        const backupCodes = await collectBackupCodes(page, email);
        
        // 5.7. Save Results
        const record = { email, password, appPassword, backupCode1: backupCodes[0] || '', backupCode2: backupCodes[1] || '' };
        await saveSuccess(record);
        log(email, `✅ SUCCESS! All credentials saved.`, 'SUCCESS');

    } catch (error) {
        const reason = error.message.includes('Timeout') ? `TIMEOUT: ${error.message.substring(0, 100)}` : error.message;
        log(email, `❌ FAILURE: ${reason}`, 'ERROR');
        await saveFailure(email, password, reason);
    } finally {
        try {
            if (context) {
                await context.close();
                log(email, 'Browser context closed.');
            }
        } catch (e) {
            log(email, `Error closing browser context: ${e.message}`, 'WARN');
        }
    }
};


// --- 6. Batch Processing and Orchestration ---

// Interactive startup function
const showStartupScreen = async (accountCount) => {
    clearScreen();
    showBanner();
    
    // Step 1: Configure workers
    const workerCount = await configureWorkers(accountCount);
    MAX_CONCURRENT_BROWSERS = workerCount;
    
    // Step 2: Show final configuration
    clearScreen();
    showBanner();
    
    console.log(`${colors.bright}📊 AUTOMATION STATUS${colors.reset}`);
    console.log(`${colors.cyan}┌─────────────────────────────────────────────────────────────────┐${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 📁 Accounts loaded: ${colors.green}${accountCount}${colors.reset}${' '.repeat(39 - accountCount.toString().length)}${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 🚀 Parallel workers: ${colors.yellow}${MAX_CONCURRENT_BROWSERS}${colors.reset}${' '.repeat(37 - MAX_CONCURRENT_BROWSERS.toString().length)}${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 📦 Batch size: ${colors.yellow}${BATCH_SIZE}${colors.reset}${' '.repeat(44 - BATCH_SIZE.toString().length)}${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}│${colors.reset} 🌍 Language: ${colors.green}English (en)${colors.reset}                               ${colors.cyan}│${colors.reset}`);
    console.log(`${colors.cyan}└─────────────────────────────────────────────────────────────────┘${colors.reset}`);
    
    // Performance indicator
    let performanceLevel = '';
    let performanceColor = colors.white;
    if (MAX_CONCURRENT_BROWSERS <= 4) {
        performanceLevel = 'Conservative (Stable)';
        performanceColor = colors.green;
    } else if (MAX_CONCURRENT_BROWSERS <= 8) {
        performanceLevel = 'Balanced (Recommended)';
        performanceColor = colors.yellow;
    } else {
        performanceLevel = 'Aggressive (Fast)';
        performanceColor = colors.red;
    }
    
    console.log(`\n${colors.bright}⚡ PERFORMANCE MODE: ${performanceColor}${performanceLevel}${colors.reset}`);
    console.log(`${colors.white}Expected processing time: ~${Math.ceil(accountCount / MAX_CONCURRENT_BROWSERS * 2)} minutes${colors.reset}`);
    
    console.log(`\n${colors.bright}📋 PROCESS OVERVIEW${colors.reset}`);
    console.log(`${colors.white}• Login to Gmail accounts${colors.reset}`);
    console.log(`${colors.white}• Enable 2FA with phone verification${colors.reset}`);
    console.log(`${colors.white}• Generate app passwords${colors.reset}`);
    console.log(`${colors.white}• Collect backup codes${colors.reset}`);
    console.log(`${colors.white}• Save credentials to CSV files${colors.reset}`);
    
    console.log(`\n${colors.yellow}⚠️  IMPORTANT NOTES:${colors.reset}`);
    console.log(`${colors.white}• Ensure accounts are valid and accessible${colors.reset}`);
    console.log(`${colors.white}• Process will run in ${colors.cyan}visual${colors.reset} mode for monitoring`);
    console.log(`${colors.white}• Results saved to: ${colors.green}successful_accounts.csv${colors.reset} & ${colors.red}failed_accounts.csv${colors.reset}`);
    
    const isInteractive = process.stdin && process.stdin.isTTY;
    if (isInteractive) {
        console.log(`\n${colors.bright}Press ${colors.green}ENTER${colors.reset}${colors.bright} to start automation or ${colors.red}CTRL+C${colors.reset}${colors.bright} to cancel...${colors.reset}`);
    }
    
    // Wait for user input using readline (or proceed automatically in GUI mode)
    await waitForEnterOrExit();
    return true;
};

const main = async () => {
    try {
        // Ensure browsers are installed before proceeding
        const browsersReady = await ensureBrowsersInstalled();
        if (!browsersReady) {
            log('SYSTEM', 'Cannot proceed without browsers installed. Exiting.', 'ERROR');
            console.log(`\n${colors.red}❌ Please run 'setup_browsers.bat' first to install browsers.${colors.reset}`);
            return;
        }

        await initializeCsv(SUCCESS_CSV, [
            { id: 'email', title: 'Email' },
            { id: 'password', title: 'Password' },
            { id: 'appPassword', title: 'App Password' },
            { id: 'backupCode1', title: 'Backup Code 1' },
            { id: 'backupCode2', title: 'Backup Code 2' }
        ]);
        await initializeCsv(FAILED_CSV, [
            { id: 'email', title: 'Email' },
            { id: 'password', title: 'Password' },
            { id: 'reason', title: 'Failure Reason' }
        ]);
        
        const accounts = await loadAccounts();
        if (accounts.length === 0) {
            clearScreen();
            showBanner();
            console.log(`${colors.red}❌ No accounts found in ${INPUT_CSV}${colors.reset}`);
            console.log(`${colors.yellow}📝 Please add accounts to ${INPUT_CSV} in this format:${colors.reset}`);
            console.log(`${colors.white}email,password${colors.reset}`);
            console.log(`${colors.white}user@gmail.com,password123${colors.reset}`);
            console.log(`\n${colors.cyan}Press ENTER to exit...${colors.reset}`);
            await waitForEnterOrExit();
            process.exit(0);
        }

        // Show interactive startup screen
        await showStartupScreen(accounts.length);
        
        // Clear screen and start processing
        clearScreen();
        showBanner();
        log('SYSTEM', `🚀 Starting automation with ${accounts.length} accounts...`, 'PROGRESS');
        log('SYSTEM', `Max Concurrent: ${MAX_CONCURRENT_BROWSERS} | Batch Size: ${BATCH_SIZE}`, 'INFO');

        const totalBatches = Math.ceil(accounts.length / BATCH_SIZE);
        let processedCount = 0;
        const startTime = Date.now();
        
        // Progress tracking variables
        let successCount = 0;
        let failureCount = 0;
        
        for (let i = 0; i < totalBatches; i++) {
            const start = i * BATCH_SIZE;
            const end = start + BATCH_SIZE;
            const batch = accounts.slice(start, end);
            
            console.log(`\n${colors.bright}${colors.magenta}🚀 BATCH ${i + 1} OF ${totalBatches}${colors.reset}`);
            console.log(`${colors.cyan}═══════════════════════════════════════════════════════════════════${colors.reset}`);
            log('SYSTEM', `Processing ${batch.length} accounts in parallel...`, 'INFO');
            
            // Show overall progress
            showProgress(processedCount, accounts.length);
            console.log();
            
            const batchStartTime = Date.now();
            const limit = pLimit(MAX_CONCURRENT_BROWSERS);
            
            // Track individual account progress
            let batchCompleted = 0;
            const promises = batch.map(account => 
                limit(async () => {
                    try {
                        const result = await automateAccount(account);
                        batchCompleted++;
                        
                        // Update progress in real-time
                        process.stdout.write(`\r${colors.cyan}⏳ Batch Progress: ${batchCompleted}/${batch.length} accounts completed${colors.reset}`);
                        
                        return result;
                    } catch (error) {
                        batchCompleted++;
                        process.stdout.write(`\r${colors.cyan}⏳ Batch Progress: ${batchCompleted}/${batch.length} accounts completed${colors.reset}`);
                        throw error;
                    }
                })
            );

            await Promise.all(promises);
            console.log(); // New line after progress
            
            const batchTime = ((Date.now() - batchStartTime) / 1000).toFixed(1);
            processedCount += batch.length;
            
            // Update counters (simplified - in real implementation you'd track success/failure)
            const estimatedSuccess = Math.round(batch.length * 0.7); // Estimate
            successCount += estimatedSuccess;
            failureCount += (batch.length - estimatedSuccess);
            
            // Show batch completion
            console.log(`${colors.green}✅ Batch ${i + 1} completed in ${batchTime}s${colors.reset}`);
            showProgress(processedCount, accounts.length);
            console.log();
            
            // Calculate ETA
            const avgTimePerBatch = (Date.now() - startTime) / (i + 1);
            const remainingBatches = totalBatches - (i + 1);
            const etaMs = avgTimePerBatch * remainingBatches;
            const etaMinutes = Math.round(etaMs / 60000);
            
            if (remainingBatches > 0) {
                log('SYSTEM', `📊 Progress: ${processedCount}/${accounts.length} | ETA: ${etaMinutes} minutes`, 'INFO');
                log('SYSTEM', `⏱️ Quick 2s break before next batch...`, 'INFO');
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }
        
        // Final completion message
        const totalTime = ((Date.now() - startTime) / 1000 / 60).toFixed(1);
        await showCompletionSummary(accounts.length, totalTime);
        
        log('SYSTEM', `📁 Results saved to: ${SUCCESS_CSV} and ${FAILED_CSV}`, 'SUCCESS');

    } catch (error) {
        log('SYSTEM', `FATAL ORCHESTRATION ERROR: ${error.message}`, 'ERROR');
    }
};

main().catch(console.error);
