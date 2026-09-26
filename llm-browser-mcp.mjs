#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// ── LLM Browser MCP v3 (Windows) ────────────────────────────────────────────
// Full-featured MCP server with persistent profiles, credential management,
// and complete browser surface. Everything a user can do, the LLM can do.
import { launchPersistentContext } from 'cloakbrowser';
import { writeFile, readFile, mkdir, readdir, rm, access, cp } from 'fs/promises';
import { dirname, join, basename } from 'path';
import { homedir } from 'os';
import { existsSync, appendFileSync } from 'fs';
import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import { sanitize, Verdict } from './injection-guard.mjs';
import { autoReport } from './auto-report.mjs';
import { elevateScanResult } from './elevate-alert.mjs';

const PROFILES_DIR = join(homedir(), '.llm-browser', 'profiles');
const runFile = promisify(execFile);
const QUARANTINE_LOG = join(homedir(), '.llm-browser', 'quarantine.jsonl');
// Profile used whenever no profile has been explicitly loaded. Without this,
// "no profile loaded" meant "no persistence at all" - see getPage(). A fresh
// server process always starts with _currentProfile === null, and nothing in
// the tool surface forces a profile load before navigating, so this is the
// path a casual "open the browser and log in" session actually takes.
const DEFAULT_PROFILE = 'default';
// Default profile lives in the cloakbrowser data dir, not under PROFILES_DIR.
// It is the only profile with the anti-detect Chromium's own storage layout,
// and it is where the primary Google identity is signed in once and reused.
const PROFILE_DIR_OVERRIDES = {
    [DEFAULT_PROFILE]: join(homedir(), '.cloakbrowser', 'google-profile'),
};
function _profileDir(name) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) throw new Error('Invalid profile name');
    return PROFILE_DIR_OVERRIDES[name] || join(PROFILES_DIR, name);
}
// Default/home page: a fresh session (or a brand-new profile with no
// restored tabs) opens here instead of a blank page.
const HOME_URL = 'https://www.google.com';

// ── Browser lifecycle ───────────────────────────────────────────────────────
let _browser = null, _context = null, _page = null;
let _currentProfile = null;  // name of active profile; null = not yet loaded, falls back to DEFAULT_PROFILE in getPage()
// Headed by default. This browser exists to be indistinguishable from a human
// one, and headless is the loudest signal there is — it defeats the entire
// point of the anti-detection layer. It also skips real compositing, so modals
// and animated dialogs can stay mounted but never paint: OpenRouter's verify
// dialog resolved as a real <button> that never became clickable, which reads
// as "the site blocked us" when it was simply never drawn.
// Set LLM_BROWSER_HEADLESS=1 for a genuinely unattended box with no desktop.
let _headed = process.env.LLM_BROWSER_HEADLESS !== '1';
const VIEWPORT = { width: 1920, height: 1080 };

async function _ensureProfilesDir() {
    await mkdir(PROFILES_DIR, { recursive: true });
}

function _launchOpts() {
    return {
        headless: !_headed,
        // Radeon/SwiftShader conflict crashes the renderer on real pages.
        // Software rendering costs nothing meaningful for automation workloads.
        args: ['--disable-gpu'],
        // Headed: let the page use the real window size.
        //
        // Forcing an explicit viewport pins innerWidth/innerHeight while the OS
        // window stays whatever size Chromium opened it at, producing
        // outerHeight < innerHeight — impossible on a real browser, where the
        // titlebar, tab strip and omnibox always make the outer window taller
        // than the viewport. It is a single-signal automation tell and was
        // measured here as 1920x1080 inner against 1920x858 outer.
        //
        // Every other fingerprint signal was already clean (webdriver false,
        // plugins present, spoofed hardware WebGL, no automation globals), so
        // this was the one thing giving the browser away.
        viewport: _headed ? null : VIEWPORT,
        locale: 'en-US',
        acceptDownloads: true,
        // NOT ignoring HTTPS errors by default, deliberately.
        //
        // It was set globally so the router's self-signed cert would not show
        // an interstitial. But this option disables certificate validation for
        // the whole context, and Cloudflare Turnstile depends on a normal TLS
        // path to load and attest its widget from challenges.cloudflare.com.
        // With validation off the widget cannot execute and the page reports
        // "The security check is unavailable" — which looks like being blocked
        // as a bot, but is the challenge failing to run at all. It broke every
        // Cloudflare-fronted site to spare one LAN device an interstitial.
        //
        // The router is handled per-profile instead: set
        // LLM_BROWSER_INSECURE_TLS=1 for a session that genuinely needs it.
        ignoreHTTPSErrors: process.env.LLM_BROWSER_INSECURE_TLS === '1',
        // Session-cookie survival is configured as a profile preference by
        // _enableSessionRestore(), NOT as a launch flag.
        //
        // `--restore-last-session` does preserve session cookies, but it also
        // makes Chromium attempt to hand off to an already-running instance of
        // the profile, which fails the launch outright with "Opening in
        // existing browser session" even when no such instance exists. Writing
        // `session.restore_on_startup = 1` into the profile's own Preferences
        // is what Chrome's "Continue where you left off" setting does, and it
        // achieves the same cookie behaviour without touching startup handoff.
    };
}

async function _gotoHome(page) {
    try {
        await page.goto(HOME_URL, { waitUntil: 'domcontentloaded', timeout: 15000 });
    } catch {
        // Home page unreachable (router offline, DNS, etc.) - leave the tab
        // on about:blank rather than fail session startup over it.
    }
}

// This used to branch: if a profile was explicitly loaded, go through
// _launchProfile (persistent); otherwise spin up a bare in-memory context
// (_browser.newContext with no userDataDir) and use that instead. That
// second branch is not "persistence with a bug" - a Playwright context with
// no userDataDir has nowhere on disk to write to, ever, no matter how
// cleanly it's closed. Since _currentProfile starts null on every process
// launch and nothing forces a profile load first, that branch was the one
// actually taken by an ordinary "open the browser, log in" session, which is
// why logins never stuck: they were never going anywhere durable in the
// first place. Every path through getPage() now goes through the same
// persistent-context launcher as an explicit llm_profile_load, falling back
// to a standing "default" profile instead of an ephemeral one.
async function getPage() {
    if (_page && !_page.isClosed?.()) return _page;
    return _launchProfile(_currentProfile || DEFAULT_PROFILE);
}

/**
 * Turn on Chrome's "Continue where you left off" for a profile.
 *
 * Chromium's cookie loader discards session-only cookies (no Max-Age/Expires)
 * on every launch unless session restore is enabled — and most sites issue
 * their primary auth cookie as a session cookie, so logins evaporate between
 * runs. The `--restore-last-session` flag also fixes this, but it makes
 * Chromium try to hand off to an existing instance of the profile and fail the
 * launch with "Opening in existing browser session". Setting the preference
 * directly gets the cookie behaviour with none of the startup handoff.
 */
async function _enableSessionRestore(profileDir) {
    const prefsPath = join(profileDir, 'Default', 'Preferences');
    let prefs = {};
    try {
        prefs = JSON.parse(await readFile(prefsPath, 'utf8'));
    } catch {
        // Brand-new profile: Chromium writes Preferences on first clean exit,
        // so seeding it here is what makes the very first session durable.
        await mkdir(dirname(prefsPath), { recursive: true });
    }
    // 1 = restore the last session.
    if (prefs?.session?.restore_on_startup === 1) return;
    prefs.session = { ...(prefs.session ?? {}), restore_on_startup: 1 };
    prefs.profile = { ...(prefs.profile ?? {}), exit_type: 'Normal' };
    await writeFile(prefsPath, JSON.stringify(prefs));
}

/**
 * Clear a profile lock left behind by a browser that is no longer running.
 *
 * Headed sessions outlive the script that started them: when the parent process
 * exits without closing the context, the window stays up holding the profile,
 * and if it is later killed the lock files remain. The next launch then fails
 * with "Opening in existing browser session", which reads as a broken profile
 * rather than stale state.
 *
 * Only clears when no live process is actually using the directory — a real
 * concurrent session must still be refused, not stomped on.
 */
async function _clearStaleLock(profileDir) {
    const { execFileSync } = await import('child_process');
    let holders = 0;
    try {
        const escaped = profileDir.replace(/\\/g, '\\\\').replace(/'/g, "''");
        const out = execFileSync('powershell', ['-NoProfile', '-Command',
            `(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" | ` +
            `Where-Object { $_.CommandLine -like '*${escaped}*' } | Measure-Object).Count`,
        ], { encoding: 'utf8', timeout: 15000 });
        holders = parseInt(out.trim(), 10) || 0;
    } catch {
        // Cannot enumerate processes: leave the lock alone rather than risk
        // corrupting a profile that is genuinely in use.
        return;
    }
    if (holders > 0) return;

    for (const artifact of ['lockfile', 'SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
        try { await rm(join(profileDir, artifact), { force: true }); } catch { /* already gone */ }
    }
    // Chromium refuses a clean restore when the last exit was marked a crash.
    const prefsPath = join(profileDir, 'Default', 'Preferences');
    try {
        const prefs = JSON.parse(await readFile(prefsPath, 'utf8'));
        if (prefs?.profile?.exit_type && prefs.profile.exit_type !== 'Normal') {
            prefs.profile.exit_type = 'Normal';
            await writeFile(prefsPath, JSON.stringify(prefs));
        }
    } catch { /* no Preferences yet */ }
    process.stderr.write(`[llm-browser] cleared stale lock on profile ${basename(profileDir)}\n`);
}

async function _launchProfile(name) {
    await closeAll();
    await _ensureProfilesDir();
    const profileDir = _profileDir(name);
    await mkdir(profileDir, { recursive: true });
    await _clearStaleLock(profileDir);
    await _enableSessionRestore(profileDir);
    // cloakbrowser's launchPersistentContext takes a single options object with
    // userDataDir, not Playwright's positional (dir, opts) signature. Passing the
    // directory positionally throws before _currentProfile is ever assigned, so
    // every session silently fell back to an ephemeral context.
    _context = await launchPersistentContext({ userDataDir: profileDir, ..._launchOpts() });
    _currentProfile = name;
    const pages = _context.pages();
    const isFreshProfile = pages.length === 0;
    _page = isFreshProfile ? await _context.newPage() : pages[0];
    _page.setDefaultTimeout(30000);
    _browser = null;  // persistent context doesn't expose a separate browser
    // Only land on the home page for a brand-new profile/tab - an existing
    // profile's restored tab reflects real user state and must not be
    // clobbered by a forced navigation.
    if (isFreshProfile) await _gotoHome(_page);
    return _page;
}

async function closeAll() {
    // Failures are logged (stderr - stdout is the JSON-RPC channel) instead
    // of swallowed. A context that fails to close cleanly is exactly the
    // condition that leaves a stale profile lock behind for the next launch
    // to trip over, which is worth surfacing rather than hiding.
    try { if (_context) await _context.close(); } catch (e) { process.stderr.write(`[llm-browser] context close failed: ${e && e.message || e}\n`); }
    try { if (_browser) await _browser.close(); } catch (e) { process.stderr.write(`[llm-browser] browser close failed: ${e && e.message || e}\n`); }
    _browser = _context = _page = null;
}

async function nav(url, waitMs) {
    const page = await getPage();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    if (waitMs) await page.waitForTimeout(waitMs);
    return page;
}

// ── Shared encrypted account vault ───────────────────────────────────────────
async function _vault(args) {
    const env = { ...process.env };
    const separator = process.platform === 'win32' ? ';' : ':';
    if (env.WRAITH_SRC) env.PYTHONPATH = [env.WRAITH_SRC, env.PYTHONPATH].filter(Boolean).join(separator);
    const { stdout } = await runFile(env.WRAITH_PYTHON || 'python', ['-m', 'wraith.account_vault', ...args], {
        env, windowsHide: true, timeout: 15000, maxBuffer: 2 * 1024 * 1024,
    });
    return stdout;
}

async function _vaultInput(args, value) {
    const env = { ...process.env };
    const separator = process.platform === 'win32' ? ';' : ':';
    if (env.WRAITH_SRC) env.PYTHONPATH = [env.WRAITH_SRC, env.PYTHONPATH].filter(Boolean).join(separator);
    return await new Promise((resolve, reject) => {
        const child = spawn(env.WRAITH_PYTHON || 'python', ['-m', 'wraith.account_vault', ...args], {
            env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000,
        });
        let output = '';
        child.stdout.on('data', chunk => { output += chunk; });
        child.on('error', () => reject(new Error('Vault unavailable')));
        child.on('close', code => code === 0 ? resolve(output) : reject(new Error('Vault operation failed')));
        child.stdin.end(value);
    });
}

function _siteOrigin(site) {
    if (!site || typeof site !== 'string') throw new Error('site required');
    return new URL(site.includes('://') ? site : `https://${site}`).origin;
}

// ── Tool implementations ────────────────────────────────────────────────────

// === PROFILE MANAGEMENT ===

async function llm_profile_create({ name, copy_from }) {
    if (!name) throw new Error('name required');
    await _ensureProfilesDir();
    const profileDir = _profileDir(name);
    if (existsSync(profileDir)) return { engine: 'llm', profile: name, status: 'already exists' };
    if (copy_from) {
        const srcDir = _profileDir(copy_from);
        if (!existsSync(srcDir)) throw new Error(`source profile "${copy_from}" not found`);
        await cp(srcDir, profileDir, { recursive: true, errorOnExist: true });
    } else {
        await mkdir(profileDir, { recursive: true });
    }
    return { engine: 'llm', profile: name, status: 'created', copied_from: copy_from || null };
}

async function llm_profile_list() {
    await _ensureProfilesDir();
    const entries = await readdir(PROFILES_DIR, { withFileTypes: true });
    const profiles = ['default', ...entries.filter(e => e.isDirectory() && e.name !== 'default').map(e => e.name)];
    return { engine: 'llm', profiles, active: _currentProfile || DEFAULT_PROFILE, count: profiles.length };
}

async function llm_profile_load({ name }) {
    if (!name) throw new Error('name required');
    await _ensureProfilesDir();
    const profileDir = _profileDir(name);
    await mkdir(profileDir, { recursive: true });
    await _launchProfile(name);
    return { engine: 'llm', profile: name, status: 'loaded', url: _page.url() };
}

async function llm_profile_delete({ name }) {
    if (!name) throw new Error('name required');
    if (name === _currentProfile) await closeAll();
    const profileDir = _profileDir(name);
    if (Object.values(PROFILE_DIR_OVERRIDES).includes(profileDir)) {
        return { engine: 'llm', profile: name, status: 'refused', reason: 'profile is a protected default (override-backed)' };
    }
    if (!existsSync(profileDir)) return { engine: 'llm', profile: name, status: 'not found' };
    await rm(profileDir, { recursive: true, force: true });
    if (_currentProfile === name) _currentProfile = null;
    return { engine: 'llm', profile: name, status: 'deleted' };
}

// === CREDENTIAL MANAGEMENT ===

async function llm_credential_save({ site, username, password, notes, account_id }) {
    const origin = _siteOrigin(site);
    const entry = JSON.parse(await _vaultInput(['_upsert_json'], JSON.stringify({
        url: origin, username, password, name: notes || '', source: 'agent', account_id: account_id || '',
    })));
    return { engine: 'llm', account: entry, status: 'saved' };
}

async function llm_credential_get({ site }) {
    const origin = _siteOrigin(site);
    const entries = JSON.parse(await _vault(['list', origin]));
    return { engine: 'llm', site: origin, accounts: entries, count: entries.length };
}

async function llm_credential_list() {
    const accounts = JSON.parse(await _vault(['list-all']));
    return { engine: 'llm', accounts, total: accounts.length };
}

async function llm_credential_delete({ account_id }) {
    if (!account_id) throw new Error('account_id required');
    return { engine: 'llm', ...JSON.parse(await _vault(['delete', account_id])) };
}

async function llm_autofill({ account_id }) {
    if (!account_id) throw new Error('account_id required');
    const page = await getPage();
    const origin = new URL(page.url()).origin;
    const entries = JSON.parse(await _vault(['list', origin]));
    const account = entries.find(entry => entry.id === account_id);
    if (!account) return { engine: 'llm', status: 'account not found for current site' };
    const selectors = [
        { user: 'input[type="email"]', pass: 'input[type="password"]' },
        { user: 'input[name="username"]', pass: 'input[type="password"]' },
        { user: 'input[name="email"]', pass: 'input[type="password"]' },
        { user: 'input[name="login"]', pass: 'input[type="password"]' },
        { user: 'input[id="username"]', pass: 'input[type="password"]' },
        { user: 'input[id="email"]', pass: 'input[type="password"]' },
        { user: '#identifierId', pass: 'input[type="password"]' },  // Google
        { user: 'input[autocomplete="username"]', pass: 'input[autocomplete="current-password"]' },
    ];
    let filled = false;
    for (const { user, pass } of selectors) {
        const userEl = await page.$(user);
        if (userEl) {
            const username = await _vault(['_browser_reveal', account_id, 'username', origin]);
            if (new URL(page.url()).origin !== origin) throw new Error('Page origin changed');
            await page.fill(user, username);
            const passEl = await page.$(pass);
            if (passEl) {
                const password = await _vault(['_browser_reveal', account_id, 'password', origin]);
                if (new URL(page.url()).origin !== origin) throw new Error('Page origin changed');
                await page.fill(pass, password);
            }
            filled = true;
            break;
        }
    }
    return { engine: 'llm', site: origin, username: account.username, filled, status: filled ? 'autofilled' : 'no matching form fields found' };
}

async function llm_fill_account({ account_id, field_kind, selector }) {
    if (!account_id || !selector || !['username', 'password'].includes(field_kind)) {
        throw new Error('account_id, field_kind and selector required');
    }
    const page = await getPage();
    const origin = new URL(page.url()).origin;
    const locator = page.locator(selector).first();
    const metadata = await locator.evaluate(el => ({ tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || '').toLowerCase() }));
    if (!['input', 'textarea'].includes(metadata.tag)) throw new Error('Target is not an input field');
    if (field_kind === 'password' && metadata.type !== 'password') throw new Error('Target is not a password field');
    if (field_kind === 'username' && metadata.type === 'password') throw new Error('Target is not a username field');
    const value = await _vault(['_browser_reveal', account_id, field_kind, origin]);
    if (new URL(page.url()).origin !== origin) throw new Error('Page origin changed');
    await locator.fill(value);
    return { engine: 'llm', filled: true, origin, field_kind };
}

async function llm_credential_import_google({ csv_paths, source = 'google' }) {
    if (!Array.isArray(csv_paths) || !csv_paths.length) throw new Error('csv_paths required');
    return { engine: 'llm', ...JSON.parse(await _vault(['import-google', ...csv_paths, '--source', source])) };
}

// === SEARCH & NAVIGATION ===

async function llm_search({ query, num = 8 }) {
    const q = String(query || '').trim();
    if (!q) throw new Error('query required');
    const n = Math.min(parseInt(num, 10) || 8, 20);
    const page = await nav(`https://www.google.com/search?q=${encodeURIComponent(q)}&num=${n}`, 2500);
    const results = await page.evaluate((max) => {
        const out = [];
        document.querySelectorAll('div.g, div.tF2Cxc, div[data-sokoban-container]').forEach(g => {
            const a = g.querySelector('a[href]'), h = g.querySelector('h3');
            const sn = g.querySelector('.VwiC3b, .yXK7lf, .lEBKkf, span.aCOpRe');
            if (a && h) out.push({ title: h.innerText, url: a.href, snippet: (sn ? sn.innerText : '').slice(0, 400) });
        });
        return out.slice(0, max);
    }, n);
    if (!results.length) {
        const raw = await page.evaluate(() => document.body.innerText.slice(0, 4000));
        return { engine: 'llm', query: q, results: [], raw };
    }
    return { engine: 'llm', query: q, results };
}

async function llm_open({ url, extract, wait_ms = 2500 }) {
    if (!url) throw new Error('url required');
    const page = await nav(String(url), parseInt(wait_ms, 10) || 2500);
    if (extract) {
        const js = (String(extract).includes('document') || String(extract).startsWith('return'))
            ? String(extract) : `document.querySelector(${JSON.stringify(extract)})?.innerText`;
        const data = await page.evaluate(new Function(`return (${js.startsWith('return') ? '()=>{' + js + '}' : '()=>(' + js + ')'})()`));
        return { engine: 'llm', url, data };
    }
    const data = await page.evaluate(() => ({ title: document.title, url: location.href, text: document.body.innerText.slice(0, 6000) }));
    return { engine: 'llm', url, data };
}

async function llm_navigate({ url, wait_ms = 1500 }) {
    if (!url) throw new Error('url required');
    const page = await nav(String(url), parseInt(wait_ms, 10) || 1500);
    return { engine: 'llm', url: page.url(), title: await page.title() };
}

async function llm_back() {
    const page = await getPage();
    await page.goBack({ waitUntil: 'domcontentloaded' });
    return { engine: 'llm', url: page.url(), title: await page.title() };
}

async function llm_forward() {
    const page = await getPage();
    await page.goForward({ waitUntil: 'domcontentloaded' });
    return { engine: 'llm', url: page.url(), title: await page.title() };
}

async function llm_close() {
    const profile = _currentProfile;
    await closeAll();
    _currentProfile = null;
    return { ok: true, closed: true, profile };
}

// === PAGE INTERACTION ===

async function llm_click({ selector, button = 'left', count = 1, wait_ms = 500 }) {
    if (!selector) throw new Error('selector required');
    const page = await getPage();
    await page.click(selector, { button, clickCount: parseInt(count, 10) || 1 });
    if (wait_ms) await page.waitForTimeout(parseInt(wait_ms, 10) || 500);
    return { engine: 'llm', clicked: selector, url: page.url() };
}

async function llm_fill({ selector, value }) {
    if (!selector) throw new Error('selector required');
    if (value === undefined || value === null) throw new Error('value required');
    const page = await getPage();
    await page.fill(selector, String(value));
    return { engine: 'llm', filled: selector, value: String(value) };
}

async function llm_type({ selector, text, delay = 50 }) {
    if (!selector) throw new Error('selector required');
    if (!text) throw new Error('text required');
    const page = await getPage();
    await page.click(selector);
    await page.type(selector, String(text), { delay: parseInt(delay, 10) || 50 });
    return { engine: 'llm', typed: selector, length: String(text).length };
}

async function llm_select({ selector, value }) {
    if (!selector) throw new Error('selector required');
    if (!value) throw new Error('value required');
    const page = await getPage();
    const values = Array.isArray(value) ? value : [String(value)];
    const selected = await page.selectOption(selector, values);
    return { engine: 'llm', selector, selected };
}

async function llm_press({ key }) {
    if (!key) throw new Error('key required');
    const page = await getPage();
    await page.keyboard.press(key);
    return { engine: 'llm', pressed: key };
}

async function llm_scroll({ direction = 'down', amount = 500, selector }) {
    const page = await getPage();
    if (selector) {
        await page.evaluate((sel) => {
            const el = document.querySelector(sel);
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, selector);
    } else {
        const delta = direction === 'up' ? -Math.abs(amount) : Math.abs(amount);
        await page.mouse.wheel(0, delta);
    }
    await page.waitForTimeout(300);
    const pos = await page.evaluate(() => ({ x: window.scrollX, y: window.scrollY, height: document.body.scrollHeight }));
    return { engine: 'llm', scroll: pos };
}

async function llm_wait({ selector, state = 'visible', timeout = 10000 }) {
    if (!selector) throw new Error('selector required');
    const page = await getPage();
    await page.waitForSelector(selector, { state, timeout: parseInt(timeout, 10) || 10000 });
    return { engine: 'llm', found: true, selector, state };
}

async function llm_hover({ selector }) {
    if (!selector) throw new Error('selector required');
    const page = await getPage();
    await page.hover(selector);
    return { engine: 'llm', hovered: selector };
}

async function llm_focus({ selector }) {
    if (!selector) throw new Error('selector required');
    const page = await getPage();
    await page.focus(selector);
    return { engine: 'llm', focused: selector };
}

// === CONTENT EXTRACTION ===

async function llm_eval({ js }) {
    if (!js) throw new Error('js required');
    const page = await getPage();
    const source = String(js);

    // Expression or statement mode is decided by parsing, not by looking for
    // the substring "return".
    //
    // The previous heuristic treated any code *containing* "return" as a
    // statement block, so a self-contained IIFE like
    //     (() => { return findButton(); })()
    // was spliced in as a bare statement and its value thrown away — the tool
    // answered `undefined` for a snippet that had computed the right result.
    // Silent, and indistinguishable from "the page had no such element", which
    // is exactly how it read. The word also appears in ordinary identifiers and
    // strings ("returned", "returnUrl"), so the match was wrong in both
    // directions.
    //
    // Wrapping as an expression fails at Function-construction time when the
    // source is genuinely a statement block, which makes the fallback exact.
    let wrapped;
    try {
        wrapped = new Function(`return (async()=>( ${source} ))()`);
    } catch (err) {
        if (!(err instanceof SyntaxError)) throw err;
        wrapped = new Function(`return (async()=>{ ${source} })()`);
    }
    const data = await page.evaluate(wrapped);
    return { engine: 'llm', data };
}

async function llm_fingerprint_health() {
    const page = await getPage();
    const signals = await page.evaluate(() => {
        const webdriver = navigator.webdriver === true;
        const headlessUA = /Headless/i.test(navigator.userAgent);
        const plugins = navigator.plugins.length;
        const geometryValid = outerWidth >= innerWidth && outerHeight >= innerHeight;
        return { webdriver, headlessUA, plugins, geometryValid,
            basicSignalsPass: !webdriver && !headlessUA && plugins > 0 && geometryValid };
    });
    return { engine: 'llm', ...signals };
}

async function llm_extract_links({ filter }) {
    const page = await getPage();
    const links = await page.evaluate((f) => {
        const anchors = [...document.querySelectorAll('a[href]')];
        return anchors
            .map(a => ({ text: (a.innerText || '').trim().slice(0, 200), url: a.href }))
            .filter(l => l.url && l.url.startsWith('http'))
            .filter(l => !f || l.url.includes(f) || l.text.toLowerCase().includes(f.toLowerCase()));
    }, filter || null);
    return { engine: 'llm', count: links.length, links: links.slice(0, 100) };
}

async function llm_extract_text({ selector, max_length = 8000 }) {
    const page = await getPage();
    const text = selector
        ? await page.evaluate((sel, max) => { const el = document.querySelector(sel); return el ? el.innerText.slice(0, max) : null; }, selector, max_length)
        : await page.evaluate((max) => document.body.innerText.slice(0, max), max_length);
    return { engine: 'llm', text, length: text ? text.length : 0, url: page.url() };
}

async function llm_extract_forms() {
    const page = await getPage();
    const forms = await page.evaluate(() => {
        return [...document.querySelectorAll('form, input, textarea, select, button[type="submit"]')].reduce((acc, el) => {
            if (el.tagName === 'FORM') {
                acc.push({ tag: 'form', action: el.action, method: el.method, id: el.id, fields: [] });
            } else {
                const form = acc[acc.length - 1] || (acc.push({ tag: 'form', action: '', method: '', id: '', fields: [] }), acc[acc.length - 1]);
                form.fields.push({
                    tag: el.tagName.toLowerCase(), type: el.type || '', name: el.name || '', id: el.id || '',
                    placeholder: el.placeholder || '', value: el.value || '',
                    selector: el.id ? `#${el.id}` : el.name ? `[name="${el.name}"]` : `${el.tagName.toLowerCase()}[type="${el.type}"]`,
                });
            }
            return acc;
        }, []);
    });
    return { engine: 'llm', forms, count: forms.length, url: page.url() };
}

async function llm_screenshot({ full_page = false }) {
    const page = await getPage();
    const buf = await page.screenshot({ fullPage: !!full_page, type: 'png' });
    return { engine: 'llm', image_base64: buf.toString('base64'), bytes: buf.length };
}

// === DOWNLOADS & SAVING ===

async function llm_download({ url, save_path }) {
    if (!url) throw new Error('url required');
    const dest = save_path || join(homedir(), 'Downloads', basename(new URL(url).pathname) || 'download');
    const page = await getPage();
    const [download] = await Promise.all([
        page.waitForEvent('download', { timeout: 30000 }).catch(() => null),
        page.evaluate((u) => {
            const a = document.createElement('a'); a.href = u; a.download = ''; a.style.display = 'none';
            document.body.appendChild(a); a.click(); a.remove();
        }, url),
    ]);
    if (download) {
        const tmpPath = await download.path();
        if (tmpPath) {
            const data = await readFile(tmpPath);
            await mkdir(dirname(dest), { recursive: true });
            await writeFile(dest, data);
            return { engine: 'llm', saved: dest, bytes: data.length, suggested: download.suggestedFilename() };
        }
    }
    const buf = await page.evaluate(async (u) => {
        const r = await fetch(u); const ab = await r.arrayBuffer();
        return Array.from(new Uint8Array(ab));
    }, url);
    const data = Buffer.from(buf);
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, data);
    return { engine: 'llm', saved: dest, bytes: data.length };
}

async function llm_pdf({ save_path, full_page = true }) {
    const page = await getPage();
    const dest = save_path || join(homedir(), 'Downloads', `page-${Date.now()}.pdf`);
    await mkdir(dirname(dest), { recursive: true });
    const buf = await page.pdf({ format: 'A4', printBackground: true, ...(full_page ? {} : { pageRanges: '1' }) });
    await writeFile(dest, buf);
    return { engine: 'llm', saved: dest, bytes: buf.length, url: page.url() };
}

// === COOKIE & STORAGE ===

async function llm_cookies({ action = 'get', cookies }) {
    const ctx = _context || (await getPage(), _context);
    if (action === 'set' && Array.isArray(cookies)) {
        await ctx.addCookies(cookies);
        return { engine: 'llm', action: 'set', count: cookies.length };
    }
    if (action === 'clear') {
        await ctx.clearCookies();
        return { engine: 'llm', action: 'clear' };
    }
    const all = await ctx.cookies();
    return { engine: 'llm', action: 'get', count: all.length, cookies: all.slice(0, 50) };
}

async function llm_storage({ action = 'get', key, value, type = 'local' }) {
    const page = await getPage();
    const store = type === 'session' ? 'sessionStorage' : 'localStorage';
    if (action === 'set' && key) {
        await page.evaluate(([s, k, v]) => window[s].setItem(k, v), [store, key, String(value)]);
        return { engine: 'llm', action: 'set', store, key, value: String(value) };
    }
    if (action === 'get' && key) {
        const val = await page.evaluate(([s, k]) => window[s].getItem(k), [store, key]);
        return { engine: 'llm', action: 'get', store, key, value: val };
    }
    if (action === 'remove' && key) {
        await page.evaluate(([s, k]) => window[s].removeItem(k), [store, key]);
        return { engine: 'llm', action: 'remove', store, key };
    }
    if (action === 'clear') {
        await page.evaluate((s) => window[s].clear(), store);
        return { engine: 'llm', action: 'clear', store };
    }
    const data = await page.evaluate((s) => {
        const obj = {}; for (let i = 0; i < window[s].length; i++) { const k = window[s].key(i); obj[k] = window[s].getItem(k); }
        return obj;
    }, store);
    return { engine: 'llm', action: 'get_all', store, entries: Object.keys(data).length, data };
}

// === TAB MANAGEMENT ===

async function llm_tabs() {
    if (!_context) return { engine: 'llm', tabs: [] };
    const pages = _context.pages();
    const tabs = await Promise.all(pages.map(async (p, i) => ({
        index: i, url: p.url(), title: await p.title().catch(() => ''), active: p === _page
    })));
    return { engine: 'llm', count: tabs.length, tabs };
}

async function llm_tab_switch({ index }) {
    if (!_context) throw new Error('no browser open');
    const pages = _context.pages();
    const i = parseInt(index, 10);
    if (i < 0 || i >= pages.length) throw new Error(`tab index ${i} out of range (${pages.length} tabs)`);
    _page = pages[i];
    await _page.bringToFront();
    return { engine: 'llm', switched: i, url: _page.url(), title: await _page.title() };
}

async function llm_new_tab({ url }) {
    const ctx = _context || (await getPage(), _context);
    const page = await ctx.newPage();
    _page = page;
    if (url) await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    return { engine: 'llm', url: page.url(), title: await page.title(), tabs: ctx.pages().length };
}

async function llm_close_tab({ index }) {
    if (!_context) throw new Error('no browser open');
    const pages = _context.pages();
    const i = index !== undefined ? parseInt(index, 10) : pages.indexOf(_page);
    if (i < 0 || i >= pages.length) throw new Error(`tab index ${i} out of range`);
    await pages[i].close();
    const remaining = _context.pages();
    if (remaining.length > 0) {
        _page = remaining[Math.min(i, remaining.length - 1)];
    } else {
        _page = await _context.newPage();
    }
    return { engine: 'llm', closed_tab: i, remaining: remaining.length, active_url: _page.url() };
}

// === STATUS ===

async function llm_status() {
    const info = {
        engine: 'llm',
        browser_open: !!(_browser || _context),
        profile: _currentProfile || DEFAULT_PROFILE,
        url: _page && !_page.isClosed?.() ? _page.url() : null,
        title: _page && !_page.isClosed?.() ? await _page.title().catch(() => null) : null,
        tabs: _context ? _context.pages().length : 0,
    };
    return info;
}

// ── Tool registry ───────────────────────────────────────────────────────────
const TOOLS = [
    // Profile management
    { name: 'llm_profile_create', description: 'Create a named browser profile (persistent cookies, logins, history). Optionally copy from existing profile.',
      inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Profile name' }, copy_from: { type: 'string', description: 'Copy from existing profile (optional)' } }, required: ['name'] }, fn: llm_profile_create },
    { name: 'llm_profile_list', description: 'List all saved browser profiles and which is active.',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_profile_list },
    { name: 'llm_profile_load', description: 'Load a browser profile (restarts browser with that profile). All logins, cookies, history persist.',
      inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Profile name to load (creates if new)' } }, required: ['name'] }, fn: llm_profile_load },
    { name: 'llm_profile_delete', description: 'Delete a saved browser profile and all its data.',
      inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Profile name to delete' } }, required: ['name'] }, fn: llm_profile_delete },

    // Credential management
    { name: 'llm_credential_save', description: 'Save login credentials (username/password) for a website.',
      inputSchema: { type: 'object', properties: { site: { type: 'string', description: 'Website domain (e.g. github.com)' }, username: { type: 'string' }, password: { type: 'string' }, notes: { type: 'string', description: 'Optional notes' }, account_id: { type: 'string', description: 'Existing account ID when rotating its password' } }, required: ['site', 'username', 'password'] }, fn: llm_credential_save },
    { name: 'llm_credential_get', description: 'List imported account labels for a website; passwords remain encrypted.',
      inputSchema: { type: 'object', properties: { site: { type: 'string', description: 'Website domain' } }, required: ['site'] }, fn: llm_credential_get },
    { name: 'llm_credential_list', description: 'List all sites with saved credentials.',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_credential_list },
    { name: 'llm_credential_delete', description: 'Delete one account by its imported account ID.',
      inputSchema: { type: 'object', properties: { account_id: { type: 'string' } }, required: ['account_id'] }, fn: llm_credential_delete },
    { name: 'llm_credential_import_google', description: 'Import Google Password Manager CSV exports into the encrypted local vault. Returns counts, no passwords.',
      inputSchema: { type: 'object', properties: { csv_paths: { type: 'array', items: { type: 'string' } }, source: { type: 'string' } }, required: ['csv_paths'] }, fn: llm_credential_import_google },
    { name: 'llm_autofill', description: 'Fill a saved account in the current site using its account ID; the password is never returned.',
      inputSchema: { type: 'object', properties: { account_id: { type: 'string' } }, required: ['account_id'] }, fn: llm_autofill },
    { name: 'llm_fill_account', description: 'Fill one login field in the current page with a saved account without returning the secret.',
      inputSchema: { type: 'object', properties: { account_id: { type: 'string' }, field_kind: { type: 'string', enum: ['username', 'password'] }, selector: { type: 'string' } }, required: ['account_id', 'field_kind', 'selector'] }, fn: llm_fill_account },

    // Search & navigation
    { name: 'llm_search', description: 'Web/Google search. Returns title/url/snippet results.',
      inputSchema: { type: 'object', properties: { query: { type: 'string', description: 'Search query' }, num: { type: 'integer', description: 'Max results (default 8, max 20)' } }, required: ['query'] }, fn: llm_search },
    { name: 'llm_open', description: 'Open a URL; return rendered title+text, or a CSS-selector/JS extract.',
      inputSchema: { type: 'object', properties: { url: { type: 'string' }, extract: { type: 'string', description: 'CSS selector or JS expr (optional)' }, wait_ms: { type: 'integer' } }, required: ['url'] }, fn: llm_open },
    { name: 'llm_navigate', description: 'Navigate to a URL (keeps page open for interaction).',
      inputSchema: { type: 'object', properties: { url: { type: 'string' }, wait_ms: { type: 'integer' } }, required: ['url'] }, fn: llm_navigate },
    { name: 'llm_back', description: 'Go back one page in browser history.',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_back },
    { name: 'llm_forward', description: 'Go forward one page in browser history.',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_forward },

    // Page interaction
    { name: 'llm_click', description: 'Click an element by CSS selector.',
      inputSchema: { type: 'object', properties: { selector: { type: 'string' }, button: { type: 'string', description: 'left/right/middle' }, count: { type: 'integer', description: '2 for double-click' }, wait_ms: { type: 'integer' } }, required: ['selector'] }, fn: llm_click },
    { name: 'llm_fill', description: 'Fill a form field (clears existing value first).',
      inputSchema: { type: 'object', properties: { selector: { type: 'string' }, value: { type: 'string' } }, required: ['selector', 'value'] }, fn: llm_fill },
    { name: 'llm_type', description: 'Type text character-by-character (simulates real typing).',
      inputSchema: { type: 'object', properties: { selector: { type: 'string' }, text: { type: 'string' }, delay: { type: 'integer', description: 'ms between keystrokes (default 50)' } }, required: ['selector', 'text'] }, fn: llm_type },
    { name: 'llm_select', description: 'Select option(s) from a dropdown.',
      inputSchema: { type: 'object', properties: { selector: { type: 'string' }, value: { type: 'string' } }, required: ['selector', 'value'] }, fn: llm_select },
    { name: 'llm_press', description: 'Press a keyboard key (Enter, Tab, Escape, Control+a, etc.).',
      inputSchema: { type: 'object', properties: { key: { type: 'string' } }, required: ['key'] }, fn: llm_press },
    { name: 'llm_scroll', description: 'Scroll the page or scroll an element into view.',
      inputSchema: { type: 'object', properties: { direction: { type: 'string', description: 'up/down' }, amount: { type: 'integer' }, selector: { type: 'string', description: 'Scroll element into view instead' } }, required: [] }, fn: llm_scroll },
    { name: 'llm_wait', description: 'Wait for an element to appear on the page.',
      inputSchema: { type: 'object', properties: { selector: { type: 'string' }, state: { type: 'string', description: 'visible/hidden/attached/detached' }, timeout: { type: 'integer' } }, required: ['selector'] }, fn: llm_wait },
    { name: 'llm_hover', description: 'Hover over an element.',
      inputSchema: { type: 'object', properties: { selector: { type: 'string' } }, required: ['selector'] }, fn: llm_hover },
    { name: 'llm_focus', description: 'Focus an element.',
      inputSchema: { type: 'object', properties: { selector: { type: 'string' } }, required: ['selector'] }, fn: llm_focus },

    // Content extraction
    { name: 'llm_eval', description: 'Run JavaScript in the current page.',
      inputSchema: { type: 'object', properties: { js: { type: 'string' } }, required: ['js'] }, fn: llm_eval },
    { name: 'llm_fingerprint_health', description: 'Check basic automation and window signals without screenshots. This does not predict every site verdict.',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_fingerprint_health },
    { name: 'llm_extract_links', description: 'Extract all links from the page, optionally filtered.',
      inputSchema: { type: 'object', properties: { filter: { type: 'string', description: 'Filter by URL or text' } }, required: [] }, fn: llm_extract_links },
    { name: 'llm_extract_text', description: 'Extract text content from the page or a specific element.',
      inputSchema: { type: 'object', properties: { selector: { type: 'string' }, max_length: { type: 'integer', description: 'default 8000' } }, required: [] }, fn: llm_extract_text },
    { name: 'llm_extract_forms', description: 'Detect and list all forms and input fields on the page with their selectors.',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_extract_forms },
    { name: 'llm_screenshot', description: 'Take a PNG screenshot (base64).',
      inputSchema: { type: 'object', properties: { full_page: { type: 'boolean' } }, required: [] }, fn: llm_screenshot },

    // Downloads & saving
    { name: 'llm_download', description: 'Download a file from a URL and save it locally.',
      inputSchema: { type: 'object', properties: { url: { type: 'string' }, save_path: { type: 'string', description: 'default ~/Downloads/' } }, required: ['url'] }, fn: llm_download },
    { name: 'llm_pdf', description: 'Save the current page as a PDF.',
      inputSchema: { type: 'object', properties: { save_path: { type: 'string' }, full_page: { type: 'boolean' } }, required: [] }, fn: llm_pdf },

    // Cookies & storage
    { name: 'llm_cookies', description: 'Get, set, or clear browser cookies.',
      inputSchema: { type: 'object', properties: { action: { type: 'string', description: 'get/set/clear' }, cookies: { type: 'array', description: 'Cookie objects for set', items: { type: 'object' } } }, required: [] }, fn: llm_cookies },
    { name: 'llm_storage', description: 'Get/set/remove/clear localStorage or sessionStorage for current page.',
      inputSchema: { type: 'object', properties: { action: { type: 'string', description: 'get/set/remove/clear/get_all (default get_all)' }, key: { type: 'string' }, value: { type: 'string' }, type: { type: 'string', description: 'local or session (default local)' } }, required: [] }, fn: llm_storage },

    // Tab management
    { name: 'llm_tabs', description: 'List all open browser tabs.',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_tabs },
    { name: 'llm_tab_switch', description: 'Switch to a different tab by index.',
      inputSchema: { type: 'object', properties: { index: { type: 'integer' } }, required: ['index'] }, fn: llm_tab_switch },
    { name: 'llm_new_tab', description: 'Open a new tab, optionally navigating to a URL.',
      inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: [] }, fn: llm_new_tab },
    { name: 'llm_close_tab', description: 'Close a tab by index (defaults to current tab).',
      inputSchema: { type: 'object', properties: { index: { type: 'integer' } }, required: [] }, fn: llm_close_tab },

    // Lifecycle & status
    { name: 'llm_status', description: 'Get current browser status: open/closed, active profile, URL, tab count.',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_status },
    { name: 'llm_close', description: 'Close the browser (profile data is preserved).',
      inputSchema: { type: 'object', properties: {}, required: [] }, fn: llm_close },
];

/**
 * Append an evidence record for a blocked payload.
 *
 * Written to disk rather than stdout because stdout is the JSON-RPC channel —
 * anything logged there would corrupt the protocol stream. This file is the
 * evidence bundle source for CISA/IT reporting.
 */
function recordQuarantine(toolName, scanResult) {
    const entry = {
        ts: new Date().toISOString(),
        tool: toolName ?? 'unknown',
        verdict: scanResult.verdict,
        severity: scanResult.severity,
        signals: scanResult.signals,
    };
    try {
        appendFileSync(QUARANTINE_LOG, JSON.stringify(entry) + '\n');
    } catch {
        // Losing the audit line must never break the tool call itself.
    }

    // Blocking silently is only half the job. If the operator never learns a
    // page tried to open a port on their machine, they keep visiting it.
    elevateScanResult(toolName ?? 'unknown', scanResult);

    // Detect, ignore, AND report — without asking. The evidence line above is
    // only a local record; until this call existed the reporter was never
    // invoked by anything, so incidents accumulated in quarantine.jsonl and
    // were never filed to the Event Log or staged for IC3.
    autoReport(toolName ?? 'unknown', scanResult);
}

// ── stdio JSON-RPC loop ───────────────────────────────────────────────────
function send(obj) { obj.jsonrpc = '2.0'; process.stdout.write(JSON.stringify(obj) + '\n'); }

// Serializes every tool invocation. Tool calls share one browser/page/
// context across the whole process; if two JSON-RPC messages land in
// separate stdin "data" events - normal under pipe buffering, not a
// hypothetical - the async handler below runs a second, overlapping time
// while the first is still mid-flight, and both can race a
// launchPersistentContext() call against the same profile directory at
// once. Reproduced live: a 3-call burst produced an out-of-order response
// (the 3rd reply arrived before the 2nd's error) and one of the two
// concurrent launches against the same profile died with "Target page,
// context or browser has been closed" while the other succeeded. Chaining
// every tool.fn() call through one promise makes execution order match
// arrival order and removes the race. `.then(fn, fn)` re-runs fn as the
// next link regardless of whether the previous call resolved or rejected,
// so one failed tool call can never wedge the queue for the calls after it.
let _callChain = Promise.resolve();
function runExclusive(fn) {
    const result = _callChain.then(fn, fn);
    _callChain = result.then(() => {}, () => {});
    return result;
}

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', async (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg; try { msg = JSON.parse(line); } catch { continue; }
        const { id, method, params } = msg;
        try {
            if (method === 'initialize') {
                send({ id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'llm-browser-mcp', version: '3.0.0' } } });
            } else if (method === 'notifications/initialized') {
                // no response
            } else if (method === 'tools/list') {
                send({ id, result: { tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) } });
            } else if (method === 'tools/call') {
                const tool = TOOLS.find(t => t.name === params?.name);
                if (!tool) { send({ id, error: { code: -32601, message: `Unknown tool: ${params?.name}` } }); continue; }
                const result = await runExclusive(() => tool.fn(params.arguments || {}));
                // Single chokepoint: every tool result serializes here, so
                // scanning the serialized payload covers innerText paths as well
                // as llm_eval and custom extractors that can return raw HTML,
                // attributes, or comments.
                const { text, result: scanResult } = sanitize(JSON.stringify(result));
                if (scanResult.verdict !== Verdict.PASS) {
                    recordQuarantine(params?.name, scanResult);
                }
                send({ id, result: { content: [{ type: 'text', text }] } });
            } else if (id !== undefined) {
                send({ id, error: { code: -32601, message: `Unknown method: ${method}` } });
            }
        } catch (e) {
            if (id !== undefined) send({ id, error: { code: -32000, message: String(e && e.message || e) } });
        }
    }
});
// Graceful-shutdown coverage. SIGTERM is registered for parity with POSIX
// hosts, but Node cannot actually receive it on Windows - a parent killing
// this process the default way (or an MCP host tearing the child down
// between sessions) terminates it outright without ever running this
// handler, which is exactly how a persistent context's profile lock gets
// left stale and its last writes lost. SIGINT/SIGHUP/SIGBREAK are real,
// deliverable Windows signals (Ctrl+C, console-window-close, Ctrl+Break).
// The stdin close/end handlers cover the case that actually matters most for
// a stdio MCP server: the host disconnecting closes the pipe as a plain I/O
// event, which fires regardless of platform signal support.
let _shuttingDown = false;
function shutdown() {
    if (_shuttingDown) return;
    _shuttingDown = true;
    closeAll().finally(() => process.exit(0));
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('SIGHUP', shutdown);
process.on('SIGBREAK', shutdown);
process.stdin.on('close', shutdown);
process.stdin.on('end', shutdown);
process.stderr.write(`llm-browser-mcp v3.0.0 ready — ${TOOLS.length} tools\n`);
