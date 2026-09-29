/**
 * Chromium browser verification for UI-06:
 * Tests that back-navigation form restoration in real Chromium synchronizes
 * transport field visibility (REALITY fields shown, callback URL hidden)
 * and preserves typed user input.
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const PORT = 5569;
const CHROME_PORT = 9335;
const ROOT = path.resolve(__dirname, '../..');

// Static HTTP server serving the real dashboard templates and static assets
const server = http.createServer((req, res) => {
    let filePath = '';
    if (req.url === '/' || req.url === '/index.html') {
        filePath = path.join(ROOT, 'server/templates/index.html');
    } else if (req.url === '/static/dashboard.js') {
        filePath = path.join(ROOT, 'server/static/dashboard.js');
    } else if (req.url === '/static/style.css') {
        filePath = path.join(ROOT, 'server/static/style.css');
    } else {
        res.writeHead(404);
        res.end('Not found');
        return;
    }

    let content = fs.readFileSync(filePath, 'utf8');
    if (req.url === '/' || req.url === '/index.html') {
        content = content.replace(/{{[^}]+}}/g, '');
        content = content.replace(/<link\b[^>]*href="https:\/\/[^>]*>/g, '');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    } else if (req.url.endsWith('.js')) {
        res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
    } else if (req.url.endsWith('.css')) {
        res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8' });
    }
    res.end(content);
});

async function run() {
    await new Promise((resolve) => server.listen(PORT, '127.0.0.1', resolve));

    const tmpUserData = `/tmp/chromium-ui06-${Date.now()}`;
    const chrome = spawn('chromium', [
        '--headless=new',
        `--remote-debugging-port=${CHROME_PORT}`,
        `--user-data-dir=${tmpUserData}`,
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-gpu',
        'about:blank',
    ], { stdio: 'ignore' });

    let targetWs = null;
    for (let i = 0; i < 40; i++) {
        await new Promise((r) => setTimeout(r, 200));
        try {
            const resp = await fetch(`http://127.0.0.1:${CHROME_PORT}/json/list`);
            if (resp.ok) {
                const list = await resp.json();
                const pageTarget = list.find((t) => t.type === 'page');
                if (pageTarget && pageTarget.webSocketDebuggerUrl) {
                    targetWs = pageTarget.webSocketDebuggerUrl;
                    break;
                }
            }
        } catch {}
    }

    if (!targetWs) {
        chrome.kill();
        server.close();
        throw new Error('Chromium page target not found in /json/list');
    }

    const ws = new WebSocket(targetWs);
    await new Promise((resolve) => ws.onopen = resolve);

    let msgId = 0;
    const pending = new Map();
    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.id && pending.has(msg.id)) {
            pending.get(msg.id)(msg);
            pending.delete(msg.id);
        }
    };

    function send(method, params = {}) {
        const id = ++msgId;
        return new Promise((resolve) => {
            pending.set(id, resolve);
            ws.send(JSON.stringify({ id, method, params }));
        });
    }

    try {
        await send('Page.enable');
        await send('Runtime.enable');

        // Navigate to the dashboard page
        await send('Page.navigate', { url: `http://127.0.0.1:${PORT}/` });
        await new Promise((r) => setTimeout(r, 1000));

        // Step 1: User selects REALITY and types a VPS address
        const selectReality = await send('Runtime.evaluate', {
            expression: `(() => {
                const sel = document.getElementById("build-transport");
                sel.value = "reality";
                sel.dispatchEvent(new Event("change"));
                document.getElementById("build-vps-addr").value = "198.51.100.99:8443";
                return {
                    val: sel.value,
                    vps: document.getElementById("build-vps-addr").value,
                    realityDisplay: window.getComputedStyle(document.getElementById("reality-fields")).display,
                    serverUrlDisplay: window.getComputedStyle(document.getElementById("server-url-group")).display,
                };
            })()`,
            returnByValue: true,
        });

        console.log('After selecting REALITY:', selectReality.result.result.value);

        // Step 2: Navigate away to about:blank
        await send('Page.navigate', { url: 'about:blank' });
        await new Promise((r) => setTimeout(r, 600));

        // Step 3: Navigate back in history
        const navHistory = await send('Page.getNavigationHistory');
        const currentIndex = navHistory.result.currentIndex;
        const prevEntry = navHistory.result.entries[currentIndex - 1];
        await send('Page.navigateToHistoryEntry', { entryId: prevEntry.id });

        // Wait for navigation, form restoration, and pageshow event
        await new Promise((r) => setTimeout(r, 1500));

        // Step 4: Check restored states in Chromium
        const checkRestored = await send('Runtime.evaluate', {
            expression: `(() => {
                const sel = document.getElementById("build-transport");
                const realityFields = document.getElementById("reality-fields");
                const serverUrlGroup = document.getElementById("server-url-group");
                const vps = document.getElementById("build-vps-addr");
                return {
                    transportValue: sel.value,
                    realityDisplay: window.getComputedStyle(realityFields).display,
                    serverUrlDisplay: window.getComputedStyle(serverUrlGroup).display,
                    vpsValue: vps.value,
                };
            })()`,
            returnByValue: true,
        });

        const state = checkRestored.result.result.value;
        console.log('Observed states after Chromium Back navigation:');
        console.log(JSON.stringify(state, null, 2));

        if (state.transportValue !== 'reality') {
            throw new Error(`Expected transportValue 'reality', got '${state.transportValue}'`);
        }
        if (state.realityDisplay === 'none') {
            throw new Error(`Expected realityDisplay NOT 'none', got '${state.realityDisplay}'`);
        }
        if (state.serverUrlDisplay !== 'none') {
            throw new Error(`Expected serverUrlDisplay 'none', got '${state.serverUrlDisplay}'`);
        }
        if (state.vpsValue !== '198.51.100.99:8443') {
            throw new Error(`Expected vpsValue '198.51.100.99:8443', got '${state.vpsValue}'`);
        }

        console.log('SUCCESS: Chromium Back navigation fixture verified UI-06!');

        // Recheck the previously resolved layout findings with actual CSS and
        // deterministic API fixtures, without contacting a team server.
        for (const width of [1280, 500]) {
            await send('Emulation.setDeviceMetricsOverride', {
                width, height: 1000, deviceScaleFactor: 1, mobile: false,
            });
            const layout = await send('Runtime.evaluate', {
                expression: `(async () => {
                    loadStats = () => {};
                    apiFetch = async () => ({ok: true, json: async () => ({builds: [{
                        id: 1, filename: 'fixture.bin', target_os: 'linux', arch: 'amd64',
                        transport_mode: 'reality', decoy_domain: 'very-long-domain.'.repeat(15) + 'example',
                        file_size: 1024, created_at: '2026-09-25 00:00:00'
                    }]})});
                    switchSection('deploy');
                    await new Promise(resolve => setTimeout(resolve, 0));
                    const row = document.querySelector('.payload-item');
                    const button = document.getElementById('check-domain-btn');
                    button.textContent = 'Measuring…';
                    const groups = document.querySelectorAll('#reality-fields > .form-group');
                    const persist = document.getElementById('build-persist-method');
                    return {
                        children: row.children.length,
                        columns: getComputedStyle(row).gridTemplateColumns.split(' ').length,
                        rowOverflow: row.scrollWidth > row.clientWidth + 1,
                        buttonOverflow: button.scrollWidth > button.clientWidth + 1,
                        gap: parseFloat(getComputedStyle(groups[1]).marginTop),
                        label: !!document.querySelector('label[for="build-persist-method"]'),
                        selectStyled: persist.classList.contains('form-select'),
                        measurementLive: document.getElementById('decoy-domain-hint').getAttribute('aria-live'),
                        badgeTitle: document.querySelector('.payload-reality-badge').title.length,
                    };
                })()`, awaitPromise: true, returnByValue: true,
            });
            if (layout.result.exceptionDetails) throw new Error(JSON.stringify(layout.result.exceptionDetails));
            const measured = layout.result.result.value;
            if (measured.children !== 6 || measured.columns !== (width === 1280 ? 6 : 2) ||
                measured.rowOverflow || measured.buttonOverflow || measured.gap !== 20 ||
                !measured.label || !measured.selectStyled || measured.measurementLive !== 'polite' ||
                measured.badgeTitle < 100) {
                throw new Error('Layout regression at ' + width + ': ' + JSON.stringify(measured));
            }
            console.log('Layout and accessibility markup verified at ' + width + 'px');

            const cardLayout = await send('Runtime.evaluate', {
                expression: `(async () => {
                    apiFetch = async () => ({ok: true, json: async () => ({agents: [{
                        id: 'fixture-agent', hostname: 'fixture', os: 'linux',
                        last_seen: '2026-09-25T00:00:00Z', transport_mode: 'reality',
                        decoy_domain: 'long-domain.'.repeat(20) + 'example'
                    }]})});
                    switchSection('control');
                    refreshAgents();
                    await new Promise(resolve => setTimeout(resolve, 0));
                    const card = document.querySelector('.agent-card');
                    const status = document.getElementById('send-file-status');
                    status.textContent = 'Long file status: ' + 'filename'.repeat(80);
                    return {
                        cardOverflow: card.scrollWidth > card.clientWidth + 1,
                        statusOverflow: status.scrollWidth > status.clientWidth + 1,
                        badgeTitle: card.querySelector('.agent-transport-badge').title.length,
                    };
                })()`, awaitPromise: true, returnByValue: true,
            });
            if (cardLayout.result.exceptionDetails) throw new Error(JSON.stringify(cardLayout.result.exceptionDetails));
            const card = cardLayout.result.result.value;
            if (card.cardOverflow || card.statusOverflow || card.badgeTitle < 100) {
                throw new Error('Agent card/status overflow at ' + width + ': ' + JSON.stringify(card));
            }
        }
    } finally {
        ws.close();
        chrome.kill();
        server.close();
        try { fs.rmSync(tmpUserData, { recursive: true, force: true }); } catch {}
    }
}

run().catch((err) => {
    console.error('Chromium test failed:', err);
    process.exit(1);
});
