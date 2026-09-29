const assert = require('node:assert/strict');
const test = require('node:test');
const {createDashboard, flush} = require('./dashboard_harness.cjs');

test('send file retains its original recipient without altering a later terminal or draft', async () => {
    for (const returnToOriginal of [false, true]) {
        const {context, get} = createDashboard();
        context.loadTasks = () => {};
        context.loadStagedFiles = () => {};
        context.selectAgent('agent-a');
        let finishStage;
        const tasks = [];
        context.apiFetch = (url, options) => {
            if (url === '/api/files/stage') return new Promise(resolve => { finishStage = resolve; });
            assert.equal(url, '/api/task');
            tasks.push(JSON.parse(options.body));
            return Promise.resolve({ok: true, json: async () => ({task_id: 42})});
        };
        const input = {files: [{name: 'fixture.txt'}], value: 'fixture.txt'};
        context.sendFileToAgent(input);
        context.selectAgent('agent-b');
        if (returnToOriginal) context.selectAgent('agent-a');
        const terminal = get('terminal-output').innerHTML;
        get('command-input').value = 'unfinished draft';
        finishStage({ok: true, json: async () => ({file_id: 7, filename: 'fixture.txt'})});
        await flush();
        assert.equal(tasks.length, 1);
        assert.equal(tasks[0].agent_id, 'agent-a');
        assert.equal(tasks[0].command, 'download 7 fixture.txt');
        assert.equal(get('command-input').value, 'unfinished draft');
        assert.equal(get('terminal-output').innerHTML, terminal);
    }
});

test('send file rejects failed and malformed staging responses without submitting a task', async () => {
    for (const response of [
        {ok: false, status: 500, json: async () => ({file_id: 7, filename: 'fixture.txt'})},
        {ok: true, json: async () => ({file_id: null, filename: 'fixture.txt'})},
        {ok: true, json: async () => ({file_id: 7, filename: null})},
        {ok: true, json: async () => null},
    ]) {
        const {context, get} = createDashboard();
        context.loadTasks = () => {};
        context.selectAgent('agent-a');
        context.apiFetch = async url => {
            assert.equal(url, '/api/files/stage', 'invalid staging response queued a task');
            return response;
        };
        context.sendFileToAgent({files: [{name: 'fixture.txt'}], value: ''});
        await flush();
        assert.match(get('terminal-output').innerHTML, /Upload failed/);
        assert.equal(get('send-file-btn').disabled, false);
    }
});

test('send file failures after selection changes stay visible and never overwrite the new terminal', async () => {
    for (const phase of ['stage', 'task']) {
        const {context, get} = createDashboard();
        context.loadTasks = () => {};
        context.loadStagedFiles = () => {};
        context.selectAgent('agent-a');
        let rejectStage;
        const tasks = [];
        context.apiFetch = (url, options) => {
            if (url === '/api/files/stage') return new Promise((resolve, reject) => {
                rejectStage = () => phase === 'stage' ? reject(new Error('offline'))
                    : resolve({ok: true, json: async () => ({file_id: 7, filename: 'fixture.txt'})});
            });
            tasks.push(JSON.parse(options.body));
            return Promise.resolve({ok: false, status: 404, json: async () => ({error: 'Agent not found'})});
        };
        context.sendFileToAgent({files: [{name: 'fixture.txt'}], value: ''});
        context.selectAgent('agent-b');
        assert.equal(get('send-file-btn').disabled, true);
        const terminal = get('terminal-output').innerHTML;
        rejectStage();
        await flush();
        assert.equal(get('terminal-output').innerHTML, terminal);
        assert.equal(get('send-file-btn').disabled, false);
        assert.match(get('send-file-status').textContent, /agent-a.*(offline|Agent not found)/);
        assert.equal(tasks.length, phase === 'stage' ? 0 : 1);
        if (tasks.length) assert.equal(tasks[0].agent_id, 'agent-a');
    }
});

test('a previous notification cannot hide the next pending operation', async () => {
    const {context, get, timers} = createDashboard();
    const fields = {
        'build-jitter-min': '8', 'build-jitter-max': '15', 'build-transport': 'http',
        'build-os': 'linux', 'build-arch': 'amd64', 'build-persist-method': 'none',
        'build-profile': '1', 'build-locale': 'en-US', 'build-url': 'http://example.invalid',
    };
    for (const [id, value] of Object.entries(fields)) get(id).value = value;
    const requests = [];
    context.apiFetch = () => new Promise(resolve => requests.push(resolve));
    context.triggerDownload = () => {};
    context.loadBuilds = () => {};
    context.loadStats = () => {};
    context.buildAgent({preventDefault() {}});
    requests[0]({json: async () => ({build_id: 1, filename: 'fixture', file_size: 1})});
    await flush();
    assert.equal(timers.size, 1);
    context.buildAgent({preventDefault() {}});
    for (const callback of [...timers.values()]) callback();
    assert.equal(get('build-btn').disabled, true);
    assert.equal(get('build-progress').classList.contains('hidden'), false);
    assert.equal(get('progress-text').style.color, '');
});

test('failed or malformed list responses produce an error, not an empty state', async () => {
    const {context, get} = createDashboard();
    for (const response of [
        {ok: false, status: 500, json: async () => ({error: 'failure'})},
        {ok: true, status: 200, json: async () => ({error: 'invalid shape'})},
    ]) {
        context.apiFetch = async () => response;
        context.loadBuilds();
        await flush();
        assert.match(get('payload-list').innerHTML, /Unable to load builds/);
        assert.doesNotMatch(get('payload-list').innerHTML, /No payloads generated/);
    }
    context.apiFetch = async () => ({ok: true, json: async () => ({builds: []})});
    context.loadBuilds();
    await flush();
    assert.match(get('payload-list').innerHTML, /No payloads generated/);
});

test('an HTTP download failure never saves the error response', async () => {
    const {context, get, downloads} = createDashboard();
    let readBody = false;
    context.apiFetch = async () => ({ok: false, status: 404, blob: async () => { readBody = true; }});
    context.triggerDownload(1, 'fixture.bin');
    await flush();
    assert.equal(readBody, false);
    assert.deepEqual(downloads, []);
    assert.match(get('download-status').textContent, /Download failed.*404/);
});

test('successful downloads still reach the browser', async () => {
    const {context, get, downloads} = createDashboard();
    context.apiFetch = async () => ({ok: true, blob: async () => new Blob(['fixture'])});
    context.triggerDownload(1, 'fixture.txt');
    await flush();
    assert.deepEqual(downloads, ['fixture.txt']);
    assert.match(get('download-status').textContent, /sent to your browser/);
});

test('build deletion reports a reference conflict and leaves the list visible', async () => {
    const {context, get} = createDashboard({confirm: () => true});
    get('payload-list').innerHTML = 'Existing build';
    context.apiFetch = async () => ({
        ok: false, status: 409,
        json: async () => ({error: 'Build is referenced by registered agents'}),
    });
    context.deleteBuild(7);
    await flush();
    assert.equal(get('payload-list').innerHTML, 'Existing build');
    assert.match(get('build-action-status').textContent, /Build deletion failed.*referenced/);
});

test('editing the domain cancels a measurement and ignores its late response', async () => {
    const {context, get} = createDashboard();
    let resolve, signal;
    context.apiFetch = (_, options) => {
        signal = options.signal;
        return new Promise(done => { resolve = done; });
    };
    get('build-decoy-domain').value = 'first.example';
    context.checkDecoyDomain();
    get('build-decoy-domain').value = 'second.example';
    get('build-decoy-domain').dispatch('input');
    assert.equal(signal.aborted, true);
    resolve({json: async () => ({ok: true, size_bytes: 1000, limit_bytes: 8192, fits: true})});
    await flush();
    assert.doesNotMatch(get('decoy-domain-hint').textContent, /1000/);
    assert.equal(get('check-domain-btn').disabled, false);
});

test('measurement shows certificate size and whether it fits, then clears after edits', async () => {
    const {context, get} = createDashboard();
    let submitted;
    context.apiFetch = async (_, options) => {
        submitted = JSON.parse(options.body);
        return {json: async () => ({ok: true, size_bytes: 1000, limit_bytes: 8192, fits: true})};
    };
    get('build-decoy-domain').value = 'example.com';
    context.checkDecoyDomain();
    await flush();
    assert.deepEqual(submitted, {domain: 'example.com'});
    assert.match(get('decoy-domain-hint').textContent, /Certificate size: 1,000 bytes.*Fits/);
    assert.match(get('decoy-domain-hint').textContent, /Estimate only.*live REALITY connection/);
    assert.match(get('decoy-domain-hint').className, /success/);
    get('build-decoy-domain').dispatch('input');
    assert.doesNotMatch(get('decoy-domain-hint').textContent, /1000/);
});

test('an older response cannot overwrite a newer measurement', async () => {
    const {context, get} = createDashboard();
    const pending = [];
    context.apiFetch = () => new Promise(resolve => pending.push(resolve));
    get('build-decoy-domain').value = 'first.example';
    context.checkDecoyDomain();
    get('build-decoy-domain').value = 'second.example';
    context.checkDecoyDomain();
    pending[1]({json: async () => ({ok: true, size_bytes: 9000, limit_bytes: 8192, fits: false})});
    await flush();
    pending[0]({json: async () => ({ok: true, size_bytes: 1000, limit_bytes: 8192, fits: true})});
    await flush();
    assert.match(get('decoy-domain-hint').textContent, /Certificate size: 9,000 bytes.*Does not fit/);
    assert.match(get('decoy-domain-hint').textContent, /Estimate only.*live REALITY connection/);
});

test('SQLite UTC timestamps agree with explicitly zoned timestamps', () => {
    const previousZone = process.env.TZ;
    process.env.TZ = 'America/New_York';
    try {
        class FixedDate extends Date {
            constructor(...args) { super(...(args.length ? args : ['2026-09-24T12:05:00Z'])); }
        }
        const {context} = createDashboard({Date: FixedDate});
        assert.equal(context.formatTimestamp('2026-09-24 12:00:00'), '5m ago');
        assert.equal(context.formatTimestamp('2026-09-24T12:00:00Z'), '5m ago');
        assert.equal(context.formatTimestamp('2026-09-24T08:00:00-04:00'), '5m ago');
        assert.equal(context.formatTimestamp('invalid'), '-');
    } finally {
        if (previousZone === undefined) delete process.env.TZ;
        else process.env.TZ = previousZone;
    }
});

for (const [method, id, key] of [
    ['loadLoot', 'loot-list', 'loot'],
    ['loadStagedFiles', 'staged-file-list', 'files'],
]) {
    test(`${method} distinguishes errors from an empty list and recovers`, async () => {
        const {context, get} = createDashboard();
        const responses = [
            {ok: false, status: 500},
            ...[null, {}, {[key]: {}}].map(body => ({ok: true, json: async () => body})),
            {ok: true, json: async () => { throw new SyntaxError('invalid JSON'); }},
            new Error('network <fixture>'),
        ];
        for (const response of responses) {
            context.apiFetch = async () => {
                if (response instanceof Error) throw response;
                return response;
            };
            context[method]();
            await flush();
            assert.match(get(id).innerHTML, /Unable to load files/);
            assert.doesNotMatch(get(id).innerHTML, /No files|<fixture>/);
        }
        context.apiFetch = async () => ({ok: true, json: async () => ({[key]: []})});
        context[method]();
        await flush();
        assert.match(get(id).innerHTML, /No files/);
        assert.doesNotMatch(get(id).innerHTML, /Unable to load/);
        context.apiFetch = async () => ({ok: true, json: async () => ({[key]: [
            {id: 1, filename: 'fixture.txt', agent_id: 'fixture', original_path: 'fixture.txt', file_size: 1},
        ]})});
        context[method]();
        await flush();
        assert.match(get(id).innerHTML, /fixture\.txt/);
        assert.doesNotMatch(get(id).innerHTML, /Unable to load|No files/);
    });
}

test('file download failures produce a visible error and never save a response', async () => {
    const {context, get, downloads} = createDashboard();
    for (const status of [404, 500]) {
        let readBody = false;
        context.apiFetch = async () => ({ok: false, status, blob: async () => { readBody = true; }});
        context.downloadLoot(1);
        await flush();
        assert.equal(readBody, false);
        assert.deepEqual(downloads, []);
        assert.match(get('loot-download-status').textContent, new RegExp(`Download failed.*${status}`));
    }
    for (const fetcher of [
        async () => { throw new Error('network failure'); },
        async () => ({ok: true, headers: {get: () => null}, blob: async () => { throw new Error('body failure'); }}),
    ]) {
        context.apiFetch = fetcher;
        context.downloadLoot(1);
        await flush();
        assert.deepEqual(downloads, []);
        assert.match(get('loot-download-status').textContent, /Download failed/);
    }
});

test('a successful file download clears the error and preserves its filename', async () => {
    const {context, get, downloads} = createDashboard();
    get('loot-download-status').textContent = 'Previous failure';
    context.apiFetch = async () => ({ok: true,
        headers: {get: () => 'attachment; filename="fixture.txt"'}, blob: async () => ({}),
    });
    context.downloadLoot(1);
    await flush();
    assert.deepEqual(downloads, ['fixture.txt']);
    assert.match(get('loot-download-status').textContent, /sent to your browser/);
});

const validStats = {agents: 2, pending: 3, completed: 4, builds: 5};

test('statistics failures preserve last successful counts, warn, and recover', async () => {
    const {context, get} = createDashboard();
    context.apiFetch = async () => ({ok: true, json: async () => validStats});
    context.loadStats();
    await flush();
    const responses = [
        {ok: false, status: 500},
        ...[null, {}, {...validStats, agents: '2'}, {...validStats, completed: -1}]
            .map(body => ({ok: true, json: async () => body})),
        {ok: true, json: async () => { throw new SyntaxError('invalid JSON'); }},
        new Error('network failure'),
    ];
    for (const response of responses) {
        context.apiFetch = async () => {
            if (response instanceof Error) throw response;
            return response;
        };
        context.loadStats();
        await flush();
        for (const [key, value] of Object.entries(validStats)) assert.equal(get(`stat-${key}`).textContent, value);
        assert.match(get('stats-status').textContent, /Could not refresh.*last successful counts/);
    }
    context.apiFetch = async () => ({ok: true, json: async () => ({agents: 0, pending: 0, completed: 0, builds: 0})});
    context.loadStats();
    await flush();
    for (const key of Object.keys(validStats)) assert.equal(get(`stat-${key}`).textContent, 0);
    assert.equal(get('stats-status').textContent, '');
});

test('an initial statistics failure leaves counts unavailable instead of zero', async () => {
    const {context, get} = createDashboard();
    for (const key of Object.keys(validStats)) get(`stat-${key}`).textContent = '--';
    context.apiFetch = async () => ({ok: false, status: 503});
    context.loadStats();
    await flush();
    for (const key of Object.keys(validStats)) assert.equal(get(`stat-${key}`).textContent, '--');
    assert.match(get('stats-status').textContent, /Statistics are unavailable/);
    assert.doesNotMatch(get('stats-status').textContent, /last successful counts/);
});

test('an expired operator session redirects to login', async () => {
    let redirect = '';
    const {context} = createDashboard({
        fetch: async () => ({status: 401}),
        locationAssign: target => { redirect = target; },
    });
    await assert.rejects(context.apiFetch('/api/stats'), /Operator session expired/);
    assert.equal(redirect, '/login');
});

test('restored transport selections synchronize field visibility on pageshow and input without erasing typed values', async () => {
    const {context, get, timers} = createDashboard();
    const transport = get('build-transport');
    const serverUrlGroup = get('server-url-group');
    const realityFields = get('reality-fields');
    const serverUrl = get('build-url');
    const vpsAddr = get('build-vps-addr');

    // User types in form
    serverUrl.value = 'http://operator.example:5000';
    vpsAddr.value = '198.51.100.1:443';

    // Initial state: default is http
    transport.value = 'http';
    context.toggleTransportFields();
    assert.equal(serverUrlGroup.style.display, 'block');
    assert.equal(realityFields.style.display, 'none');

    // Simulate browser history navigation restoring 'reality'
    transport.value = 'reality';
    context.window.dispatch('pageshow');
    for (const cb of [...timers.values()]) cb();

    assert.equal(realityFields.style.display, 'block');
    assert.equal(serverUrlGroup.style.display, 'none');

    // Verify typed values were preserved intact
    assert.equal(serverUrl.value, 'http://operator.example:5000');
    assert.equal(vpsAddr.value, '198.51.100.1:443');

    // Switch back to https_pinned
    transport.value = 'https_pinned';
    transport.dispatch('change');
    assert.equal(serverUrlGroup.style.display, 'block');
    assert.equal(realityFields.style.display, 'none');
    assert.equal(serverUrl.value, 'http://operator.example:5000');
});

test('macOS target selection removes the unsupported 386 architecture', () => {
    const {get} = createDashboard();
    const os = get('build-os');
    const arch = get('build-arch');
    const arch386 = get('build-arch-386');

    os.value = 'linux';
    arch.value = '386';
    os.dispatch('change');
    assert.equal(arch386.disabled, false);
    assert.equal(arch.value, '386');

    os.value = 'mac';
    os.dispatch('change');
    assert.equal(arch386.disabled, true);
    assert.equal(arch.value, 'amd64');
});

test('build and agent badges agree on transport mode representation', async () => {
    const {context, get} = createDashboard();

    // 1. Agent cards: test reality, https_pinned, and http
    context.apiFetch = async () => ({
        ok: true,
        json: async () => ({
            agents: [
                {id: 'a1', hostname: 'host-reality', os: 'linux', ip: '10.0.0.1', last_seen: '2026-09-24T00:00:00Z', transport_mode: 'reality', decoy_domain: 'decoy.example'},
                {id: 'a2', hostname: 'host-tls', os: 'linux', ip: '10.0.0.2', last_seen: '2026-09-24T00:00:00Z', transport_mode: 'https_pinned', decoy_domain: null},
                {id: 'a3', hostname: 'host-http', os: 'linux', ip: '10.0.0.3', last_seen: '2026-09-24T00:00:00Z', transport_mode: 'http', decoy_domain: null},
                {id: 'a4', hostname: 'host-empty', os: 'linux', ip: '10.0.0.4', last_seen: '2026-09-24T00:00:00Z', transport_mode: '', decoy_domain: null},
            ]
        })
    });
    context.refreshAgents();
    await flush();

    const agentsHtml = get('agent-list').innerHTML;
    assert.match(agentsHtml, /agent-transport-badge reality.*REALITY · decoy\.example/);
    assert.match(agentsHtml, /agent-transport-badge tls.*TLS/);
    assert.match(agentsHtml, /Transport unknown · 10\.0\.0\.4/);
    assert.match(agentsHtml, /<button class="btn-force-delete-agent"[^>]*>Forget record<\/button>/);

    // 2. Build list: test reality, https_pinned, and http
    context.apiFetch = async () => ({
        ok: true,
        json: async () => ({
            builds: [
                {id: 1, filename: 'b-reality', target_os: 'linux', arch: 'amd64', file_size: 100, created_at: '2026-09-24T00:00:00Z', transport_mode: 'reality', decoy_domain: 'decoy.example'},
                {id: 2, filename: 'b-tls', target_os: 'linux', arch: 'amd64', file_size: 100, created_at: '2026-09-24T00:00:00Z', transport_mode: 'https_pinned', decoy_domain: null},
                {id: 3, filename: 'b-http', target_os: 'linux', arch: 'amd64', file_size: 100, created_at: '2026-09-24T00:00:00Z', transport_mode: 'http', decoy_domain: null},
            ]
        })
    });
    context.loadBuilds();
    await flush();

    const buildsHtml = get('payload-list').innerHTML;
    assert.match(buildsHtml, /payload-reality-badge.*REALITY · decoy\.example/);
    assert.match(buildsHtml, /payload-tls-badge.*TLS/);
    assert.match(buildsHtml, /payload-http-badge.*HTTP/);
});

const agentFixture = {id: 'fixture', hostname: 'saved-host', os: 'linux', last_seen: '2026-09-24T00:00:00Z'};

test('agent refresh failures preserve the last list, show a warning, and recover', async () => {
    const {context, get} = createDashboard();
    context.apiFetch = async () => ({ok: true, json: async () => ({agents: [agentFixture]})});
    context.refreshAgents();
    await flush();
    const savedList = get('agent-list').innerHTML;
    assert.match(savedList, /saved-host/);
    const failures = [
        async () => ({ok: false, status: 503, json: async () => ({agents: []})}),
        async () => { throw new Error('Network unavailable'); },
        ...[null, {}, {agents: null}, {agents: [null]}, {agents: [{id: 7}]}]
            .map(body => async () => ({ok: true, json: async () => body})),
    ];
    for (const failure of failures) {
        context.apiFetch = failure;
        context.refreshAgents();
        await flush();
        assert.equal(get('agent-list').innerHTML, savedList);
        assert.match(get('agents-status').textContent, /Could not refresh agents.*last successful list/);
    }
    context.apiFetch = async () => ({ok: true, json: async () => ({agents: []})});
    context.refreshAgents();
    await flush();
    assert.match(get('agent-list').innerHTML, /No agents connected/);
    assert.equal(get('agents-status').textContent, '');
});

test('an initial agent refresh failure reports unavailable data', async () => {
    const {context, get} = createDashboard();
    get('agent-list').innerHTML = 'Agent list unavailable';
    context.apiFetch = async () => ({ok: false, status: 500});
    context.refreshAgents();
    await flush();
    assert.equal(get('agent-list').innerHTML, 'Agent list unavailable');
    assert.match(get('agents-status').textContent, /Agent list is unavailable/);
    assert.doesNotMatch(get('agents-status').textContent, /last successful list/);
});

test('late agent responses cannot replace a newer list or warning', async () => {
    const {context, get} = createDashboard();
    let resolveOld;
    context.apiFetch = () => new Promise(resolve => { resolveOld = resolve; });
    context.refreshAgents();
    context.apiFetch = async () => ({ok: true, json: async () => ({agents: [agentFixture]})});
    context.refreshAgents();
    await flush();
    const latest = get('agent-list').innerHTML;
    resolveOld({ok: true, json: async () => ({agents: []})});
    await flush();
    assert.equal(get('agent-list').innerHTML, latest);

    context.apiFetch = () => new Promise(resolve => { resolveOld = resolve; });
    context.refreshAgents();
    context.apiFetch = async () => ({ok: false, status: 503});
    context.refreshAgents();
    await flush();
    const warning = get('agents-status').textContent;
    resolveOld({ok: true, json: async () => ({agents: []})});
    await flush();
    assert.equal(get('agents-status').textContent, warning);
    assert.equal(get('agent-list').innerHTML, latest);
});

test('slow polling can still display a result while a newer request is pending', async () => {
    const {context, get} = createDashboard();
    const pending = [];
    context.apiFetch = () => new Promise(resolve => pending.push(resolve));
    context.refreshAgents();
    context.refreshAgents();
    pending[0]({ok: true, json: async () => ({agents: [agentFixture]})});
    await flush();
    assert.match(get('agent-list').innerHTML, /saved-host/);
    pending[1]({ok: true, json: async () => ({agents: []})});
    await flush();
    assert.match(get('agent-list').innerHTML, /No agents connected/);
});

test('build validation and staged upload errors use visible status without blocking', async () => {
    const {context, get} = createDashboard();
    context.buildAgent({preventDefault() {}});
    assert.match(get('build-validation-status').textContent, /Server URL is required/);
    context.stageFile();
    assert.match(get('stage-action-status').textContent, /Select a file/);
    get('stage-file-input').files = [{name: 'sample'}];
    context.apiFetch = async () => ({ok: false, status: 413, json: async () => ({error: 'too large'})});
    context.stageFile();
    await flush();
    assert.match(get('stage-action-status').textContent, /Upload failed: too large/);
    assert.equal(get('stage-btn').disabled, false);
});

test('forget record confirms its local scope and handles success and failures', async () => {
    const prompts = [];
    const {context, get} = createDashboard({confirm: message => { prompts.push(message); return true; }});
    context.apiFetch = async url => url.startsWith('/api/tasks/')
        ? {json: async () => ({tasks: []})}
        : {ok: true, json: async () => ({status: 'ok'})};
    context.refreshAgents = () => {};
    context.loadStats = () => {};
    context.selectAgent('agent-1');
    context.forceDeleteAgent('agent-1');
    await flush();
    assert.match(prompts[0], /does NOT remove anything from the agent's host/);
    assert.match(get('agents-action-status').textContent, /Server record removed/);
    assert.equal(get('command-input').disabled, true);
    assert.equal(get('send-btn').disabled, true);
    context.apiFetch = async () => ({ok: false, status: 500, json: async () => ({error: 'database busy'})});
    context.forceDeleteAgent('agent-2');
    await flush();
    assert.match(get('agents-action-status').textContent, /database busy/);
    context.apiFetch = async () => { throw new Error('offline'); };
    context.forceDeleteAgent('agent-2');
    await flush();
    assert.match(get('agents-action-status').textContent, /offline/);
});

test('live polling times out without marking the server task failed and ignores late output', async () => {
    const {context, get, timers, intervals} = createDashboard();
    const initialIntervals = new Set(intervals.keys());
    const initialTimers = new Set(timers.keys());
    let resolveResult;
    context.apiFetch = () => new Promise(resolve => { resolveResult = resolve; });
    context.pollForResult(31);
    const pollId = [...intervals.keys()].find(id => !initialIntervals.has(id));
    assert.ok(pollId);
    const tick = intervals.get(pollId);
    tick();
    const timeout = timers.get([...timers.keys()].find(id => !initialTimers.has(id)));
    timeout();
    assert.equal(intervals.has(pollId), false);
    assert.match(get('terminal-output').innerHTML, /Live polling stopped; check Task History/);
    assert.doesNotMatch(get('terminal-output').innerHTML, /failed/i);
    resolveResult({json: async () => ({results: [{output: 'late'}]})});
    await flush();
    assert.doesNotMatch(get('terminal-output').innerHTML, /late<\/div>/);
});

test('switching agents ignores a pending task submission response', async () => {
    const {context, get, intervals, timers} = createDashboard();
    context.loadTasks = () => {};
    context.selectAgent('agent-a');
    const initialIntervals = [...intervals.keys()];
    const initialTimers = [...timers.keys()];
    let resolveSubmission;
    context.apiFetch = (url, options) => {
        assert.equal(url, '/api/task');
        assert.equal(JSON.parse(options.body).agent_id, 'agent-a');
        return new Promise(resolve => { resolveSubmission = resolve; });
    };
    get('command-input').value = 'fixture';
    context.sendCommand();
    context.selectAgent('agent-b');
    const otherTerminal = get('terminal-output').innerHTML;
    resolveSubmission({ok: true, json: async () => ({task_id: 41})});
    await flush();
    assert.equal(get('terminal-output').innerHTML, otherTerminal);
    assert.deepEqual([...intervals.keys()], initialIntervals);
    assert.deepEqual([...timers.keys()], initialTimers);
});

test('a result already in flight cannot render after switching agents or returning to the old agent', async () => {
    for (const returnToOldAgent of [false, true]) {
        const {context, get, intervals, timers} = createDashboard();
        context.loadTasks = () => {};
        context.loadStats = () => { throw new Error('Stale result refreshed statistics'); };
        context.selectAgent('agent-a');
        let resolveResult;
        context.apiFetch = () => new Promise(resolve => { resolveResult = resolve; });
        const initialIntervals = [...intervals.keys()];
        const initialTimers = [...timers.keys()];
        context.pollForResult(42);
        const pollId = [...intervals.keys()].find(id => !initialIntervals.includes(id));
        intervals.get(pollId)();
        context.selectAgent('agent-b');
        if (returnToOldAgent) context.selectAgent('agent-a');
        const currentTerminal = get('terminal-output').innerHTML;
        resolveResult({json: async () => ({results: [{output: 'old task output'}]})});
        await flush();
        assert.equal(get('terminal-output').innerHTML, currentTerminal);
        assert.deepEqual([...intervals.keys()], initialIntervals);
        assert.deepEqual([...timers.keys()], initialTimers);
    }
});

test('a previous agent polling timeout cannot enter the current terminal', () => {
    const {context, get, intervals, timers} = createDashboard();
    context.loadTasks = () => {};
    context.selectAgent('agent-a');
    const initialIntervals = [...intervals.keys()];
    const initialTimers = [...timers.keys()];
    context.pollForResult(43);
    const timeoutId = [...timers.keys()].find(id => !initialTimers.includes(id));
    context.selectAgent('agent-b');
    const currentTerminal = get('terminal-output').innerHTML;
    timers.get(timeoutId)();
    assert.equal(get('terminal-output').innerHTML, currentTerminal);
    assert.deepEqual([...intervals.keys()], initialIntervals);
    assert.deepEqual([...timers.keys()], initialTimers);
});

test('polling stops before another request when the selected agent changes', () => {
    const {context, intervals, timers} = createDashboard();
    context.loadTasks = () => {};
    context.selectAgent('agent-a');
    context.apiFetch = () => { throw new Error('Stale polling issued a request'); };
    const initialIntervals = [...intervals.keys()];
    const initialTimers = [...timers.keys()];
    context.pollForResult(44);
    const pollId = [...intervals.keys()].find(id => !initialIntervals.includes(id));
    context.selectAgent('agent-b');
    intervals.get(pollId)();
    assert.deepEqual([...intervals.keys()], initialIntervals);
    assert.deepEqual([...timers.keys()], initialTimers);
});

test('live polling success stops timeout and shows output', async () => {
    const {context, get, timers, intervals} = createDashboard();
    const initialIntervals = new Set(intervals.keys());
    const initialTimers = new Set(timers.keys());
    context.apiFetch = async () => ({json: async () => ({results: [{output: '<done>'}]})});
    context.loadTasks = () => {};
    context.loadStats = () => {};
    context.pollForResult(32);
    const pollId = [...intervals.keys()].find(id => !initialIntervals.has(id));
    intervals.get(pollId)();
    await flush();
    assert.equal(intervals.has(pollId), false);
    assert.equal([...timers.keys()].some(id => !initialTimers.has(id)), false);
    assert.match(get('terminal-output').innerHTML, /&lt;done&gt;/);
    assert.match(get('terminal-output').innerHTML, /Complete/);
});

test('history displays escaped command and result and ignores old agent responses', async () => {
    const {context, get} = createDashboard();
    const pending = [];
    context.apiFetch = url => new Promise(resolve => pending.push({url, resolve}));
    context.selectAgent('first');
    context.selectAgent('second');
    pending[1].resolve({json: async () => ({tasks: [{id: 2, command: '<safe>', status: 'complete'}]})});
    await flush();
    pending[0].resolve({json: async () => ({tasks: [{id: 1, command: 'stale', status: 'complete'}]})});
    await flush();
    assert.match(get('task-list').innerHTML, /&lt;safe&gt;/);
    assert.doesNotMatch(get('task-list').innerHTML, /stale/);
    context.viewTaskResult(2);
    pending[2].resolve({json: async () => ({results: [{output: '<result>'}]})});
    await flush();
    assert.match(get('terminal-output').innerHTML, /&lt;safe&gt;/);
    assert.match(get('terminal-output').innerHTML, /&lt;result&gt;/);
    context.viewTaskResult(2);
    context.selectAgent('third');
    pending[3].resolve({json: async () => ({results: [{output: 'stale output'}]})});
    await flush();
    assert.doesNotMatch(get('terminal-output').innerHTML, /stale output/);
});

test('certificate deletion failure remains visible and restores button', async () => {
    const {context, get} = createDashboard({confirm: () => true});
    context.apiFetch = async () => ({ok: false, status: 500, json: async () => ({error: 'busy'})});
    context.deleteCert();
    await flush();
    assert.match(get('tls-action-status').textContent, /Certificate deletion failed: busy/);
    assert.equal(get('tls-delete-btn').disabled, false);
});

test('self-destruct reports rejected responses and network failures without success state', async () => {
    const {context, get} = createDashboard({confirm: () => true});
    for (const failure of [
        async () => ({ok: false, status: 500, json: async () => ({error: 'server busy'})}),
        async () => { throw new Error('offline'); },
    ]) {
        get('terminal-output').innerHTML = '';
        context.apiFetch = failure;
        context.deleteAgent('agent-1');
        await flush();
        assert.match(get('agents-action-status').textContent, /Could not queue self-destruct/);
        assert.doesNotMatch(get('terminal-output').innerHTML, /Self-destruct queued/);
    }
});

test('failed command submission replaces its waiting line with the actual error', async () => {
    const {context, get} = createDashboard();
    context.loadTasks = () => {};
    context.selectAgent('agent-1');
    for (const failure of [
        async () => ({ok: false, status: 400, json: async () => ({error: 'invalid command'})}),
        async () => { throw new Error('offline'); },
    ]) {
        context.apiFetch = failure;
        get('command-input').value = 'whoami';
        context.sendCommand();
        await flush();
        assert.match(get('terminal-output').innerHTML, /Task submission failed/);
        assert.doesNotMatch(get('terminal-output').innerHTML, /Submitting task/);
    }
});

test('loot and staged-file deletion show HTTP and network failures', async () => {
    const {context, get} = createDashboard({confirm: () => true});
    for (const [action, statusId] of [
        [() => context.deleteLoot(1), 'loot-action-status'],
        [() => context.deleteStagedFile(2), 'staged-delete-status'],
    ]) {
        context.apiFetch = async () => ({ok: false, status: 409, json: async () => ({error: 'record locked'})});
        action();
        await flush();
        assert.match(get(statusId).textContent, /deletion failed: record locked/i);
        context.apiFetch = async () => { throw new Error('offline'); };
        action();
        await flush();
        assert.match(get(statusId).textContent, /deletion failed: offline/i);
    }
});

test('sent tasks display delivery uncertainty and manual abandonment warns about duplicate execution', async () => {
    const prompts = [];
    const {context, get} = createDashboard({confirm: message => { prompts.push(message); return true; }});
    context.apiFetch = async url => url.startsWith('/api/tasks/') && !url.endsWith('/abandon')
        ? {json: async () => ({tasks: [{id: 9, command: 'whoami', status: 'sent'}]})}
        : {ok: true, json: async () => ({status: 'ok'})};
    context.selectAgent('agent-1');
    await flush();
    assert.match(get('task-list').innerHTML, /Delivery uncertain/);
    assert.match(get('task-list').innerHTML, /Abandon/);
    context.abandonTask(9);
    await flush();
    assert.match(prompts[0], /may execute it twice/);
    assert.match(get('task-action-status').textContent, /could execute it twice/);
});
