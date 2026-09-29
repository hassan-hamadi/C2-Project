// Isolated dashboard harness: no network requests, downloads, or real timers.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../static/dashboard.js'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));

function createDashboard(globals = {}) {
    const elements = new Map();
    const timers = new Map();
    const intervals = new Map();
    const downloads = [];
    let timerId = 0;
    function get(id) {
        if (!elements.has(id)) {
            const classes = new Set();
            const listeners = new Map();
            elements.set(id, {
                value: '', textContent: '', innerHTML: '', disabled: false, style: {},
                classList: {
                    add: name => classes.add(name),
                    remove: name => classes.delete(name),
                    contains: name => classes.has(name),
                    toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name),
                },
                addEventListener: (name, callback) => listeners.set(name, callback),
                dispatch: name => listeners.get(name)?.(),
                querySelector(selector) {
                    const marker = selector.match(/^\[data-submission-id="(\d+)"\]$/);
                    if (!marker) return null;
                    const element = elements.get(id);
                    const linePattern = new RegExp(`<div class="([^"]*)" data-submission-id="${marker[1]}">([^<]*)<\\/div>`);
                    if (!linePattern.test(element.innerHTML)) return null;
                    return {
                        set className(value) { element.innerHTML = element.innerHTML.replace(linePattern, `<div class="${value}" data-submission-id="${marker[1]}">$2</div>`); },
                        set textContent(value) { element.innerHTML = element.innerHTML.replace(linePattern, (_, classes) => `<div class="${classes}" data-submission-id="${marker[1]}">${value}</div>`); },
                    };
                },
                insertAdjacentHTML: (_, html) => { elements.get(id).innerHTML += html; },
                focus() {},
            });
        }
        return elements.get(id);
    }
    const windowListeners = new Map();
    const documentListeners = new Map();
    const context = vm.createContext({
        document: {
            getElementById: get,
            querySelectorAll: () => [],
            createElement: () => ({click() { downloads.push(this.download); }}),
            body: {appendChild() {}, removeChild() {}},
            addEventListener: (name, cb) => {
                if (!documentListeners.has(name)) documentListeners.set(name, []);
                documentListeners.get(name).push(cb);
            },
            dispatch: name => {
                for (const cb of documentListeners.get(name) || []) cb();
            },
        },
        window: {
            URL: {createObjectURL: () => 'blob:fixture', revokeObjectURL() {}},
            location: {assign: globals.locationAssign || (() => {})},
            addEventListener: (name, cb) => {
                if (!windowListeners.has(name)) windowListeners.set(name, []);
                windowListeners.get(name).push(cb);
            },
            dispatch: name => {
                for (const cb of windowListeners.get(name) || []) cb();
            },
        },
        setInterval: callback => { intervals.set(++timerId, callback); return timerId; },
        clearInterval: id => intervals.delete(id),
        setTimeout: callback => { timers.set(++timerId, callback); return timerId; },
        clearTimeout: id => timers.delete(id),
        AbortController,
        FormData: class { append() {} },
        fetch: () => Promise.reject(new Error('Network access is disabled in this harness')),
        alert: message => { throw new Error(message); },
        ...globals,
    });
    vm.runInContext(source, context);
    return {context, get, timers, intervals, downloads, windowListeners, documentListeners};
}

module.exports = {createDashboard, flush};
