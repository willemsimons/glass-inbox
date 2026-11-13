// Execute the actual desktop merge code with a fake DOM and a controlled snapshot request.
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = readFileSync('inbox.py', 'utf8');
const start = source.indexOf('  // Preserve open drafts, selection, and scroll position');
const code = source.slice(start, source.indexOf('  const foot = document.querySelector', start));
function context() {
  const c = { composing: null, draft: null, drag: null, picks: new Set(), pendingWrites: 0, revision: 0, search: '', searchHits: null,
    document: { hidden: false, activeElement: null, querySelectorAll: () => [], addEventListener: () => {} },
    setInterval: () => {}, toast: () => {}, fail: e => { throw e; },
    mail: [{ id: 9, a: 'work', gmailId: 'same' }, { id: 10, a: 'personal', gmailId: 'same' }], sel: 10,
    events: [], ev: e => e, REAL: {}, NOW: {}, undoFn: () => {}, evUndo: () => {}, threads: { stale: 1 },
    render: () => { c.renders++; }, renders: 0, calls: 0,
    call: async () => { c.calls++; return { mail: [{ id: 1, a: 'personal', gmailId: 'same', unread: false }, { id: 2, a: 'work', gmailId: 'new' }], events: [], base: [2026, 10, 3], now: { day: 1 } }; }
  };
  vm.createContext(c); vm.runInContext(code, c); return c;
}
(async () => {
  let c = context(); await c.syncSnapshot();
  assert.equal(c.sel, 10); assert.equal(c.mail[0].id, 10); assert.equal(c.mail[0].unread, false);
  assert.equal(c.mail[1].id, 11); assert.equal(c.renders, 1); assert.equal(Object.keys(c.threads).length, 0);
  c = context(); c.composing = { body: 'keep my draft' }; await c.syncSnapshot(); assert.equal(c.calls, 0);
  c = context(); c.pendingWrites = 1; await c.syncSnapshot(); assert.equal(c.calls, 0);
  c = context(); c.searchHits = new Set([9]); await c.syncSnapshot(); assert.equal(c.calls, 0);
  c = context(); const fetch = c.call; c.call = async () => { const data = await fetch(); c.revision++; return data; };
  await c.syncSnapshot(); assert.equal(c.renders, 0); assert.equal(c.mail[0].id, 9);
  console.log('Desktop merge: 5 scenarios passed (account identity, draft preservation, pending writes, open search, stale snapshot).');
})().catch(error => { console.error(error); process.exitCode = 1; });
