const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const dashboardDirectory = path.join(__dirname, '../dashboard');
const pageFiles = {
  dashboard: 'index.html', scan: 'scan.html', history: 'history.html',
  policy: 'policy.html', users: 'users.html', login: 'login.html',
};

function pageScripts(page) {
  const html = fs.readFileSync(path.join(dashboardDirectory, pageFiles[page]), 'utf8');
  return [...html.matchAll(/<script src="([^"]+)" defer><\/script>/g)]
    .map((match) => ({name: match[1], source: fs.readFileSync(path.join(dashboardDirectory, match[1]), 'utf8')}));
}
function harness(search = '?repository=1&branch=test%2Fallow&scan=2', page = 'history') {
  const nodes = new Map();
  const intervals = [];
  const listeners = [];
  let scrolls = 0;
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, {
      innerHTML: '', textContent: '', hidden: true, dataset: {},
      querySelector: () => null, focus: () => {},
      scrollIntoView: () => { scrolls++; },
    });
    return nodes.get(id);
  };
  const context = {
    URL, URLSearchParams, console,
    location: {search},
    document: {
      body: {dataset: {page}}, visibilityState: 'visible',
      getElementById: node,
      addEventListener: (name) => listeners.push(name),
      querySelectorAll: () => [],
    },
    window: {
      matchMedia: () => ({}), addEventListener: () => {},
      setInterval: (_, delay) => intervals.push(delay),
    },
  };
  context.history = {replaceState: (_, __, url) => {
    context.location.search = new URL(url, 'https://local/dashboard/').search;
  }};
  vm.createContext(context);
  for (const script of pageScripts(page)) {
    vm.runInContext(script.source, context, {filename: script.name});
  }
  const run = code => vm.runInContext(code, context);
  run('state.user = {role: "viewer"}; state.scans.set("2", {id:2, repository_id:1, repository_name:"test", status:"BLOCK", github:{branch:"test/allow",commit_sha:"a".repeat(40)}})');
  return {context, node, run, intervals, listeners, scrolls: () => scrolls};
}

test('each page loads shared assets and its own script without duplicate startup hooks', () => {
  const scripts = {
    dashboard: 'dashboard', scan: 'monitoring', history: 'history',
    policy: 'policy', users: 'users', login: 'login',
  };
  for (const [page, script] of Object.entries(scripts)) {
    assert.deepEqual(pageScripts(page).map(item => item.name), [
      'scripts/common.js', `scripts/${script}.js`,
    ]);
    const html = fs.readFileSync(path.join(dashboardDirectory, pageFiles[page]), 'utf8');
    const styles = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)"/g)].map(match => match[1]);
    assert.deepEqual(styles, ['css/base.css', 'css/layout.css', 'css/components.css', `css/${script}.css`]);
    for (const file of styles) assert.ok(fs.existsSync(path.join(dashboardDirectory, file)));
    const h = harness('', page);
    assert.deepEqual(h.intervals, [5000, 60000]);
    assert.equal(h.listeners.filter(name => name === 'DOMContentLoaded').length, 1);
    assert.equal(h.listeners.filter(name => name === 'click').length, 1);
    for (const [otherPage, pageFunction] of Object.entries({
      dashboard: 'loadDashboard', scan: 'loadRepositorySelect', history: 'loadHistory',
      policy: 'loadPolicy', users: 'loadUsers', login: 'initLogin',
    })) {
      assert.equal(h.run(`typeof ${pageFunction}`), otherPage === page ? 'function' : 'undefined');
    }
  }
});

test('shared template formatting preserves interpolation semantics and does not replace escaping', () => {
  const h = harness();
  assert.equal(h.run('templateText(null)'), 'null');
  assert.equal(h.run('templateText(undefined)'), 'undefined');
  assert.equal(h.run('templateText({[Symbol.toPrimitive](hint){return hint;}})'), 'string');
  assert.equal(h.run('templateText("<unsafe>")'), '<unsafe>');
  assert.equal(h.run('templateText(escapeHtml("<unsafe>"))'), '&lt;unsafe&gt;');
  assert.throws(() => h.run('templateText(Symbol("test"))'), /Symbol/);
});

test('repository-scoped history can render shared branch disclosures without the Dashboard script', () => {
  const h = harness('?repository=1');
  const html = h.run('historyScope({id:1,name:"repo",tracking:{branches:[{branch:"main",execution_status:"completed",policy_status:"BLOCK",findings:1}]}},null,null)');
  assert.ok(html.includes('data-repository-group="1"'));
  assert.ok(html.includes('BLOCK'));
  assert.ok(html.includes('branch=main'));
  assert.equal(h.run('typeof loadDashboard'), 'undefined');
});

test('finding keeps original path and adds English location and commit-specific link', () => {
  const h = harness();
  const html = h.run('findingRow({scanner:"Bandit",file:"/home/runner/work/repo/repo/target/src/app.py",line:3}, "", {full_name:"owner/repo",commit_sha:"a".repeat(40)})');
  assert.ok(html.includes('Bandit / /home/runner/work/repo/repo/target/src/app.py:3'));
  assert.ok(html.includes('<dt>Affected file</dt><dd><code>src/app.py</code>'));
  assert.ok(html.includes('<dt>Line</dt><dd>3</dd>'));
  assert.ok(html.includes('/src/app.py#L3'));
  assert.ok(html.includes('Open file on GitHub'));
  h.context.windowsPath = String.raw`C:\a\repo\repo\target\src\app.py`;
  assert.equal(h.run('reportFilePath(windowsPath)'), 'src/app.py');
});

test('unknown locations remain visible, missing lines and unsafe paths do not invent links', () => {
  const h = harness();
  assert.equal(h.run('reportFilePath("/unknown/place/file.py")'), '/unknown/place/file.py');
  const html = h.run('findingRow({file:"../<unsafe>.py",line:0}, "", {full_name:"owner/repo",commit_sha:"a".repeat(40)})');
  assert.ok(html.includes('&lt;unsafe&gt;'));
  assert.ok(html.includes('<dt>Line</dt><dd>Not available</dd>'));
  assert.ok(!html.includes('Open file on GitHub'));
});

test('close during findings request removes scan from URL and ignores late response', async () => {
  const h = harness();
  let resolve;
  h.context.pending = new Promise(done => { resolve = done; });
  h.run('fetchJson = () => pending');
  const request = h.run('showHistoryFindings("2")');
  assert.ok(h.node('history-detail').innerHTML.includes('Close details'));
  h.run('closeHistoryFindings()');
  assert.equal(h.node('history-detail').hidden, true);
  assert.equal(new URLSearchParams(h.context.location.search).get('scan'), null);
  assert.equal(new URLSearchParams(h.context.location.search).get('branch'), 'test/allow');
  resolve({findings: []});
  await request;
  assert.equal(h.node('history-detail').innerHTML, '');
  assert.equal(h.node('history-detail').hidden, true);
});

test('background history refresh updates list without changing or scrolling open details', async () => {
  const h = harness();
  h.context.calls = [];
  h.run('fetchJson = async url => { calls.push(url); return url === API.scans ? {scans:[state.scans.get("2")]} : {repositories:[{id:1,name:"test",tracking:{branches:[]}}]}; }');
  h.node('history-detail').hidden = false;
  h.node('history-detail').innerHTML = 'Reading scan 2';
  await h.run('loadHistory({background:true})');
  assert.equal(h.node('history-detail').innerHTML, 'Reading scan 2');
  assert.equal(h.scrolls(), 0);
  assert.ok(!h.context.calls.some(url => url.includes('/findings')));
  h.run('closeHistoryFindings()');
  await h.run('loadHistory({background:true})');
  assert.equal(h.node('history-detail').hidden, true);
  assert.equal(h.scrolls(), 0);
});

test('late history response cannot restore a closed scan in the breadcrumb', async () => {
  const h = harness();
  let resolve;
  h.context.pending = new Promise(done => { resolve = done; });
  h.run('fetchJson = () => pending');
  const request = h.run('loadHistory({background:true})');
  h.run('closeHistoryFindings()');
  resolve({scans: []});
  await request;
  assert.equal(h.node('history-scope').innerHTML, '');
  assert.equal(h.node('history-detail').hidden, true);
});

test('background refresh skips hidden tabs and prevents overlapping requests', async () => {
  const h = harness();
  h.context.refreshes = 0;
  let resolve;
  h.context.pending = new Promise(done => { resolve = done; });
  h.run('loadHistory = async () => { refreshes++; await pending; }');
  h.context.document.visibilityState = 'hidden';
  await h.run('refreshVisiblePage()');
  assert.equal(h.context.refreshes, 0);
  h.context.document.visibilityState = 'visible';
  const first = h.run('refreshVisiblePage()');
  await h.run('refreshVisiblePage()');
  assert.equal(h.context.refreshes, 1);
  resolve();
  await first;
});

test('failed findings request still provides a working close control', async () => {
  const h = harness();
  h.run('fetchJson = async () => { throw new Error("Report not available"); }');
  await h.run('showHistoryFindings("2", {scroll:false})');
  assert.ok(h.node('history-detail').innerHTML.includes('Close details'));
  assert.ok(h.node('history-detail').innerHTML.includes('Report not available'));
  assert.equal(h.scrolls(), 0);
  h.run('closeHistoryFindings()');
  assert.equal(h.node('history-detail').hidden, true);
});

test('history search and filters combine without changing the selected scan', () => {
  const h = harness();
  h.run(`state.scopedScans = [
    {id:2,repository_id:1,repository_name:'alpha',status:'BLOCK',scanned_at:'2026-10-01',github:{branch:'test/fix',commit_sha:'abc',commit_message:'Fix issue'}},
    {id:3,repository_id:2,repository_name:'beta',status:'ALLOW',scanned_at:'2026-10-02',github:{branch:'main',commit_sha:'def',commit_message:'Clean'}},
    {id:4,repository_id:1,repository_name:'alpha',status:'ALLOW',scanned_at:'2026-10-03',github:{branch:'test/fix',commit_sha:'aaa',commit_message:'Follow up'}}
  ]; state.historyFilters = {search:'FIX',repository:'1',gate:'BLOCK'}; renderHistoryList();`);
  const html = h.node('history-container').innerHTML;
  assert.ok(html.includes('Fix issue'));
  assert.ok(!html.includes('Follow up'));
  assert.ok(!html.includes('Clean'));
  assert.equal(new URLSearchParams(h.context.location.search).get('scan'), '2');
  h.run('state.historyFilters.search="unmatched"; renderHistoryList()');
  assert.ok(h.node('history-container').innerHTML.includes('No matching scans'));
});

test('history stats describe all scoped records before search filters', () => {
  const h = harness();
  h.run(`state.scopedScans=[{repository_id:1,repository_name:'repo',status:'ALLOW',findings:0},{repository_id:1,repository_name:'repo',status:'BLOCK',findings:15}];
    state.historyFilters.gate='ALLOW'; renderHistoryStats();`);
  const html = h.node('history-stats').innerHTML;
  assert.ok(html.includes('Recorded scans'));
  assert.ok(html.includes('<strong>2</strong>'));
  assert.ok(html.includes('<strong>15</strong>'));
  assert.ok(h.node('history-stats-scope').textContent.includes('before search filters'));
});

test('new scans do not narrow the history table after selecting a scan', async () => {
  const h = harness('');
  h.run(`fetchJson = async url => url === API.scans ? {scans:[state.scans.get('2'),{id:3,repository_id:9,repository_name:'another',status:'ALLOW'}]} : {repositories:[]};`);
  await h.run('loadHistory({background:true})');
  h.run('fetchJson = async () => ({findings:[]})');
  await h.run('showHistoryFindings("2",{scroll:false})');
  h.run(`fetchJson = async url => url === API.scans ? {scans:[state.scans.get('2'),{id:3,repository_id:9,repository_name:'another',status:'ALLOW'}]} : {repositories:[]};`);
  await h.run('loadHistory({background:true})');
  assert.ok(h.node('history-container').innerHTML.includes('another'));
});

test('finding severity sort is stable, preserves source order and supports scanner filtering', () => {
  const h = harness();
  h.run(`globalThis.findings = [
    {scanner:'Bandit',severity:'LOW'}, {scanner:'Trivy',severity:'CRITICAL'},
    {scanner:'Gitleaks',severity:'HIGH'}, {scanner:'Bandit',severity:'HIGH'}
  ]`);
  assert.equal(h.run('filteredFindings(findings).map(row=>row.index).join(",")'), '1,2,3,0');
  assert.equal(h.run('findings[0].severity'), 'LOW');
  h.run('state.detailFilters.scanner="Bandit"');
  assert.equal(h.run('filteredFindings(findings).map(row=>row.index).join(",")'), '3,0');
  h.run('state.detailFilters.sort="original"');
  assert.equal(h.run('filteredFindings(findings).map(row=>row.index).join(",")'), '0,3');
});

test('finding disclosure is keyed by original index across filtering and sorting', () => {
  const h = harness();
  h.run('state.findingDisclosure.set("2:3", false)');
  const html = h.run('findingCard({rule_id:"B602",scanner:"Bandit",severity:"HIGH",message:"<unsafe>"},3,state.scans.get("2"))');
  assert.ok(!html.includes(' open>'));
  assert.ok(html.includes('&lt;unsafe&gt;'));
  assert.ok(html.includes('Source link unavailable'));
  assert.ok(html.includes('data-finding-key="2:3"'));
});

test('ALLOW, BLOCK, unknown policies and legacy reports render distinct detail states', () => {
  const h = harness();
  assert.ok(h.run('detailView({id:1,status:"ALLOW",score:100,grade:"A"},[])').includes('Security gate allowed'));
  assert.ok(h.run('detailView({id:1,status:"BLOCK",score:75,grade:"C"},[])').includes('Security gate blocked'));
  const unknown = h.run('detailView({id:1},[])');
  assert.ok(unknown.includes('Policy not evaluated'));
  assert.ok(unknown.includes('Legacy local scan'));
  assert.ok(unknown.includes('Not available'));
  h.run('state.selectedDetail={scan:{id:1},findings:[]}; renderDetailFindings()');
  assert.ok(h.node('detail-findings-list').innerHTML.includes('No findings'));
  h.run('state.selectedDetail.findings=[{scanner:"Bandit"}];state.detailFilters.scanner="Trivy";renderDetailFindings()');
  assert.ok(h.node('detail-findings-list').innerHTML.includes('No matching findings'));
});

test('failed run history opens without requesting findings or claiming a clean result', async () => {
  const h = harness();
  h.run(`state.scans.set('run-1-10-1',{id:'run-1-10-1',repository_id:1,report_available:false,execution_status:'error',status:null,score:null,reason:'Report validation failed',github:{run_id:10,run_attempt:1,branch:'main'}});
    fetchJson=async()=>{throw new Error('Must not request findings for an unvalidated report')}`);
  await h.run(`showHistoryFindings('run-1-10-1',{scroll:false})`);
  assert.ok(h.node('history-detail').innerHTML.includes('ERROR'));
  assert.ok(h.node('history-detail').innerHTML.includes('Policy not evaluated'));
  assert.ok(h.node('detail-findings-list').innerHTML.includes('No validated report'));
  assert.ok(!h.node('detail-findings-list').innerHTML.includes('No findings in this recorded scan'));
  assert.equal(h.scrolls(), 0);
});

function monitoringHarness() {
  const h = harness('', 'scan');
  h.context.Option = function(text, value) { this.text = text; this.value = value; };
  const select = h.node('repository-select');
  select.value = '';
  select.options = [];
  select.replaceChildren = (...options) => { select.options = options; select.value = options[0]?.value || ''; };
  select.add = option => select.options.push(option);
  return h;
}

test('monitoring distinguishes evaluated findings from pending and failed branches', () => {
  const h = monitoringHarness();
  h.run(`state.monitoringRepositories.set('1',{id:1,name:'real-repo',tracking:{branches:[
    {branch:'test/allow',execution_status:'completed',policy_status:'ALLOW',findings:0},
    {branch:'test/block',execution_status:'completed',policy_status:'BLOCK',findings:15},
    {branch:'main',execution_status:'running',policy_status:'ALLOW',findings:0},
    {branch:'error',execution_status:'error',policy_status:'ALLOW',message:'Report unavailable'},
    {branch:'warn',execution_status:'completed',policy_status:'WARN',findings:1}
  ]}}); document.getElementById('repository-select').value='1'; renderMonitoringRepository()`);
  const html = h.node('scan-results').innerHTML;
  assert.equal(h.node('scan-results').hidden, false);
  assert.ok(html.includes('real-repo'));
  assert.ok(html.includes('15 findings'));
  assert.ok(html.includes('0 findings'));
  assert.ok(html.includes('WARN, 1 finding'));
  assert.ok(html.includes('View main history: RUNNING, Not evaluated'));
  assert.ok(html.includes('View error history: ERROR, Not evaluated'));
  assert.ok(html.includes('history.html?repository=1&amp;branch=test%2Fblock') || html.includes('history.html?repository=1&branch=test%2Fblock'));
  assert.ok(html.includes('Report unavailable'));
});

test('monitoring escapes repository, branch and error content and clears deselected results', () => {
  const h = monitoringHarness();
  h.run(`state.monitoringRepositories.set('1',{id:1,name:'<repo>',tracking:{message:'<error>',branches:[{branch:'test/<script>',execution_status:'error',message:'<img onerror="bad">'}]}});
    document.getElementById('repository-select').value='1'; renderMonitoringRepository()`);
  const html = h.node('scan-results').innerHTML;
  assert.ok(html.includes('&lt;repo&gt;'));
  assert.ok(html.includes('&lt;error&gt;'));
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<script>'));
  h.node('repository-select').value = '';
  h.run('renderMonitoringRepository()');
  assert.equal(h.node('scan-results').hidden, true);
  assert.equal(h.node('scan-results').innerHTML, '');
});

test('monitoring background update honors a selection changed during the request', async () => {
  const h = monitoringHarness();
  const select = h.node('repository-select');
  select.value = '1';
  let resolve;
  h.context.pending = new Promise(done => { resolve = done; });
  h.run('fetchJson=()=>pending');
  const request = h.run('loadRepositorySelect({background:true})');
  select.value = '2';
  resolve({repositories:[{id:1,name:'first'}, {id:2,name:'second',tracking:{synced_at:'2026-10-19T08:00:00Z',branches:[]}}]});
  await request;
  assert.equal(select.value, '2');
  assert.ok(h.node('scan-results').innerHTML.includes('second'));
  assert.ok(!h.node('scan-results').innerHTML.includes('first'));
  assert.ok(h.node('monitoring-last-sync').textContent.startsWith('Last synced:'));
});

test('monitoring refresh failure removes stale ALLOW results and disables unavailable selection', async () => {
  const h = monitoringHarness();
  h.run(`state.monitoringRepositories.set('1',{id:1,name:'repo',tracking:{branches:[{branch:'main',execution_status:'completed',policy_status:'ALLOW',findings:0}]}});
    document.getElementById('repository-select').value='1'; renderMonitoringRepository();
    fetchJson=async()=>{throw new Error('API unavailable')}`);
  assert.ok(h.node('scan-results').innerHTML.includes('ALLOW'));
  await h.run('loadRepositorySelect({background:true})');
  assert.equal(h.node('scan-results').hidden, true);
  assert.equal(h.node('scan-results').innerHTML, '');
  assert.equal(h.node('repository-select').disabled, true);
  assert.ok(h.node('scan-message').innerHTML.includes('API unavailable'));
  assert.equal(h.node('monitoring-last-sync').textContent, 'Could not refresh repository data');
});
