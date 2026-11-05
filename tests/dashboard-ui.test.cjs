const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const dashboardDirectory = path.join(__dirname, '../dashboard');
const pageFiles = {
  dashboard: 'index.html', scan: 'scan.html', history: 'history.html',
  policy: 'policy.html', users: 'users.html', login: 'login.html',
  settings: 'settings.html', 'scan-detail':'scan-detail.html', members:'members.html',
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
    location: {search,href:'https://local/dashboard/'+pageFiles[page]+search,assign:url=>{context.navigation=url;},replace:url=>{context.redirect=url;}},
    sessionStorage: {getItem:key=>context.storage?.[key]??null,setItem:(key,value)=>{context.storage??={};context.storage[key]=value;}},
    document: {
      body: {dataset: {page}}, visibilityState: 'visible',
      getElementById: node,
      addEventListener: (name) => listeners.push(name),
      querySelectorAll: () => [],
    },
    window: {
      matchMedia: () => ({}), addEventListener: () => {}, scrollY:128, scrollTo:()=>{},
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
    settings: 'settings', 'scan-detail':'scan-detail', members:'members',
  };
  for (const [page, script] of Object.entries(scripts)) {
    assert.deepEqual(pageScripts(page).map(item => item.name), [
      'scripts/common.js', ...(['history','scan-detail'].includes(page)?['scripts/scan-renderer.js']:[]), `scripts/${script}.js`,
    ]);
    const html = fs.readFileSync(path.join(dashboardDirectory, pageFiles[page]), 'utf8');
    const styles = [...html.matchAll(/<link rel="stylesheet" href="([^"]+)"/g)].map(match => match[1]);
    assert.deepEqual(styles, ['css/base.css', 'css/layout.css', 'css/components.css', ...(['scan-detail'].includes(page)?['css/history.css']:[]), `css/${script}.css`]);
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

function settingsHarness() {
  const h = harness('', 'settings');
  h.run('state.user={role:"superuser"};');
  const fields = ['owner','app_id','installation_id','private_key_path','workflow'];
  for (const field of fields) {
    h.node(`setting-${field}`).value = field === 'owner' ? 'new-owner' : 'test-value';
    h.node(`setting-${field}`).setAttribute = () => {};
  }
  h.node('owner-settings-form').reportValidity = () => true;
  h.node('owner-settings-form').setAttribute = () => {};
  h.run('setMessage=(id,text,type)=>{el(id).textContent=text;el(id).messageType=type;};');
  h.node('settings-message').classList = {toggle: () => {}};
  return h;
}

test('Owner Settings test sends entered values without saving and blocks duplicate submissions', async () => {
  const h = settingsHarness();
  h.run('globalThis.calls=[]; fetchJson=(url,options)=>new Promise(resolve=>{calls.push({url,options});globalThis.finish=resolve;});');
  const pending = h.run('submitOwnerSettings(false)');
  await h.run('submitOwnerSettings(true)');
  assert.equal(h.run('calls.length'), 1);
  assert.equal(h.run('calls[0].url'), '/api/owner-settings/test');
  assert.equal(h.run('JSON.parse(calls[0].options.body).owner'), 'new-owner');
  assert.equal(h.node('owner-settings-fields').disabled, true);
  h.run('finish({message:"Connection verified.",repositories_accessible:2})');
  await pending;
  assert.ok(h.node('settings-message').textContent.includes('have not been saved'));
  assert.equal(h.node('owner-settings-fields').disabled, false);
});

test('Owner Settings errors remain text, highlight fields and preserve entered values', async () => {
  const h = settingsHarness();
  let focused = false;
  h.node('setting-owner').focus = () => {focused = true;};
  h.run('fetchJson=async()=>{const error=new ApiError("Invalid settings",422);error.fields={owner:"<invalid owner>"};throw error;};');
  await h.run('submitOwnerSettings(true)');
  assert.equal(h.node('error-owner').textContent, '<invalid owner>');
  assert.equal(h.node('setting-owner').value, 'new-owner');
  assert.equal(h.node('owner-settings-fields').disabled, false);
  assert.equal(focused, true);
});

test('Owner Settings saves verified values and refreshes connection status without starting a scan', async () => {
  const h = settingsHarness();
  h.run(`globalThis.calls=[]; fetchJson=async(url,options)=>{calls.push({url,options});return {source:"database",updated_at:null,settings:{owner:"new-owner",app_id:"123",installation_id:"456",private_key_path:"/safe/test.pem",workflow:"security-gate.yml"}}}; initializeGitHubMonitor=async(autoSync)=>{calls.push({autoSync})};`);
  await h.run('submitOwnerSettings(true)');
  assert.equal(h.run('calls[0].url'), '/api/owner-settings');
  assert.equal(h.run('calls[1].autoSync'), false);
  assert.equal(h.node('setting-app_id').value, '123');
  assert.ok(h.node('settings-message').textContent.includes('no Backend restart'));
  h.run('state.user={role:"viewer"};');
  await h.run('submitOwnerSettings(true)');
  assert.equal(h.run('calls.length'), 2);
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

test('View opens independent scan details and preserves History filters and scroll', () => {
  const h=harness('?repository=1&q=fix&page=2');
  h.run('initializeHistory();state.historyPage=2;openScanDetails("2")');
  const target=new URL(h.context.navigation,'https://local/dashboard/');
  assert.equal(target.pathname,'/dashboard/scan-detail.html');
  assert.equal(target.searchParams.get('scan'),'2');
  assert.ok(target.searchParams.get('return').includes('q=fix'));
  assert.ok(target.searchParams.get('return').includes('page=2'));
  assert.equal(Object.values(h.context.storage)[0],'128');
});

test('background History refresh updates only the list and never requests inline findings', async () => {
  const h=harness('?repository=1'); h.context.calls=[];
  h.run('fetchJson=async url=>{calls.push(url);return url===API.scans?{scans:[state.scans.get("2")]}:{repositories:[{id:1,name:"test",tracking:{branches:[]}}]}}');
  await h.run('loadHistory({background:true})');
  assert.ok(h.node('history-container').innerHTML.includes('test'));
  assert.equal(h.scrolls(),0);
  assert.ok(!h.context.calls.some(url=>url.includes('/findings')));
});

test('legacy History scan links redirect to details without a return loop or external return', () => {
  const h=harness(); assert.equal(h.run('initializeHistory()'),false);
  const target=new URL(h.context.redirect,'https://local/dashboard/');
  assert.equal(target.pathname,'/dashboard/scan-detail.html');
  assert.equal(new URL(target.searchParams.get('return'),'https://local/dashboard/').searchParams.has('scan'),false);
  for(const url of ['https://evil.example/dashboard/history.html','//evil.example','javascript:alert(1)','/dashboard/users.html']) {
    h.context.returnUrl=url; assert.equal(h.run('safeHistoryReturn(returnUrl)'),'history.html');
  }
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

test('detail Findings failure retains Back and clears stale scan content', async () => {
  const h=harness('?scan=2','scan-detail');
  h.run('fetchJson=async url=>{if(url.endsWith("/findings"))throw new ApiError("Access removed",404);return {scan:state.scans.get("2")}}');
  await h.run('loadScanDetail()');
  assert.ok(h.node('history-detail').innerHTML.includes('Back to history'));
  assert.ok(h.node('history-detail').innerHTML.includes('Access removed'));
  assert.equal(h.run('state.selectedDetail'),null);
  assert.equal(h.node('history-scope').innerHTML,'');
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

test('History pagination limits rows and retains its scope during background refresh', async () => {
  const h=harness('');
  h.run('globalThis.rows=Array.from({length:45},(_,i)=>({id:i+1,repository_id:1,repository_name:"repo-"+(i+1),status:"ALLOW"}));fetchJson=async()=>({scans:rows});state.historyPage=2;');
  await h.run('loadHistory({background:true})');
  const html=h.node('history-container').innerHTML;
  assert.equal((html.match(/data-action="show-findings"/g)||[]).length,20);
  assert.ok(html.includes('Page 2 of 3'));
  assert.equal(h.run('state.scopedScans.length'),45);
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

test('failed Run details load without findings or a fake ALLOW and stay on the same record', async () => {
  const h=harness('?scan=run-1-10-1','scan-detail');h.context.calls=[];
  h.run(`fetchJson=async url=>{calls.push(url);if(url.includes('/findings'))throw Error('No report');return {scan:{id:'run-1-10-1',repository_id:1,repository_name:'repo',report_available:false,execution_status:'error',status:null,score:null,reason:'Report validation failed',github:{branch:'main'}}}}`);
  await h.run('loadScanDetail()');
  assert.ok(h.node('history-detail').innerHTML.includes('Policy not evaluated'));
  assert.ok(h.node('detail-findings-list').innerHTML.includes('No validated report'));
  await h.run('loadScanDetail({background:true})');
  assert.ok(h.context.calls.every(url=>url.endsWith('/run-1-10-1')));
});

function monitoringHarness() {
  const h = harness('', 'scan');
  h.context.Option = function(text, value) { this.text = text; this.value = value; };
  const select = h.node('repository-select');
  select.value = ''; select.options = [];
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

function usersHarness() {
  const h = harness('', 'users');
  h.context.calls = [];
  h.context.confirmed = true;
  h.context.window.confirm = () => h.context.confirmed;
  h.context.location.replace = url => { h.context.redirect = url; };
  h.context.fixtureUsers = [
    {id:1, username:'admin', role:'superuser', is_active:true},
    {id:2, username:'viewer', role:'viewer', is_active:true},
  ];
  h.run('state.user={id:1,username:"admin",role:"superuser"}; state.csrf="test-csrf"; state.users=new Map(fixtureUsers.map(u=>[String(u.id),u])); setMessage=(id,text,type)=>{document.getElementById(id).textContent=text;document.getElementById(id).messageType=type;}; fetchJson=async(url,options={})=>{calls.push({url,...options});return url===API.users?{users:fixtureUsers}:url.endsWith("/audit")?{events:[]}:{user:fixtureUsers[1]};};');
  h.node('reset-password-form').reset = () => {
    for (const id of ['reset-password', 'confirm-reset-password']) h.node(id).value = '';
  };
  h.node('reset-password-dialog').showModal = () => { h.node('reset-password-dialog').open = true; };
  h.node('reset-password-dialog').close = () => { h.node('reset-password-dialog').open = false; };
  return h;
}

test('User access combines username search and Role and retains filters after refresh', async () => {
  const h = usersHarness();
  h.context.fixtureUsers.push(
    {id:3,username:'View-Operator',role:'operator',is_active:true},
    {id:4,username:'Other',role:'viewer',is_active:false},
  );
  h.run('userAccessFilters.search="  VIEW  ";userAccessFilters.role="viewer";');
  await h.run('loadUserList()');
  assert.equal(h.node('user-access-count').textContent, '1 of 4 users');
  assert.ok(h.node('users-container').innerHTML.includes('>viewer</strong>'));
  assert.ok(!h.node('users-container').innerHTML.includes('View-Operator'));
  assert.equal(h.run('state.users.size'), 4);
  h.context.fixtureUsers[1].role = 'operator';
  await h.run('loadUserList()');
  assert.equal(h.node('user-access-count').textContent, '0 of 4 users');
  assert.ok(h.node('users-container').innerHTML.includes('No matching users'));
  assert.equal(h.run('userAccessFilters.search'), '  VIEW  ');
  assert.equal(h.run('userAccessFilters.role'), 'viewer');
  h.run('userAccessFilters.search="";userAccessFilters.role="";renderUserList();');
  assert.equal(h.node('user-access-count').textContent, '4 of 4 users');
  assert.ok(h.node('users-container').innerHTML.includes('Disabled'));
});

test('failed user refresh clears stale accounts even when the filter changes', async () => {
  const h = usersHarness();
  await h.run('loadUserList()');
  h.run('fetchJson=async()=>{throw new Error("Access revoked");};');
  await h.run('loadUserList()');
  h.run('userAccessFilters.search="admin";renderUserList();');
  assert.equal(h.run('state.users.size'), 0);
  assert.equal(h.node('user-access-count').textContent, 'User list unavailable');
  assert.ok(h.node('users-container').innerHTML.includes('Access revoked'));
  assert.ok(!h.node('users-container').innerHTML.includes('data-action="delete-user"'));
});

test('User access search and Role events filter the cached list without additional requests', async () => {
  const h = usersHarness();
  const handlers = {};
  for (const id of ['user-access-search','user-access-role','create-user-form','reset-password-form','reset-password-dialog','cancel-reset-password']) {
    h.node(id).addEventListener = (name, callback) => {handlers[id+':'+name]=callback;};
  }
  await h.run('initializeUserManagement()');
  const calls = h.context.calls.length;
  h.node('user-access-search').value = 'VIEW';
  handlers['user-access-search:input']({target:h.node('user-access-search')});
  h.node('user-access-role').value = 'operator';
  handlers['user-access-role:change']({target:h.node('user-access-role')});
  assert.equal(h.node('user-access-count').textContent, '0 of 2 users');
  h.node('user-access-role').value = 'viewer';
  handlers['user-access-role:change']({target:h.node('user-access-role')});
  assert.equal(h.node('user-access-count').textContent, '1 of 2 users');
  assert.equal(h.context.calls.length, calls);
});

test('Members links preserve the originating page and the selected Monitoring repository', () => {
  const h = harness('?q=active', 'dashboard');
  let link = new URL(h.run('membersPageLink({id:7})'), 'https://local/dashboard/');
  assert.equal(link.searchParams.get('return'), 'index.html?q=active');
  const m = harness('?repository=1', 'scan');
  link = new URL(m.run('membersPageLink({id:7})'), 'https://local/dashboard/');
  assert.equal(link.searchParams.get('repository'), '7');
  assert.equal(link.searchParams.get('return'), 'scan.html?repository=7');
});

test('Monitoring restores the returned repository only when it appears in the allowed list', async () => {
  const h = monitoringHarness();
  h.run('location.search="?repository=7";fetchJson=async()=>({repositories:[{id:1,name:"first"},{id:7,name:"returned"}]});');
  await h.run('loadRepositorySelect()');
  assert.equal(h.node('repository-select').value, '7');
  h.node('repository-select').value = '';
  h.run('location.search="?repository=99";');
  await h.run('loadRepositorySelect()');
  assert.equal(h.node('repository-select').value, '');
  assert.equal(h.node('scan-results').innerHTML, '');
});

test('Members Back rejects unsafe destinations and Breadcrumb escapes repository names', () => {
  const h = harness('?repository=1&return=scan.html%3Frepository%3D1','members');
  h.run('renderMemberNavigation({id:1,name:"<img onerror=bad>"});');
  assert.equal(h.node('member-back-link').href, 'scan.html?repository=1');
  assert.equal(h.node('member-origin-tag').textContent, 'From Repository Monitoring');
  assert.ok(h.node('member-breadcrumbs').innerHTML.includes('Repository Monitoring'));
  assert.ok(h.node('member-breadcrumbs').innerHTML.includes('&lt;img'));
  assert.ok(!h.node('member-breadcrumbs').innerHTML.includes('<img'));
  for (const destination of ['https://evil.test/dashboard/scan.html','//evil.test/dashboard/','javascript:alert(1)','users.html','../api/users']) {
    h.context.destination = destination;
    assert.equal(h.run('memberReturnInfo(destination).href'), 'index.html');
  }
  assert.equal(h.run('memberReturnInfo("history.html?repository=1&scan=2&q=test").href'), 'history.html?repository=1&q=test');
  h.run('location.search="?repository=1";renderMemberNavigation();');
  assert.equal(h.node('member-origin-tag').textContent, 'Direct link');
  assert.equal(h.node('member-back-link').textContent, 'Back to Dashboard');
  assert.ok(!h.node('member-breadcrumbs').innerHTML.includes('&lt;img'));
});

test('user controls retain role and disable actions, add reset and prevent self deletion', async () => {
  const h = usersHarness();
  h.context.fixtureUsers[1].username = '<img onerror="bad">';
  await h.run('loadUserList()');
  const html = h.node('users-container').innerHTML;
  for (const action of ['save-user-role','toggle-user','reset-user-password','delete-user']) {
    assert.ok(html.includes('data-action="' + action + '"'));
  }
  assert.ok(html.includes('disabled title="You cannot delete your own account"'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes('<img'));
  assert.equal(h.run('auditChanges({action:"user.deleted"})'), 'Account deleted');
  assert.equal(h.run('auditChanges({action:"user.password_reset"})'), 'Password reset; sessions revoked');
});

test('delete requires confirmation, blocks duplicate requests and refreshes users and audit', async () => {
  const h = usersHarness();
  const button = {dataset:{action:'delete-user',id:'2'}, disabled:false};
  h.context.button = button;
  h.context.confirmed = false;
  await h.run('dispatchAction(button)');
  assert.equal(h.context.calls.length, 0);
  h.context.confirmed = true;
  let resolve;
  h.context.pending = new Promise(done => { resolve = done; });
  h.run('fetchJson=async(url,options={})=>{calls.push({url,...options});if(options.method==="DELETE")return pending;return url===API.users?{users:fixtureUsers}:{events:[]};}');
  const request = h.run('dispatchAction(button)');
  await h.run('dispatchAction(button)');
  assert.equal(button.disabled, true);
  assert.equal(h.context.calls.length, 1);
  assert.equal(h.context.calls[0].url, '/api/users/2');
  assert.equal(h.context.calls[0].method, 'DELETE');
  resolve({message:'User deleted'});
  await request;
  assert.equal(button.disabled, false);
  assert.ok(h.context.calls.some(c => c.url === '/api/users'));
  assert.ok(h.context.calls.some(c => c.url === '/api/users/audit'));
  assert.equal(h.node('user-message').messageType, 'success');
});

test('failed deletion keeps user and displays backend error, wrong role cannot dispatch mutations', async () => {
  const h = usersHarness();
  h.context.button = {dataset:{action:'delete-user',id:'2'}, disabled:false};
  h.run('fetchJson=async()=>{throw new Error("Cannot delete the last active Super User")}');
  await h.run('dispatchAction(button)');
  assert.equal(h.run('state.users.has("2")'), true);
  assert.ok(h.node('user-message').textContent.includes('last active Super User'));
  assert.equal(h.context.button.disabled, false);
  h.run('state.user.role="viewer";fetchJson=()=>{throw new Error("must not be called")}');
  await h.run('dispatchAction(button)');
  h.run('openPasswordReset("2",button)');
  assert.notEqual(h.node('reset-password-dialog').open, true);
});

test('reset dialog rejects invalid passwords, clears secrets on cancel and restores focus', async () => {
  const h = usersHarness();
  let focused = 0;
  h.context.trigger = {isConnected:true,focus:()=>{focused++;},dataset:{action:'reset-user-password',id:'2'}};
  await h.run('dispatchAction(trigger)');
  assert.equal(h.node('reset-password-dialog').open, true);
  assert.ok(h.node('reset-password-account').textContent.includes('viewer'));
  for (const [password,confirmation] of [['Short7!','Short7!'],['x'.repeat(129),'x'.repeat(129)],['new-password-8!','different-password']]) {
    h.node('reset-password').value = password;
    h.node('confirm-reset-password').value = confirmation;
    await h.run('submitPasswordReset({preventDefault(){}})');
    assert.equal(h.context.calls.length, 0);
    assert.equal(h.node('reset-password-message').messageType, 'error');
  }
  await h.run('dispatchAction({dataset:{action:"close-password-reset"}})');
  assert.equal(h.node('reset-password-dialog').open, false);
  assert.equal(h.node('reset-password').value, '');
  assert.equal(h.node('confirm-reset-password').value, '');
  assert.equal(focused, 1);
});

test('reset sends confirmed password, blocks repeat submission and clears form on success', async () => {
  const h = usersHarness();
  let resolve;
  h.context.pending = new Promise(done => { resolve = done; });
  h.run('openPasswordReset("2",null);fetchJson=async(url,options={})=>{calls.push({url,...options});if(options.method==="POST")return pending;return url===API.users?{users:fixtureUsers}:{events:[]};}');
  h.node('reset-password').value = h.node('confirm-reset-password').value = 'Replacement-password-8!';
  const request = h.run('submitPasswordReset({preventDefault(){}})');
  await h.run('submitPasswordReset({preventDefault(){}})');
  h.run('closePasswordReset()');
  assert.equal(h.node('reset-password-dialog').open, true);
  assert.equal(h.node('save-password-button').disabled, true);
  assert.equal(h.context.calls.length, 1);
  assert.equal(h.context.calls[0].url, '/api/users/2/password');
  assert.deepEqual(JSON.parse(h.context.calls[0].body), {password:'Replacement-password-8!',confirm_password:'Replacement-password-8!'});
  resolve({user:h.context.fixtureUsers[1]});
  await request;
  assert.equal(h.node('reset-password-dialog').open, false);
  assert.equal(h.node('reset-password').value, '');
  assert.equal(h.node('save-password-button').disabled, false);
  assert.ok(h.context.calls.some(c => c.url === '/api/users/audit'));
  assert.equal(h.node('user-message').messageType, 'success');
});

test('reset failure clears both passwords and keeps dialog available for correction', async () => {
  const h = usersHarness();
  h.run('openPasswordReset("2",null);fetchJson=async()=>{throw new Error("Connection failed")}');
  h.node('reset-password').value = h.node('confirm-reset-password').value = 'Replacement-password-8!';
  await h.run('submitPasswordReset({preventDefault(){}})');
  assert.equal(h.node('reset-password-dialog').open, true);
  assert.equal(h.node('reset-password').value, '');
  assert.equal(h.node('confirm-reset-password').value, '');
  assert.equal(h.node('reset-password-message').textContent, 'Connection failed');
  assert.equal(h.node('save-password-button').disabled, false);
  assert.equal(h.node('cancel-password-button').disabled, false);
});

test('resetting own password redirects to Login and clears browser identity', async () => {
  const h = usersHarness();
  h.run('openPasswordReset("1",null)');
  h.node('reset-password').value = h.node('confirm-reset-password').value = 'Replacement-password-8!';
  assert.ok(h.node('reset-password-account').textContent.includes('log in again'));
  await h.run('submitPasswordReset({preventDefault(){}})');
  assert.equal(h.context.redirect, '/dashboard/login.html');
  assert.equal(h.run('state.user'), null);
  assert.equal(h.run('state.csrf'), null);
  assert.equal(h.node('reset-password').value, '');
});


test('repository controls respect global Role without exposing member lists to Viewer',()=>{
  const h=harness();
  assert.ok(h.run('repositoryAccessActions({id:1,name:"repo"})').includes('Leave repository'));
  assert.ok(!h.run('repositoryAccessActions({id:1})').includes('>Members<'));
  h.run('state.user.role="operator"');
  assert.ok(h.run('repositoryAccessActions({id:1})').includes('>Members<'));
  h.run('state.user.role="superuser"');
  assert.ok(!h.run('repositoryAccessActions({id:1})').includes('Leave repository'));
});

test('Audit describes policy and repository membership separately from account changes',()=>{
  const h=harness('','users');
  assert.equal(h.run('auditChanges({action:"repository.member_left",before:{repository_id:3}})'),'Member left: Repository #3');
  const text=h.run('auditChanges({action:"policy.updated",before:{minimum_score:60},after:{minimum_score:80,version:"v2"}})');
  assert.ok(text.includes('60 -> 80') && text.includes('v2'));
});

test('Policy publication states distinguish local save, pending merge, publication and observed Runner version',()=>{
  const h=harness('','policy');
  assert.ok(h.run('policyActivationText({central_file_minimum:60,settings:{}})').includes('Not published'));
  for(const [activation,text] of Object.entries({awaiting_merge:'unchanged until',published_awaiting_report:'awaiting an imported',observed_in_report:'observed in an imported',publish_failed:'Publication failed'})) {
    h.context.activation=activation;
    assert.ok(h.run('policyActivationText({settings:{activation}})').includes(text));
  }
  h.run('state.user.role="viewer"');
  assert.ok(!h.run('policyPublicationControls({updated_at:"now"})').includes('publish-policy-button'));
  h.run('state.user.role="superuser"');
  assert.ok(h.run('policyPublicationControls({updated_at:"now"})').includes('publish-policy-button'));
  const html=h.run('policyPublicationControls({publication:{pr_url:"javascript:alert(1)",error:"<img onerror=bad>"}})');
  assert.ok(!html.includes('href="javascript:'));
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
});

test('Publish uses the saved version, confirms GitHub writes, prevents duplicates and remains admin-only',async()=>{
  const h=harness('','policy');
  h.context.calls=[];let resolve;
  h.context.pending=new Promise(done=>{resolve=done;});
  let confirmed=false;let prompt='';
  h.context.window.confirm=text=>{prompt=text;return confirmed;};
  h.run('state.user.role="superuser";policyVersion="saved-version";policySavedMinimum=90;fetchJson=async(url,options)=>{calls.push({url,...options});return pending;};loadPolicy=async()=>{};setMessage=(id,text)=>{el(id).textContent=text;};');
  await h.run('publishPolicy()');
  assert.equal(h.context.calls.length,0);
  assert.ok(prompt.includes('90/100') && prompt.includes('pull request'));
  confirmed=true;
  const first=h.run('publishPolicy()');
  await h.run('publishPolicy()');
  assert.equal(h.context.calls.length,1);
  assert.equal(h.context.calls[0].url,'/api/policy/publish');
  assert.deepEqual(JSON.parse(h.context.calls[0].body),{version:'saved-version'});
  resolve({});await first;
  h.run('state.user.role="operator"');
  await h.run('publishPolicy(true)');
  assert.equal(h.context.calls.length,1);
});

test('Findings paginate and combine file and severity filters without changing the gate',()=>{
  const h=harness('?scan=2','scan-detail');
  h.run('state.selectedDetail={scan:{id:2,status:"BLOCK"},findings:Array.from({length:45},(_,i)=>({severity:i<40?"HIGH":"LOW",scanner:"Bandit",file:"src/app.py",line:i+1}))};state.detailPage=2;renderDetailFindings()');
  assert.equal((h.node('detail-findings-list').innerHTML.match(/data-finding-key=/g)||[]).length,20);
  assert.ok(h.node('detail-findings-list').innerHTML.includes('Page 2 of 3'));
  h.run('state.detailFilters.severity="LOW";state.detailFilters.file="APP.PY";state.detailPage=1;renderDetailFindings()');
  assert.equal(h.node('detail-visible-count').textContent,'5 of 45 findings');
  h.run('state.detailFilters.file="not-present";renderDetailFindings()');
  assert.ok(h.node('detail-findings-list').innerHTML.includes('No matching findings'));
  assert.equal(h.run('state.selectedDetail.scan.status'),'BLOCK');
});

test('revoked access clears an already-open detail on its next refresh',async()=>{
  const h=harness('?scan=2','scan-detail');
  h.run('fetchJson=async url=>url.endsWith("/findings")?{findings:[]}:{scan:state.scans.get("2")}');
  await h.run('loadScanDetail()');
  assert.ok(h.node('history-detail').innerHTML.includes('test'));
  h.run('fetchJson=async()=>{throw new ApiError("Resource not found",404)}');
  await h.run('loadScanDetail({background:true})');
  assert.equal(h.run('state.selectedDetail'),null);
  assert.equal(h.node('history-scope').innerHTML,'');
  assert.ok(!h.node('history-detail').innerHTML.includes('Security gate blocked'));
});

test('completed Run link requests findings from its resolved scan without changing attempts',async()=>{
  const h=harness('?scan=run-1-10-1','scan-detail');h.context.calls=[];
  h.run('fetchJson=async url=>{calls.push(url);return url.endsWith("/findings")?{findings:[]}:{scan:{id:25,repository_id:1,status:"BLOCK",github:{run_id:10,run_attempt:1,branch:"main"}}}}');
  await h.run('loadScanDetail()');
  assert.equal(h.context.calls[0],'/api/scans/run-1-10-1');
  assert.equal(h.context.calls[1],'/api/scans/25/findings');
  assert.equal(h.run('state.selectedDetail.scan.github.run_id'),10);
});

test('Leave requires confirmation, prevents duplicate requests and clears repository caches',async()=>{
  const h=harness('','dashboard');
  h.context.button={disabled:false,dataset:{name:'repo'}};
  h.context.window.confirm=()=>false;
  h.run('globalThis.calls=[];fetchJson=async(...args)=>{calls.push(args)}');
  await h.run('leaveRepository("1",button)');assert.equal(h.run('calls.length'),0);
  h.context.window.confirm=()=>true;
  h.run('fetchJson=(...args)=>new Promise(resolve=>{calls.push(args);globalThis.finish=resolve});loadDashboard=async()=>{};state.monitoringRepositories.set("1",{});state.selectedDetail={scan:{id:1}}');
  const first=h.run('leaveRepository("1",button)');
  await h.run('leaveRepository("1",button)');assert.equal(h.run('calls.length'),1);
  h.run('finish({})');await first;
  assert.equal(h.run('state.selectedDetail'),null);
  assert.equal(h.run('state.monitoringRepositories.size'),0);
  assert.equal(h.context.button.disabled,false);
});
