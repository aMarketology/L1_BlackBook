// ============================================================================
// BLACKBOOK L1 — WEB WALLET  (served at /wallet)
// ============================================================================
//
// A production-quality single-page web wallet that ships with every
// BlackBook L1 node. Connects directly to the node's JSON-RPC on port 8899.
//
// Features:
//   - View all accounts and balances (live refresh)
//   - Send BB between addresses
//   - Transaction history per address
//   - Network stats (slot, epoch, block height)
//   - Responsive design, dark theme, BlackBook branding
//
// The wallet UI is embedded as a Rust string constant and served as HTML
// by the axum handler — zero external dependencies, no build step.

use axum::response::Html;

/// Handler: GET /wallet
pub async fn wallet_page_handler() -> Html<&'static str> {
    Html(WALLET_HTML)
}

const WALLET_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>BlackBook Wallet</title>
<style>
/* ── Reset & Base ──────────────────────────────────────────── */
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0a0f;--bg2:#12121a;--bg3:#1a1a28;--bg4:#222236;
  --fg:#e8e8f0;--fg2:#a0a0b8;--fg3:#6a6a80;
  --accent:#6c5ce7;--accent2:#a29bfe;--accent3:#4834d4;
  --green:#00b894;--red:#ff6b6b;--gold:#fdcb6e;
  --border:#2a2a3e;--radius:12px;--radius-sm:8px;
  --shadow:0 4px 24px rgba(0,0,0,0.4);
  --font:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}
html{font-size:15px}
body{font-family:var(--font);background:var(--bg);color:var(--fg);min-height:100vh;overflow-x:hidden}
a{color:var(--accent2);text-decoration:none}
a:hover{text-decoration:underline}
button{cursor:pointer;font-family:inherit}
input,select{font-family:inherit}

/* ── Layout ────────────────────────────────────────────────── */
.app{max-width:1100px;margin:0 auto;padding:20px}
header{display:flex;align-items:center;justify-content:space-between;padding:16px 0 24px;border-bottom:1px solid var(--border);margin-bottom:24px}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{width:40px;height:40px;background:var(--accent);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px;color:#fff}
.logo h1{font-size:1.5rem;font-weight:700;letter-spacing:-0.5px}
.logo h1 span{color:var(--accent2)}
.net-badge{background:var(--bg3);border:1px solid var(--border);border-radius:20px;padding:6px 14px;font-size:0.75rem;color:var(--green);display:flex;align-items:center;gap:6px}
.net-badge .dot{width:8px;height:8px;background:var(--green);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}

/* ── Stats Bar ─────────────────────────────────────────────── */
.stats-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px 16px}
.stat-card .label{font-size:0.7rem;color:var(--fg3);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.stat-card .value{font-size:1.2rem;font-weight:700;font-variant-numeric:tabular-nums}

/* ── Panels ────────────────────────────────────────────────── */
.panels{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:760px){.panels{grid-template-columns:1fr}}
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}
.panel h2{font-size:1rem;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.panel h2 .icon{font-size:1.2rem}
.panel.full{grid-column:1/-1}

/* ── Account Cards ─────────────────────────────────────────── */
.accounts{display:flex;flex-direction:column;gap:10px}
.account{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px 16px;cursor:pointer;transition:all 0.15s}
.account:hover{border-color:var(--accent);transform:translateY(-1px)}
.account.active{border-color:var(--accent);background:rgba(108,92,231,0.08)}
.account .name{font-weight:600;font-size:0.95rem;margin-bottom:2px}
.account .addr{font-size:0.7rem;color:var(--fg3);font-family:'JetBrains Mono',monospace;word-break:break-all}
.account .bal{font-size:1.1rem;font-weight:700;color:var(--accent2);margin-top:6px}
.account .bal-usd{font-size:0.75rem;color:var(--fg3)}

/* ── Send Form ─────────────────────────────────────────────── */
.send-form{display:flex;flex-direction:column;gap:12px}
.form-group{display:flex;flex-direction:column;gap:4px}
.form-group label{font-size:0.75rem;color:var(--fg2);text-transform:uppercase;letter-spacing:0.5px}
.form-group input,.form-group select{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 14px;color:var(--fg);font-size:0.9rem;outline:none;transition:border 0.15s}
.form-group input:focus,.form-group select:focus{border-color:var(--accent)}
.form-group input::placeholder{color:var(--fg3)}
.btn{padding:12px 24px;border-radius:var(--radius-sm);border:none;font-weight:600;font-size:0.9rem;transition:all 0.15s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent3);transform:translateY(-1px)}
.btn-primary:disabled{opacity:0.5;cursor:not-allowed;transform:none}
.btn-sm{padding:8px 16px;font-size:0.8rem}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--fg2)}
.btn-outline:hover{border-color:var(--accent);color:var(--accent2)}

/* ── Toast ─────────────────────────────────────────────────── */
.toast{position:fixed;top:20px;right:20px;padding:14px 20px;border-radius:var(--radius-sm);font-size:0.85rem;font-weight:500;z-index:100;transition:all 0.3s;opacity:0;transform:translateY(-10px);pointer-events:none}
.toast.show{opacity:1;transform:translateY(0);pointer-events:auto}
.toast.success{background:var(--green);color:#000}
.toast.error{background:var(--red);color:#fff}
.toast.info{background:var(--accent);color:#fff}

/* ── Transaction History ───────────────────────────────────── */
.tx-list{display:flex;flex-direction:column;gap:8px;max-height:400px;overflow-y:auto}
.tx-list::-webkit-scrollbar{width:4px}
.tx-list::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.tx-item{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;font-size:0.82rem}
.tx-item .tx-sig{font-family:'JetBrains Mono',monospace;color:var(--accent2);font-size:0.7rem;word-break:break-all}
.tx-item .tx-meta{display:flex;justify-content:space-between;margin-top:6px;color:var(--fg3);font-size:0.72rem}
.tx-item .tx-status{color:var(--green);font-weight:600}
.tx-item .tx-status.failed{color:var(--red)}

/* ── Explorer ──────────────────────────────────────────────── */
.search-bar{display:flex;gap:8px;margin-bottom:16px}
.search-bar input{flex:1}
.lookup-result{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:16px;font-size:0.85rem;word-break:break-all}
.lookup-result pre{white-space:pre-wrap;font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:var(--fg2);margin-top:8px;max-height:300px;overflow-y:auto}

/* ── Empty / Loading ───────────────────────────────────────── */
.empty{color:var(--fg3);text-align:center;padding:30px;font-size:0.85rem}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--accent2);border-radius:50%;animation:spin 0.6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── Footer ────────────────────────────────────────────────── */
footer{text-align:center;padding:32px 0 16px;color:var(--fg3);font-size:0.72rem;border-top:1px solid var(--border);margin-top:32px}
</style>
</head>
<body>
<div class="app">
  <!-- Header -->
  <header>
    <div class="logo">
      <div class="logo-icon">BB</div>
      <h1>Black<span>Book</span> Wallet</h1>
    </div>
    <div class="net-badge">
      <span class="dot"></span>
      <span id="netStatus">Connecting…</span>
    </div>
  </header>

  <!-- Stats Bar -->
  <div class="stats-bar">
    <div class="stat-card"><div class="label">Slot</div><div class="value" id="statSlot">—</div></div>
    <div class="stat-card"><div class="label">Epoch</div><div class="value" id="statEpoch">—</div></div>
    <div class="stat-card"><div class="label">Block Height</div><div class="value" id="statBlockHeight">—</div></div>
    <div class="stat-card"><div class="label">Node Version</div><div class="value" id="statVersion">—</div></div>
    <div class="stat-card"><div class="label">Total Supply</div><div class="value" id="statSupply">—</div></div>
  </div>

  <!-- Main Panels -->
  <div class="panels">
    <!-- Left: Accounts -->
    <div class="panel">
      <h2><span class="icon">👛</span> Accounts</h2>
      <div class="accounts" id="accountList">
        <div class="empty"><span class="spinner"></span> Loading accounts…</div>
      </div>
      <div style="margin-top:14px">
        <div class="form-group">
          <label>Lookup any address</label>
          <div class="search-bar">
            <input type="text" id="lookupAddr" placeholder="Paste a BlackBook address…"/>
            <button class="btn btn-sm btn-outline" onclick="lookupAddress()">Lookup</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Right: Send BB -->
    <div class="panel">
      <h2><span class="icon">📤</span> Send BB</h2>
      <div class="send-form">
        <div class="form-group">
          <label>From</label>
          <select id="sendFrom"></select>
        </div>
        <div class="form-group">
          <label>To Address</label>
          <input type="text" id="sendTo" placeholder="Recipient BlackBook address"/>
        </div>
        <div class="form-group">
          <label>Amount (BB)</label>
          <input type="number" id="sendAmount" placeholder="0.00" min="0" step="0.000000001"/>
        </div>
        <button class="btn btn-primary" id="sendBtn" onclick="sendBB()">Send BB</button>
      </div>

      <div style="margin-top:24px">
        <h2><span class="icon">📜</span> Recent Transactions</h2>
        <div class="tx-list" id="txList">
          <div class="empty">Select an account to view transactions</div>
        </div>
      </div>
    </div>

    <!-- Full-width: Account Detail / Explorer -->
    <div class="panel full" id="detailPanel" style="display:none">
      <h2><span class="icon">🔍</span> Account Detail</h2>
      <div class="lookup-result" id="detailContent"></div>
    </div>
  </div>

  <footer>
    BlackBook L1 — Digital Central Bank &nbsp;|&nbsp; Node RPC: <span id="rpcUrl"></span> &nbsp;|&nbsp; Genesis: <span id="genesisHash">—</span>
  </footer>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
// ── Configuration ───────────────────────────────────────────
const RPC = window.location.protocol + '//' + window.location.hostname + ':8899';
const LAMPORTS_PER_BB = 1_000_000_000;

// Known network accounts (loaded on start + any user adds)
const KNOWN_ACCOUNTS = [
  { name: 'Max',    address: '4PtfY2ySdcGpshvfqfnaNyAVBFKtpLbZ4HTBHZBT2oby', role: 'admin' },
  { name: 'Alice',  address: 'HVbEJfko9NzqrnKzmbsJBU3rLSHehNZVEFXqiPkDCUSc', role: 'user' },
  { name: 'Bob',    address: '6fsVDKyh5UXkMVE8bBrVTiqHWAqXUeseUXFTJh2UUnn2', role: 'user' },
  { name: 'Apollo', address: '5Pk2JZ5ZfkeUdjVFzT2iY3GtcQ28Lx4cxpr7yPteTqmd', role: 'user' },
  { name: 'Dealer', address: 'DcdsDp8fQVPthhPx6wRWQaErHfDw6sKEsijs49zuCYZo', role: 'dealer' },
];

let selectedAccount = null;
let accounts = [...KNOWN_ACCOUNTS];
let balances = {};

// ── RPC Helper ──────────────────────────────────────────────
let rpcId = 1;
async function rpc(method, params = []) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: rpcId++, method, params })
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message);
  return json.result;
}

async function rpcBatch(calls) {
  const batch = calls.map((c, i) => ({
    jsonrpc: '2.0', id: i + 1, method: c.method, params: c.params || []
  }));
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(batch)
  });
  return await res.json();
}

// ── Formatting ──────────────────────────────────────────────
function formatBB(lamports) {
  const bb = lamports / LAMPORTS_PER_BB;
  return bb.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 4 });
}

function shortAddr(addr) {
  return addr.slice(0, 6) + '…' + addr.slice(-4);
}

function timeAgo(ts) {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

// ── Toast ───────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show ' + type;
  setTimeout(() => el.className = 'toast', 3500);
}

// ── Network Stats ───────────────────────────────────────────
async function refreshStats() {
  try {
    const [epochInfo, version, genesis] = await Promise.all([
      rpc('getEpochInfo'),
      rpc('getVersion'),
      rpc('getGenesisHash')
    ]);

    document.getElementById('statSlot').textContent = epochInfo.absoluteSlot.toLocaleString();
    document.getElementById('statEpoch').textContent = epochInfo.epoch;
    document.getElementById('statBlockHeight').textContent = epochInfo.blockHeight.toLocaleString();
    document.getElementById('statVersion').textContent = version['solana-core'];
    document.getElementById('genesisHash').textContent = genesis.slice(0, 12) + '…';
    document.getElementById('netStatus').textContent = 'BlackBook L1 — Slot ' + epochInfo.absoluteSlot.toLocaleString();

    // Supply
    try {
      const supply = await rpc('getSupply');
      document.getElementById('statSupply').textContent = formatBB(supply.value.total) + ' BB';
    } catch(e) {
      document.getElementById('statSupply').textContent = '–';
    }
  } catch (e) {
    document.getElementById('netStatus').textContent = 'Disconnected ✕';
    console.error('Stats error:', e);
  }
}

// ── Account Balances ────────────────────────────────────────
async function refreshBalances() {
  const calls = accounts.map(a => ({ method: 'getBalance', params: [a.address] }));
  try {
    const results = await rpcBatch(calls);
    results.sort((a, b) => a.id - b.id);
    results.forEach((r, i) => {
      if (r.result) balances[accounts[i].address] = r.result.value;
    });
    renderAccounts();
  } catch (e) {
    console.error('Balance error:', e);
  }
}

function renderAccounts() {
  const list = document.getElementById('accountList');
  const select = document.getElementById('sendFrom');
  
  list.innerHTML = accounts.map((a, i) => {
    const lam = balances[a.address] || 0;
    const isActive = selectedAccount === a.address;
    const roleBadge = a.role === 'admin' ? ' 🔑' : a.role === 'dealer' ? ' 🏦' : '';
    return `<div class="account ${isActive ? 'active' : ''}" onclick="selectAccount('${a.address}')">
      <div class="name">${a.name}${roleBadge}</div>
      <div class="addr">${a.address}</div>
      <div class="bal">${formatBB(lam)} BB</div>
    </div>`;
  }).join('');

  select.innerHTML = accounts.map(a => {
    const lam = balances[a.address] || 0;
    return `<option value="${a.address}">${a.name} (${formatBB(lam)} BB)</option>`;
  }).join('');
}

// ── Select Account ──────────────────────────────────────────
async function selectAccount(addr) {
  selectedAccount = addr;
  renderAccounts();
  await refreshTransactions(addr);
  await showAccountDetail(addr);
}

// ── Transaction History ─────────────────────────────────────
async function refreshTransactions(addr) {
  const txList = document.getElementById('txList');
  txList.innerHTML = '<div class="empty"><span class="spinner"></span> Loading…</div>';
  
  try {
    const sigs = await rpc('getSignaturesForAddress', [addr, { limit: 20 }]);
    if (!sigs || sigs.length === 0) {
      txList.innerHTML = '<div class="empty">No transactions yet</div>';
      return;
    }

    txList.innerHTML = sigs.map(s => {
      const ok = !s.err;
      return `<div class="tx-item">
        <div class="tx-sig">${s.signature}</div>
        <div class="tx-meta">
          <span>Slot ${s.slot}</span>
          <span>${s.blockTime ? timeAgo(s.blockTime) : '—'}</span>
          <span class="tx-status ${ok ? '' : 'failed'}">${ok ? '✓ Confirmed' : '✕ Failed'}</span>
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    txList.innerHTML = '<div class="empty">Error loading transactions</div>';
    console.error('TX error:', e);
  }
}

// ── Account Detail ──────────────────────────────────────────
async function showAccountDetail(addr) {
  const panel = document.getElementById('detailPanel');
  const content = document.getElementById('detailContent');
  panel.style.display = 'block';

  try {
    const info = await rpc('getAccountInfo', [addr, { encoding: 'base64' }]);
    const acct = info.value;
    if (!acct) {
      content.innerHTML = `<strong>${addr}</strong><br><br>Account not found on chain.`;
      return;
    }
    const name = accounts.find(a => a.address === addr)?.name || 'Unknown';
    content.innerHTML = `
      <strong>${name}</strong> — <span style="color:var(--fg3)">${addr}</span><br><br>
      <strong>Balance:</strong> ${formatBB(acct.lamports)} BB (${acct.lamports.toLocaleString()} lamports)<br>
      <strong>Owner:</strong> ${acct.owner}<br>
      <strong>Executable:</strong> ${acct.executable}<br>
      <strong>Rent Epoch:</strong> ${acct.rentEpoch === 18446744073709551615 ? 'Exempt' : acct.rentEpoch}<br>
      <strong>Data Size:</strong> ${acct.space} bytes
    `;
  } catch (e) {
    content.innerHTML = `Error fetching account: ${e.message}`;
  }
}

// ── Send BB ─────────────────────────────────────────────────
async function sendBB() {
  const from = document.getElementById('sendFrom').value;
  const to = document.getElementById('sendTo').value.trim();
  const amountBB = parseFloat(document.getElementById('sendAmount').value);
  const btn = document.getElementById('sendBtn');

  if (!to) return toast('Enter a recipient address', 'error');
  if (!amountBB || amountBB <= 0) return toast('Enter a valid amount', 'error');

  const lamports = Math.floor(amountBB * LAMPORTS_PER_BB);
  const fromName = accounts.find(a => a.address === from)?.name || shortAddr(from);
  const toName = accounts.find(a => a.address === to)?.name || shortAddr(to);

  btn.disabled = true;
  btn.textContent = 'Sending…';

  try {
    // Use the HTTP API transfer endpoint
    const API = window.location.protocol + '//' + window.location.hostname + ':' + window.location.port;
    const res = await fetch(API + '/transfer/simple', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to, amount: lamports })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Transfer failed');

    toast(`Sent ${amountBB} BB from ${fromName} to ${toName}`, 'success');
    document.getElementById('sendAmount').value = '';
    document.getElementById('sendTo').value = '';

    // Refresh balances & tx history
    setTimeout(async () => {
      await refreshBalances();
      if (selectedAccount) await refreshTransactions(selectedAccount);
    }, 500);
  } catch (e) {
    toast('Transfer failed: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send BB';
  }
}

// ── Lookup Arbitrary Address ────────────────────────────────
async function lookupAddress() {
  const addr = document.getElementById('lookupAddr').value.trim();
  if (!addr) return;
  
  // Add to accounts list if not already there
  if (!accounts.find(a => a.address === addr)) {
    accounts.push({ name: shortAddr(addr), address: addr, role: 'unknown' });
  }
  
  await refreshBalances();
  await selectAccount(addr);
  document.getElementById('lookupAddr').value = '';
}

// ── Init ────────────────────────────────────────────────────
document.getElementById('rpcUrl').textContent = RPC;

async function init() {
  await refreshStats();
  await refreshBalances();
  if (accounts.length > 0) selectAccount(accounts[0].address);

  // Auto-refresh every 5 seconds
  setInterval(refreshStats, 5000);
  setInterval(refreshBalances, 8000);
}

init().catch(e => {
  document.getElementById('netStatus').textContent = 'Failed to connect';
  console.error('Init error:', e);
});
</script>
</body>
</html>
"##;
