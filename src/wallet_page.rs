// ============================================================================
// BLACKBOOK L1 — WEB WALLET  (served at /wallet)
// ============================================================================
//
// A production-quality single-page web wallet that ships with every
// BlackBook L1 node. Connects directly to the node's JSON-RPC on port 8899.
//
// Features:
//   - Create wallet with BIP-39 mnemonic + Shamir 2/3 SSS
//   - Collect private key, mnemonic, and 3 shard pairs
//   - Test 2/3 SSS reconstruction to verify wallet access
//   - View all accounts and balances (live refresh)
//   - Send BB between addresses with SSS-signed transactions
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
  --green:#00b894;--red:#ff6b6b;--gold:#fdcb6e;--orange:#e17055;
  --border:#2a2a3e;--radius:12px;--radius-sm:8px;
  --shadow:0 4px 24px rgba(0,0,0,0.4);
  --font:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --mono:'JetBrains Mono','Fira Code',monospace;
}
html{font-size:15px}
body{font-family:var(--font);background:var(--bg);color:var(--fg);min-height:100vh;overflow-x:hidden}
a{color:var(--accent2);text-decoration:none}
a:hover{text-decoration:underline}
button{cursor:pointer;font-family:inherit}
input,select,textarea{font-family:inherit}

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

/* ── Tabs ──────────────────────────────────────────────────── */
.tabs{display:flex;gap:4px;margin-bottom:24px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:4px}
.tab{padding:10px 20px;border-radius:var(--radius-sm);font-size:0.85rem;font-weight:600;color:var(--fg3);border:none;background:transparent;transition:all 0.15s}
.tab:hover{color:var(--fg2);background:var(--bg3)}
.tab.active{background:var(--accent);color:#fff}

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

/* ── Tab Content ───────────────────────────────────────────── */
.tab-content{display:none}
.tab-content.active{display:block}

/* ── Create Wallet ─────────────────────────────────────────── */
.create-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:600px;margin:0 auto}
.create-card h2{font-size:1.3rem;margin-bottom:8px;text-align:center}
.create-card .subtitle{color:var(--fg3);font-size:0.85rem;text-align:center;margin-bottom:24px}
.step-indicator{display:flex;justify-content:center;gap:8px;margin-bottom:24px}
.step-dot{width:10px;height:10px;border-radius:50%;background:var(--bg4);border:2px solid var(--border);transition:all 0.3s}
.step-dot.active{background:var(--accent);border-color:var(--accent)}
.step-dot.done{background:var(--green);border-color:var(--green)}

/* ── Secret Display ────────────────────────────────────────── */
.secret-box{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:16px;margin-bottom:16px;position:relative}
.secret-box .secret-label{font-size:0.7rem;color:var(--fg3);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.secret-box .secret-value{font-family:var(--mono);font-size:0.78rem;color:var(--accent2);word-break:break-all;line-height:1.5;user-select:all;filter:blur(6px);transition:filter 0.2s}
.secret-box .secret-value.revealed{filter:none}
.secret-box .reveal-btn{position:absolute;top:12px;right:12px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:0.7rem;color:var(--fg2)}
.secret-box .reveal-btn:hover{border-color:var(--accent);color:var(--accent2)}
.copy-btn{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:6px 12px;font-size:0.75rem;color:var(--fg2);margin-top:8px;display:inline-flex;align-items:center;gap:4px}
.copy-btn:hover{border-color:var(--accent);color:var(--accent2)}

/* ── Shard Cards ───────────────────────────────────────────── */
.shard-grid{display:grid;grid-template-columns:1fr;gap:16px;margin-top:16px}
.shard-card{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:16px;position:relative}
.shard-card.shard-a{border-left:3px solid var(--accent2)}
.shard-card.shard-b{border-left:3px solid var(--gold)}
.shard-card.shard-c{border-left:3px solid var(--green)}
.shard-card .shard-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.shard-card .shard-title{font-weight:700;font-size:0.9rem}
.shard-card .shard-badge{font-size:0.65rem;padding:3px 8px;border-radius:10px;font-weight:600}
.shard-a .shard-badge{background:rgba(162,155,254,0.15);color:var(--accent2)}
.shard-b .shard-badge{background:rgba(253,203,110,0.15);color:var(--gold)}
.shard-c .shard-badge{background:rgba(0,184,148,0.15);color:var(--green)}
.shard-card .shard-desc{font-size:0.78rem;color:var(--fg3);margin-bottom:8px}
.shard-card .shard-data{font-family:var(--mono);font-size:0.72rem;color:var(--fg2);word-break:break-all;background:var(--bg);padding:10px;border-radius:6px;max-height:80px;overflow-y:auto;filter:blur(5px);transition:filter 0.2s}
.shard-card .shard-data.revealed{filter:none}

/* ── Warning Box ───────────────────────────────────────────── */
.warning-box{background:rgba(225,112,85,0.08);border:1px solid var(--orange);border-radius:var(--radius-sm);padding:14px 16px;margin:16px 0;display:flex;gap:10px;align-items:flex-start}
.warning-box .warn-icon{font-size:1.2rem;flex-shrink:0}
.warning-box .warn-text{font-size:0.8rem;color:var(--orange);line-height:1.5}
.success-box{background:rgba(0,184,148,0.08);border:1px solid var(--green);border-radius:var(--radius-sm);padding:14px 16px;margin:16px 0;display:flex;gap:10px;align-items:flex-start}
.success-box .icon{font-size:1.2rem;flex-shrink:0}
.success-box .text{font-size:0.8rem;color:var(--green);line-height:1.5}

/* ── SSS Test Panel ────────────────────────────────────────── */
.sss-test{max-width:700px;margin:0 auto}
.sss-test .combo-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin:16px 0}
.combo-card{background:var(--bg3);border:2px solid var(--border);border-radius:var(--radius-sm);padding:16px;text-align:center;cursor:pointer;transition:all 0.2s}
.combo-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.combo-card.selected{border-color:var(--green);background:rgba(0,184,148,0.06)}
.combo-card .combo-label{font-weight:700;font-size:0.9rem;margin-bottom:4px}
.combo-card .combo-desc{font-size:0.72rem;color:var(--fg3)}
.sss-result{margin-top:16px;padding:20px;border-radius:var(--radius-sm);text-align:center}
.sss-result.pass{background:rgba(0,184,148,0.08);border:1px solid var(--green)}
.sss-result.fail{background:rgba(255,107,107,0.08);border:1px solid var(--red)}
.sss-result .result-icon{font-size:2.5rem;margin-bottom:8px}
.sss-result .result-title{font-weight:700;font-size:1rem;margin-bottom:4px}
.sss-result .result-detail{font-size:0.8rem;color:var(--fg3);font-family:var(--mono)}

/* ── Account Cards ─────────────────────────────────────────── */
.accounts{display:flex;flex-direction:column;gap:10px}
.account{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px 16px;cursor:pointer;transition:all 0.15s}
.account:hover{border-color:var(--accent);transform:translateY(-1px)}
.account.active{border-color:var(--accent);background:rgba(108,92,231,0.08)}
.account .name{font-weight:600;font-size:0.95rem;margin-bottom:2px}
.account .addr{font-size:0.7rem;color:var(--fg3);font-family:var(--mono);word-break:break-all}
.account .bal{font-size:1.1rem;font-weight:700;color:var(--accent2);margin-top:6px}

/* ── Send Form ─────────────────────────────────────────────── */
.send-form{display:flex;flex-direction:column;gap:12px}
.form-group{display:flex;flex-direction:column;gap:4px}
.form-group label{font-size:0.75rem;color:var(--fg2);text-transform:uppercase;letter-spacing:0.5px}
.form-group input,.form-group select,.form-group textarea{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 14px;color:var(--fg);font-size:0.9rem;outline:none;transition:border 0.15s}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{border-color:var(--accent)}
.form-group input::placeholder,.form-group textarea::placeholder{color:var(--fg3)}
.btn{padding:12px 24px;border-radius:var(--radius-sm);border:none;font-weight:600;font-size:0.9rem;transition:all 0.15s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent3);transform:translateY(-1px)}
.btn-primary:disabled{opacity:0.5;cursor:not-allowed;transform:none}
.btn-sm{padding:8px 16px;font-size:0.8rem}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--fg2)}
.btn-outline:hover{border-color:var(--accent);color:var(--accent2)}
.btn-success{background:var(--green);color:#000}
.btn-success:hover{background:#00a383;transform:translateY(-1px)}
.btn-gold{background:var(--gold);color:#000}
.btn-gold:hover{background:#f0bd5e;transform:translateY(-1px)}
.btn-danger{background:var(--red);color:#fff}
.btn-danger:hover{background:#e55555;transform:translateY(-1px)}

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
.tx-item .tx-sig{font-family:var(--mono);color:var(--accent2);font-size:0.7rem;word-break:break-all}
.tx-item .tx-meta{display:flex;justify-content:space-between;margin-top:6px;color:var(--fg3);font-size:0.72rem}
.tx-item .tx-status{color:var(--green);font-weight:600}
.tx-item .tx-status.failed{color:var(--red)}

/* ── Explorer ──────────────────────────────────────────────── */
.search-bar{display:flex;gap:8px;margin-bottom:16px}
.search-bar input{flex:1}
.lookup-result{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:16px;font-size:0.85rem;word-break:break-all}

/* ── Checklist ─────────────────────────────────────────────── */
.checklist{list-style:none;padding:0}
.checklist li{padding:8px 0;border-bottom:1px solid var(--border);font-size:0.85rem;display:flex;align-items:center;gap:8px}
.checklist li:last-child{border:none}
.check-icon{font-size:1rem}

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

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" onclick="switchTab('create')">Create Wallet</button>
    <button class="tab" onclick="switchTab('dashboard')">Dashboard</button>
    <button class="tab" onclick="switchTab('sss-test')">SSS Recovery Test</button>
    <button class="tab" onclick="switchTab('send')">Send BB</button>
  </div>

  <!-- Stats Bar (always visible) -->
  <div class="stats-bar">
    <div class="stat-card"><div class="label">Slot</div><div class="value" id="statSlot">—</div></div>
    <div class="stat-card"><div class="label">Epoch</div><div class="value" id="statEpoch">—</div></div>
    <div class="stat-card"><div class="label">Block Height</div><div class="value" id="statBlockHeight">—</div></div>
    <div class="stat-card"><div class="label">Node Version</div><div class="value" id="statVersion">—</div></div>
    <div class="stat-card"><div class="label">Total Supply</div><div class="value" id="statSupply">—</div></div>
  </div>

  <!-- ═══════════════════════════════════════════════════════════ -->
  <!-- TAB 1: CREATE WALLET                                        -->
  <!-- ═══════════════════════════════════════════════════════════ -->
  <div class="tab-content active" id="tab-create">
    <div class="create-card" id="createStep1">
      <h2>Create Your BlackBook Wallet</h2>
      <p class="subtitle">Your keys, your coins. BlackBook uses 2-of-3 Shamir Secret Sharing for maximum security.</p>

      <div class="step-indicator">
        <div class="step-dot active" id="dot1"></div>
        <div class="step-dot" id="dot2"></div>
        <div class="step-dot" id="dot3"></div>
      </div>

      <div class="send-form">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="createUsername" placeholder="Choose a username" autocomplete="off"/>
        </div>
        <div class="form-group">
          <label>Password (encrypts your local shard)</label>
          <input type="password" id="createPassword" placeholder="Strong password — encrypts Share A"/>
        </div>
        <div class="form-group">
          <label>Confirm Password</label>
          <input type="password" id="createPasswordConfirm" placeholder="Confirm password"/>
        </div>
        <button class="btn btn-primary" id="createWalletBtn" onclick="createWallet()" style="width:100%;margin-top:8px">
          Create Wallet
        </button>
      </div>
    </div>

    <!-- Step 2: Show wallet secrets -->
    <div class="create-card" id="createStep2" style="display:none;max-width:800px">
      <h2>Your Wallet Has Been Created</h2>
      <p class="subtitle">Back up everything below. You will NOT see this again.</p>

      <div class="step-indicator">
        <div class="step-dot done" id="dot1b"></div>
        <div class="step-dot active" id="dot2b"></div>
        <div class="step-dot" id="dot3b"></div>
      </div>

      <div class="warning-box">
        <span class="warn-icon">⚠️</span>
        <span class="warn-text">
          <strong>CRITICAL:</strong> Write down your mnemonic and shards NOW.
          If you lose access to 2 of your 3 shards, your funds are permanently lost.
          Never share these with anyone.
        </span>
      </div>

      <!-- Public Address -->
      <div class="secret-box">
        <div class="secret-label">📍 Your Wallet Address (Public — safe to share)</div>
        <div class="secret-value revealed" id="walletAddress" style="font-size:0.9rem;color:var(--green)"></div>
        <button class="copy-btn" onclick="copyText('walletAddress')">📋 Copy Address</button>
      </div>

      <!-- Mnemonic -->
      <div class="secret-box">
        <div class="secret-label">🔑 BIP-39 Recovery Phrase (24 words)</div>
        <button class="reveal-btn" onclick="toggleReveal('mnemonicValue',this)">👁 Reveal</button>
        <div class="secret-value" id="mnemonicValue"></div>
        <button class="copy-btn" onclick="copyText('mnemonicValue')">📋 Copy Mnemonic</button>
      </div>

      <!-- 3 Shard Cards -->
      <h3 style="margin:20px 0 8px;font-size:0.95rem">🔐 Your 3 Shamir Secret Shares (2 of 3 required)</h3>
      <div class="shard-grid">
        <div class="shard-card shard-a">
          <div class="shard-header">
            <span class="shard-title">Share A — User Shard</span>
            <span class="shard-badge">YOUR DEVICE</span>
          </div>
          <div class="shard-desc">Password-encrypted. Stored on your device / browser. You control this shard.</div>
          <div class="shard-data" id="shardAData"></div>
          <div style="display:flex;gap:8px;margin-top:8px">
            <button class="copy-btn" onclick="copyText('shardAData')">📋 Copy</button>
            <button class="copy-btn" onclick="toggleReveal('shardAData',this)">👁 Reveal</button>
          </div>
          <div style="margin-top:6px;font-size:0.7rem;color:var(--fg3)" id="shardAEncrypted"></div>
        </div>

        <div class="shard-card shard-b">
          <div class="shard-header">
            <span class="shard-title">Share B — Server Shard</span>
            <span class="shard-badge">BLACKBOOK NODE</span>
          </div>
          <div class="shard-desc">Encrypted with server master key. Stored on-node in ReDB. Retrieved automatically during transactions.</div>
          <div class="shard-data revealed" id="shardBData" style="color:var(--gold);font-size:0.72rem">Securely stored on-node. Auto-retrieved when you transact.</div>
        </div>

        <div class="shard-card shard-c">
          <div class="shard-header">
            <span class="shard-title">Share C — Recovery Shard</span>
            <span class="shard-badge">COLD STORAGE</span>
          </div>
          <div class="shard-desc">Your offline backup. Write this down on paper or store in a hardware vault. DO NOT store digitally.</div>
          <div class="shard-data" id="shardCData"></div>
          <div style="display:flex;gap:8px;margin-top:8px">
            <button class="copy-btn" onclick="copyText('shardCData')">📋 Copy</button>
            <button class="copy-btn" onclick="toggleReveal('shardCData',this)">👁 Reveal</button>
          </div>
        </div>
      </div>

      <button class="btn btn-success" onclick="proceedToStep3()" style="width:100%;margin-top:20px">
        I've Saved Everything → Continue
      </button>
    </div>

    <!-- Step 3: Confirmation checklist -->
    <div class="create-card" id="createStep3" style="display:none">
      <h2>Wallet Setup Complete</h2>
      <p class="subtitle">Confirm you've backed up your recovery materials.</p>

      <div class="step-indicator">
        <div class="step-dot done"></div>
        <div class="step-dot done"></div>
        <div class="step-dot active"></div>
      </div>

      <div class="success-box">
        <span class="icon">✅</span>
        <span class="text">
          Your BlackBook wallet is live. Your address is on-chain and ready to receive BB tokens.
        </span>
      </div>

      <ul class="checklist" id="confirmChecks">
        <li><span class="check-icon" id="chk1">☐</span> <label><input type="checkbox" onchange="updateChecks()" style="margin-right:6px"/> I've saved my 24-word recovery phrase</label></li>
        <li><span class="check-icon" id="chk2">☐</span> <label><input type="checkbox" onchange="updateChecks()" style="margin-right:6px"/> I've saved Share A (encrypted with my password)</label></li>
        <li><span class="check-icon" id="chk3">☐</span> <label><input type="checkbox" onchange="updateChecks()" style="margin-right:6px"/> I've saved Share C (cold recovery shard)</label></li>
        <li><span class="check-icon" id="chk4">☐</span> <label><input type="checkbox" onchange="updateChecks()" style="margin-right:6px"/> I understand Share B is stored on the BlackBook node</label></li>
        <li><span class="check-icon" id="chk5">☐</span> <label><input type="checkbox" onchange="updateChecks()" style="margin-right:6px"/> I understand I need ANY 2 of 3 shards to access my wallet</label></li>
      </ul>

      <button class="btn btn-primary" id="finishBtn" onclick="finishSetup()" style="width:100%;margin-top:16px" disabled>
        Go to Dashboard
      </button>
    </div>
  </div>

  <!-- ═══════════════════════════════════════════════════════════ -->
  <!-- TAB 2: DASHBOARD                                            -->
  <!-- ═══════════════════════════════════════════════════════════ -->
  <div class="tab-content" id="tab-dashboard">
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

      <!-- Right: Recent TX -->
      <div class="panel">
        <h2><span class="icon">📜</span> Recent Transactions</h2>
        <div class="tx-list" id="txList">
          <div class="empty">Select an account to view transactions</div>
        </div>
      </div>

      <!-- Full-width: Account Detail -->
      <div class="panel full" id="detailPanel" style="display:none">
        <h2><span class="icon">🔍</span> Account Detail</h2>
        <div class="lookup-result" id="detailContent"></div>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════════════════════════ -->
  <!-- TAB 3: SSS RECOVERY TEST                                    -->
  <!-- ═══════════════════════════════════════════════════════════ -->
  <div class="tab-content" id="tab-sss-test">
    <div class="sss-test">
      <div class="panel full">
        <h2><span class="icon">🧪</span> 2/3 Shamir Secret Sharing — Recovery Test</h2>
        <p style="color:var(--fg3);font-size:0.85rem;margin-bottom:16px">
          Prove that ANY 2 of your 3 shards can reconstruct your wallet.
          Select a combination below, paste your shards, and verify.
        </p>

        <div id="sssNoWallet" style="display:none">
          <div class="warning-box">
            <span class="warn-icon">ℹ️</span>
            <span class="warn-text">Create a wallet first to test SSS recovery.</span>
          </div>
        </div>

        <div id="sssTestArea">
          <!-- Combo selector -->
          <p style="font-weight:600;font-size:0.9rem;margin-bottom:8px">Choose shard combination:</p>
          <div class="combo-grid">
            <div class="combo-card selected" id="comboAB" onclick="selectCombo('AB')">
              <div class="combo-label">A + B</div>
              <div class="combo-desc">User + Server</div>
            </div>
            <div class="combo-card" id="comboAC" onclick="selectCombo('AC')">
              <div class="combo-label">A + C</div>
              <div class="combo-desc">User + Cold</div>
            </div>
            <div class="combo-card" id="comboBC" onclick="selectCombo('BC')">
              <div class="combo-label">B + C</div>
              <div class="combo-desc">Server + Cold</div>
            </div>
          </div>

          <!-- Shard input area -->
          <div id="sssInputs">
            <div class="form-group" id="sssWalletGroup">
              <label>Wallet Address (to verify against)</label>
              <input type="text" id="sssWalletId" placeholder="Your wallet address"/>
            </div>

            <div class="form-group" id="shard1Group">
              <label id="shard1Label">Share A (paste encrypted blob)</label>
              <textarea id="sssInput1" rows="3" placeholder="Paste shard data…" style="resize:vertical"></textarea>
            </div>

            <div class="form-group" id="passwordGroup">
              <label>Password (to decrypt Share A)</label>
              <input type="password" id="sssPassword" placeholder="Your wallet password"/>
            </div>

            <div class="form-group" id="shard2Group">
              <label id="shard2Label">Share B (auto-fetched from node)</label>
              <textarea id="sssInput2" rows="3" placeholder="Paste shard data or leave empty to auto-fetch…" style="resize:vertical"></textarea>
            </div>

            <button class="btn btn-gold" onclick="runSSSTest()" id="sssTestBtn" style="width:100%;margin-top:12px">
              🔐 Verify 2/3 SSS Reconstruction
            </button>
          </div>

          <!-- Result -->
          <div id="sssResultBox" style="display:none"></div>
        </div>
      </div>

      <!-- SSS Explainer -->
      <div class="panel full" style="margin-top:20px">
        <h2><span class="icon">📖</span> How 2/3 SSS Works</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-top:12px">
          <div style="text-align:center;padding:16px">
            <div style="font-size:2rem;margin-bottom:8px">🔑</div>
            <div style="font-weight:700;font-size:0.9rem;margin-bottom:4px">Share A — You</div>
            <div style="font-size:0.78rem;color:var(--fg3)">Password-encrypted, stored on your device. You always have this shard.</div>
          </div>
          <div style="text-align:center;padding:16px">
            <div style="font-size:2rem;margin-bottom:8px">☁️</div>
            <div style="font-weight:700;font-size:0.9rem;margin-bottom:4px">Share B — Server</div>
            <div style="font-size:0.78rem;color:var(--fg3)">Server-encrypted, stored in ReDB. Released when you authenticate.</div>
          </div>
          <div style="text-align:center;padding:16px">
            <div style="font-size:2rem;margin-bottom:8px">🏦</div>
            <div style="font-weight:700;font-size:0.9rem;margin-bottom:4px">Share C — Cold</div>
            <div style="font-size:0.78rem;color:var(--fg3)">Your offline backup. Paper, hardware wallet, or vault. Emergency recovery.</div>
          </div>
        </div>
        <div style="text-align:center;margin-top:12px;padding:16px;background:var(--bg3);border-radius:var(--radius-sm);">
          <div style="font-size:0.85rem;color:var(--fg2)">
            <strong>Any 2 of 3</strong> shards reconstruct your Ed25519 private key → full wallet access.<br/>
            <span style="color:var(--accent2)">A+B</span> = Normal use &nbsp;|&nbsp;
            <span style="color:var(--gold)">A+C</span> = Server down recovery &nbsp;|&nbsp;
            <span style="color:var(--green)">B+C</span> = Lost device recovery
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════════════════════════ -->
  <!-- TAB 4: SEND BB                                              -->
  <!-- ═══════════════════════════════════════════════════════════ -->
  <div class="tab-content" id="tab-send">
    <div class="panels">
      <div class="panel">
        <h2><span class="icon">📤</span> Send BB (SSS-Signed)</h2>
        <div class="send-form">
          <div class="form-group">
            <label>From Wallet (SSS-enabled only)</label>
            <select id="sendFrom"></select>
            <div style="font-size:0.7rem;color:var(--fg3);margin-top:4px">Only wallets created through Create Wallet can send — they have Share B stored on-node.</div>
          </div>
          <div class="form-group">
            <label>To Address</label>
            <input type="text" id="sendTo" placeholder="Recipient BlackBook address"/>
          </div>
          <div class="form-group">
            <label>Amount (BB)</label>
            <input type="number" id="sendAmount" placeholder="0.00" min="0" step="0.000000001"/>
          </div>

          <!-- Share A mode toggle -->
          <div class="form-group">
            <label>Share A — How are you providing it?</label>
            <div style="display:flex;gap:8px;margin-top:4px">
              <button class="btn btn-sm" id="modeEncBtn" onclick="setSendMode('encrypted')" style="flex:1;opacity:1">🔒 Encrypted Blob + Password</button>
              <button class="btn btn-sm btn-outline" id="modeRawBtn" onclick="setSendMode('raw')" style="flex:1;opacity:0.5">🔓 Raw Shard A (hex)</button>
            </div>
          </div>

          <!-- Encrypted mode fields -->
          <div id="sendModeEncrypted">
            <div class="form-group">
              <label>Encrypted Share A Blob</label>
              <textarea id="sendShareA" rows="2" placeholder="e.g. J3rOIz9V…:ee79c3…:644d28…" style="resize:vertical"></textarea>
            </div>
            <div class="form-group">
              <label>Password (to decrypt Share A)</label>
              <input type="password" id="sendPassword" placeholder="The password you set during wallet creation"/>
            </div>
          </div>

          <!-- Raw mode field -->
          <div id="sendModeRaw" style="display:none">
            <div class="form-group">
              <label>Raw Shard A (hex)</label>
              <textarea id="sendShareARaw" rows="2" placeholder="Paste your unencrypted Share A hex…" style="resize:vertical"></textarea>
              <div style="font-size:0.7rem;color:var(--fg3);margin-top:4px">If you created your wallet without a password, this is the hex string you received.</div>
            </div>
          </div>

          <button class="btn btn-primary" id="sendBtn" onclick="sendBB()" style="width:100%">Send BB</button>
        </div>
      </div>

      <div class="panel">
        <h2><span class="icon">💰</span> Quick Balance Check</h2>
        <div class="accounts" id="sendAccountList">
          <div class="empty">Loading…</div>
        </div>
      </div>
    </div>
  </div>

  <footer>
    BlackBook L1 — Digital Central Bank &nbsp;|&nbsp; Node RPC: <span id="rpcUrl"></span> &nbsp;|&nbsp; Genesis: <span id="genesisHash">—</span>
  </footer>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
// ══════════════════════════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════════════════════════
const RPC = window.location.protocol + '//' + window.location.hostname + ':8899';
const API = window.location.origin;
const LAMPORTS_PER_BB = 1_000_000_000;

// In-memory state for current session
let currentWallet = null;   // { wallet_id, address, mnemonic, share_a, share_c, public_key, share_a_is_encrypted }
let selectedAccount = null;
let selectedCombo = 'AB';

// Known network accounts
const KNOWN_ACCOUNTS = [
  { name: 'Max',    address: '4PtfY2ySdcGpshvfqfnaNyAVBFKtpLbZ4HTBHZBT2oby', role: 'admin' },
  { name: 'Alice',  address: 'HVbEJfko9NzqrnKzmbsJBU3rLSHehNZVEFXqiPkDCUSc', role: 'user' },
  { name: 'Bob',    address: '6fsVDKyh5UXkMVE8bBrVTiqHWAqXUeseUXFTJh2UUnn2', role: 'user' },
  { name: 'Apollo', address: '5Pk2JZ5ZfkeUdjVFzT2iY3GtcQ28Lx4cxpr7yPteTqmd', role: 'user' },
  { name: 'Dealer', address: 'DcdsDp8fQVPthhPx6wRWQaErHfDw6sKEsijs49zuCYZo', role: 'dealer' },
];

let accounts = [...KNOWN_ACCOUNTS];
let balances = {};

// ══════════════════════════════════════════════════════════════
// TAB SWITCHING
// ══════════════════════════════════════════════════════════════
function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-' + tab).classList.add('active');

  if (tab === 'dashboard') { refreshBalances(); }
  if (tab === 'send') { refreshBalances(); }
  if (tab === 'sss-test') {
    if (!currentWallet) {
      document.getElementById('sssNoWallet').style.display = 'block';
      document.getElementById('sssTestArea').style.display = 'none';
    } else {
      document.getElementById('sssNoWallet').style.display = 'none';
      document.getElementById('sssTestArea').style.display = 'block';
      document.getElementById('sssWalletId').value = currentWallet.address;
      // Pre-fill Share A if available
      document.getElementById('sssInput1').value = currentWallet.share_a || '';
    }
  }
}

// ══════════════════════════════════════════════════════════════
// RPC HELPERS
// ══════════════════════════════════════════════════════════════
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

async function apiPost(path, body) {
  const res = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ══════════════════════════════════════════════════════════════
// FORMATTING
// ══════════════════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════════════════
// TOAST
// ══════════════════════════════════════════════════════════════
function toast(msg, type = 'info') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show ' + type;
  setTimeout(() => el.className = 'toast', 3500);
}

// ══════════════════════════════════════════════════════════════
// REVEAL / COPY HELPERS
// ══════════════════════════════════════════════════════════════
function toggleReveal(elementId, btn) {
  const el = document.getElementById(elementId);
  if (el.classList.contains('revealed')) {
    el.classList.remove('revealed');
    if (btn) btn.textContent = '👁 Reveal';
  } else {
    el.classList.add('revealed');
    if (btn) btn.textContent = '🙈 Hide';
  }
}

function copyText(elementId) {
  const el = document.getElementById(elementId);
  const text = el.textContent || el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    toast('Copied to clipboard!', 'success');
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    toast('Copied!', 'success');
  });
}

// ══════════════════════════════════════════════════════════════
// CREATE WALLET
// ══════════════════════════════════════════════════════════════
async function createWallet() {
  const username = document.getElementById('createUsername').value.trim();
  const password = document.getElementById('createPassword').value;
  const confirm = document.getElementById('createPasswordConfirm').value;
  const btn = document.getElementById('createWalletBtn');

  if (!username) return toast('Enter a username', 'error');
  if (!password) return toast('Enter a password to encrypt your shard', 'error');
  if (password !== confirm) return toast('Passwords do not match', 'error');
  if (password.length < 8) return toast('Password must be at least 8 characters', 'error');

  btn.disabled = true;
  btn.textContent = 'Creating wallet…';

  try {
    const data = await apiPost('/wallet/create', {
      username: username,
      password: password,
    });

    // Store wallet in session
    currentWallet = {
      wallet_id: data.wallet_id,
      address: data.address,
      mnemonic: data.mnemonic,
      share_a: data.share_a,
      share_a_is_encrypted: data.share_a_is_encrypted,
      share_c: data.share_c,
      public_key: data.public_key,
    };

    // Also save to localStorage for persistence
    localStorage.setItem('bb_wallet', JSON.stringify({
      wallet_id: data.wallet_id,
      address: data.address,
      share_a: data.share_a,
      share_a_is_encrypted: data.share_a_is_encrypted,
      public_key: data.public_key,
    }));

    // Add to accounts list
    if (!accounts.find(a => a.address === data.address)) {
      accounts.push({ name: username, address: data.address, role: 'user' });
    }

    // Populate step 2
    document.getElementById('walletAddress').textContent = data.address;
    document.getElementById('mnemonicValue').textContent = data.mnemonic;
    document.getElementById('shardAData').textContent = data.share_a;
    document.getElementById('shardAEncrypted').textContent = data.share_a_is_encrypted
      ? '🔒 Encrypted with your password (AES-256-GCM + Argon2id)'
      : '⚠️ NOT encrypted — no password provided';
    document.getElementById('shardCData').textContent = data.share_c;

    // Transition to step 2
    document.getElementById('createStep1').style.display = 'none';
    document.getElementById('createStep2').style.display = 'block';

    toast('Wallet created successfully!', 'success');
  } catch (e) {
    toast('Failed: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Wallet';
  }
}

function proceedToStep3() {
  document.getElementById('createStep2').style.display = 'none';
  document.getElementById('createStep3').style.display = 'block';
}

function updateChecks() {
  const checks = document.querySelectorAll('#confirmChecks input[type=checkbox]');
  const icons = ['chk1','chk2','chk3','chk4','chk5'];
  let allChecked = true;
  checks.forEach((c, i) => {
    document.getElementById(icons[i]).textContent = c.checked ? '✅' : '☐';
    if (!c.checked) allChecked = false;
  });
  document.getElementById('finishBtn').disabled = !allChecked;
}

function finishSetup() {
  // Switch to dashboard
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab')[1].classList.add('active');
  document.getElementById('tab-dashboard').classList.add('active');
  refreshBalances();
  toast('Welcome to BlackBook! Your wallet is ready.', 'success');
}

// ══════════════════════════════════════════════════════════════
// SSS RECOVERY TEST
// ══════════════════════════════════════════════════════════════
function selectCombo(combo) {
  selectedCombo = combo;
  document.querySelectorAll('.combo-card').forEach(c => c.classList.remove('selected'));
  document.getElementById('combo' + combo).classList.add('selected');

  const s1Label = document.getElementById('shard1Label');
  const s2Label = document.getElementById('shard2Label');
  const pwGroup = document.getElementById('passwordGroup');
  const s1Input = document.getElementById('sssInput1');
  const s2Input = document.getElementById('sssInput2');

  // Reset
  s1Input.value = '';
  s2Input.value = '';
  document.getElementById('sssPassword').value = '';

  switch (combo) {
    case 'AB':
      s1Label.textContent = 'Share A (paste encrypted blob)';
      s2Label.textContent = 'Share B (auto-fetched from node — or paste server-encrypted blob)';
      pwGroup.style.display = 'block';
      if (currentWallet) {
        s1Input.value = currentWallet.share_a || '';
      }
      break;
    case 'AC':
      s1Label.textContent = 'Share A (paste encrypted blob)';
      s2Label.textContent = 'Share C (paste raw hex from cold storage)';
      pwGroup.style.display = 'block';
      if (currentWallet) {
        s1Input.value = currentWallet.share_a || '';
        s2Input.value = currentWallet.share_c || '';
      }
      break;
    case 'BC':
      s1Label.textContent = 'Share B (auto-fetched from node — or paste server-encrypted blob)';
      s2Label.textContent = 'Share C (paste raw hex from cold storage)';
      pwGroup.style.display = 'none';
      if (currentWallet) {
        s2Input.value = currentWallet.share_c || '';
      }
      break;
  }
}

async function runSSSTest() {
  const walletId = document.getElementById('sssWalletId').value.trim();
  const input1 = document.getElementById('sssInput1').value.trim();
  let input2 = document.getElementById('sssInput2').value.trim();
  const password = document.getElementById('sssPassword').value;
  const btn = document.getElementById('sssTestBtn');
  const resultBox = document.getElementById('sssResultBox');

  if (!walletId) return toast('Enter wallet address', 'error');

  btn.disabled = true;
  btn.textContent = 'Verifying…';

  try {
    let shard1, shard2, pwd = null, shard2ServerEncrypted = false;

    if (selectedCombo === 'AB') {
      // A + B
      if (!input1) return toast('Paste Share A', 'error');
      shard1 = input1;
      pwd = password;

      // Auto-fetch Share B if not provided
      if (!input2) {
        const bResp = await apiPost('/wallet/secure/shard-b', { wallet_id: walletId });
        input2 = bResp.shard_b;
      }
      shard2 = input2;
      shard2ServerEncrypted = true;

    } else if (selectedCombo === 'AC') {
      // A + C
      if (!input1) return toast('Paste Share A', 'error');
      if (!input2) return toast('Paste Share C', 'error');
      shard1 = input1;
      shard2 = input2;
      pwd = password;

    } else if (selectedCombo === 'BC') {
      // B + C
      if (!input2) return toast('Paste Share C', 'error');

      // Auto-fetch Share B if not provided
      if (!input1) {
        const bResp = await apiPost('/wallet/secure/shard-b', { wallet_id: walletId });
        input1 = bResp.shard_b;
      }
      shard1 = input1;
      shard2 = input2;
      shard2ServerEncrypted = false;

      // For B+C, shard1 is server-encrypted
      // We send shard1 as server-encrypted and shard2 as raw hex
      const verifyData = {
        wallet_id: walletId,
        shard_1: shard1,
        shard_2: shard2,
        shard_2_is_server_encrypted: false,
      };
      // Shard 1 is B (server encrypted), need special handling
      // Actually, the verify endpoint needs to know which one is encrypted
      // Let's swap: pass B as shard_1 with server decryption, C as shard_2
      verifyData.shard_1 = shard1; // B (server-encrypted)
      verifyData.password = null; // no password — server encrypted
      // We'll tell the endpoint to server-decrypt shard_1 via a workaround
      // Actually, the endpoint expects password for shard_1 and shard_2_is_server_encrypted for shard_2
      // For B+C: Shard B is server-encrypted, Shard C is raw hex
      // So: shard_1 = C (raw hex), shard_2 = B (server-encrypted)
      const result = await apiPost('/wallet/verify-sss', {
        wallet_id: walletId,
        shard_1: shard2,  // C is raw hex
        shard_2: shard1,  // B is server-encrypted
        shard_2_is_server_encrypted: true,
      });

      showSSSResult(result);
      return;
    }

    // For A+B and A+C
    const verifyPayload = {
      wallet_id: walletId,
      shard_1: shard1,
      shard_2: shard2,
      password: pwd || undefined,
      shard_2_is_server_encrypted: shard2ServerEncrypted,
    };

    const result = await apiPost('/wallet/verify-sss', verifyPayload);
    showSSSResult(result);

  } catch (e) {
    resultBox.style.display = 'block';
    resultBox.innerHTML = `
      <div class="sss-result fail">
        <div class="result-icon">❌</div>
        <div class="result-title">Verification Failed</div>
        <div class="result-detail">${e.message}</div>
      </div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = '🔐 Verify 2/3 SSS Reconstruction';
  }
}

function showSSSResult(result) {
  const resultBox = document.getElementById('sssResultBox');
  resultBox.style.display = 'block';

  if (result.matches) {
    resultBox.innerHTML = `
      <div class="sss-result pass">
        <div class="result-icon">✅</div>
        <div class="result-title">2/3 SSS Reconstruction Successful!</div>
        <div class="result-detail">
          Wallet: ${result.wallet_id}<br/>
          Derived: ${result.derived_address}<br/>
          <strong style="color:var(--green)">Match: TRUE — Full wallet access verified</strong>
        </div>
      </div>`;
    toast('SSS verification passed!', 'success');
  } else {
    resultBox.innerHTML = `
      <div class="sss-result fail">
        <div class="result-icon">❌</div>
        <div class="result-title">Reconstruction Mismatch</div>
        <div class="result-detail">
          Expected: ${result.wallet_id}<br/>
          Got: ${result.derived_address}<br/>
          <strong style="color:var(--red)">Wrong shards or wrong password</strong>
        </div>
      </div>`;
    toast('SSS verification failed — wrong shards or password', 'error');
  }
}

// ══════════════════════════════════════════════════════════════
// NETWORK STATS
// ══════════════════════════════════════════════════════════════
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

    try {
      const supply = await rpc('getSupply');
      document.getElementById('statSupply').textContent = formatBB(supply.value.total) + ' BB';
    } catch(e) {
      document.getElementById('statSupply').textContent = '–';
    }
  } catch (e) {
    document.getElementById('netStatus').textContent = 'Disconnected ✕';
  }
}

// ══════════════════════════════════════════════════════════════
// ACCOUNT BALANCES
// ══════════════════════════════════════════════════════════════
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
  const sendList = document.getElementById('sendAccountList');

  list.innerHTML = accounts.map(a => {
    const lam = balances[a.address] || 0;
    const isActive = selectedAccount === a.address;
    const isMyWallet = currentWallet && currentWallet.address === a.address;
    const roleBadge = isMyWallet ? ' 🔐' : a.role === 'admin' ? ' 🔑' : a.role === 'dealer' ? ' 🏦' : '';
    return `<div class="account ${isActive ? 'active' : ''}" onclick="selectAccount('${a.address}')">
      <div class="name">${a.name}${roleBadge}</div>
      <div class="addr">${a.address}</div>
      <div class="bal">${formatBB(lam)} BB</div>
    </div>`;
  }).join('');

  if (select) {
    // Only show SSS-enabled wallets (created via /wallet/create) in the Send dropdown
    const sssWallets = accounts.filter(a => {
      if (currentWallet && currentWallet.address === a.address) return true;
      // Check localStorage for other SSS wallets
      try {
        const saved = localStorage.getItem('bb_wallet');
        if (saved) {
          const w = JSON.parse(saved);
          if (w.address === a.address) return true;
        }
      } catch(e) {}
      return false;
    });

    if (sssWallets.length === 0) {
      select.innerHTML = '<option value="" disabled selected>No SSS wallet — create one first</option>';
    } else {
      select.innerHTML = sssWallets.map(a => {
        const lam = balances[a.address] || 0;
        return `<option value="${a.address}">${a.name} — ${a.address.slice(0,8)}… (${formatBB(lam)} BB)</option>`;
      }).join('');
    }
  }

  if (sendList) {
    sendList.innerHTML = accounts.map(a => {
      const lam = balances[a.address] || 0;
      return `<div class="account" style="cursor:default">
        <div class="name">${a.name}</div>
        <div class="addr">${a.address}</div>
        <div class="bal">${formatBB(lam)} BB</div>
      </div>`;
    }).join('');
  }
}

// ══════════════════════════════════════════════════════════════
// SELECT ACCOUNT / TX HISTORY
// ══════════════════════════════════════════════════════════════
async function selectAccount(addr) {
  selectedAccount = addr;
  renderAccounts();
  await refreshTransactions(addr);
  await showAccountDetail(addr);
}

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
  }
}

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

// ══════════════════════════════════════════════════════════════
// SEND BB (SSS-SIGNED)
// ══════════════════════════════════════════════════════════════
let sendMode = 'encrypted'; // 'encrypted' | 'raw'

function setSendMode(mode) {
  sendMode = mode;
  document.getElementById('sendModeEncrypted').style.display = mode === 'encrypted' ? 'block' : 'none';
  document.getElementById('sendModeRaw').style.display = mode === 'raw' ? 'block' : 'none';
  // Toggle button styling
  document.getElementById('modeEncBtn').style.opacity = mode === 'encrypted' ? '1' : '0.5';
  document.getElementById('modeRawBtn').style.opacity = mode === 'raw' ? '1' : '0.5';
  document.getElementById('modeEncBtn').className = mode === 'encrypted' ? 'btn btn-sm' : 'btn btn-sm btn-outline';
  document.getElementById('modeRawBtn').className = mode === 'raw' ? 'btn btn-sm' : 'btn btn-sm btn-outline';
}

async function sendBB() {
  const from = document.getElementById('sendFrom').value;
  const to = document.getElementById('sendTo').value.trim();
  const amountBB = parseFloat(document.getElementById('sendAmount').value);
  const btn = document.getElementById('sendBtn');

  if (!to) return toast('Enter a recipient address', 'error');
  if (!amountBB || amountBB <= 0) return toast('Enter a valid amount', 'error');

  let body = { from_wallet_id: from, to_address: to, amount: amountBB };

  if (sendMode === 'encrypted') {
    const shareA = document.getElementById('sendShareA').value.trim();
    const password = document.getElementById('sendPassword').value;
    if (!shareA) return toast('Paste your encrypted Share A blob', 'error');
    if (!password) return toast('Enter your password to decrypt Share A', 'error');
    body.share_a = shareA;
    body.password = password;
  } else {
    const rawA = document.getElementById('sendShareARaw').value.trim();
    if (!rawA) return toast('Paste your raw Share A hex', 'error');
    body.share_a = rawA;
    // No password — server will decode raw hex directly
  }

  btn.disabled = true;
  btn.textContent = 'Signing & Sending…';

  try {
    const data = await apiPost('/transfer', body);

    toast(`Sent ${amountBB} BB! Sig: ${data.signature.slice(0,16)}…`, 'success');
    document.getElementById('sendAmount').value = '';
    document.getElementById('sendTo').value = '';

    setTimeout(async () => {
      await refreshBalances();
    }, 500);
  } catch (e) {
    toast('Transfer failed: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send BB';
  }
}

// ══════════════════════════════════════════════════════════════
// LOOKUP
// ══════════════════════════════════════════════════════════════
async function lookupAddress() {
  const addr = document.getElementById('lookupAddr').value.trim();
  if (!addr) return;

  if (!accounts.find(a => a.address === addr)) {
    accounts.push({ name: shortAddr(addr), address: addr, role: 'unknown' });
  }

  await refreshBalances();
  await selectAccount(addr);
  document.getElementById('lookupAddr').value = '';
}

// ══════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════
document.getElementById('rpcUrl').textContent = RPC;

// Restore wallet from localStorage if exists
(function restoreWallet() {
  try {
    const saved = localStorage.getItem('bb_wallet');
    if (saved) {
      const w = JSON.parse(saved);
      currentWallet = w;
      if (!accounts.find(a => a.address === w.address)) {
        accounts.push({ name: 'My Wallet', address: w.address, role: 'user' });
      }
      // Pre-fill Send tab Share A
      if (w.share_a) {
        setTimeout(() => {
          const el = document.getElementById('sendShareA');
          if (el) el.value = w.share_a;
        }, 100);
      }
    }
  } catch (e) {}
})();

async function init() {
  await refreshStats();
  await refreshBalances();
  if (accounts.length > 0) selectAccount(accounts[0].address);

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
