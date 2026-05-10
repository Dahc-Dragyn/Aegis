import './style.css'

interface Signal {
  timestamp: string;
  message: string;
  severity: string;
  control_id: string;
}

const mockSignals: Signal[] = [
  {
    timestamp: "2024-10-22T09:35:15Z",
    message: "☢️ CRITICAL: LINEAGE INVARIANT VIOLATION! cmd.exe spawned from an untrusted or unknown parent (Orphan).",
    severity: "Critical",
    control_id: "SI-4 [Ghost Hunter]"
  },
  {
    timestamp: "2024-10-22T09:35:16Z",
    message: "☢️ RED ALERT: DCSYNC ATTACK DETECTED! Non-DC account 'Administrator' is requesting sensitive directory replication.",
    severity: "Critical",
    control_id: "SI-4 [DCSync Detector]"
  },
  {
    timestamp: "2024-10-22T09:35:18Z",
    message: "☢️ CRITICAL: PASS-THE-HASH ATTACK DETECTED! Anomalous Logon Type 9 via 'seclogo' process.",
    severity: "Critical",
    control_id: "AC-3 [Identity Thief]"
  },
  {
    timestamp: "2024-10-22T09:35:20Z",
    message: "🟡 WARNING: UNKNOWN PROXY EXECUTION! rundll32.exe is running with a non-whitelisted module.",
    severity: "Medium",
    control_id: "SI-4 [Zero-Trust Proxy]"
  }
];

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div class="app-container">
    <header>
      <div class="logo">
        <span class="logo-shield">🛡️</span>
        <span>AEGIS TACTICAL HUD</span>
      </div>
      <div class="system-status">
        <div class="status-indicator alert">
          <div class="live-dot" style="background: var(--accent-red)"></div>
          <span>STATUS: COMPROMISED</span>
        </div>
        <div class="status-indicator">
          <span>FIDELITY: 100%</span>
        </div>
        <div class="timestamp" id="live-clock"></div>
      </div>
    </header>

    <aside>
      <div class="nav-section">
        <div class="nav-title">Mission Control</div>
        <div class="nav-item active">📊 Dashboard</div>
        <div class="nav-item">🔦 Forensic Hunt</div>
        <div class="nav-item">📜 Audit Ledger</div>
      </div>
      <div class="nav-section">
        <div class="nav-title">Compliance</div>
        <div class="nav-item">🛡️ NIST 800-53</div>
        <div class="nav-item">📋 OSCAL Manifest</div>
        <div class="nav-item">🧠 AI Advisor</div>
      </div>
    </aside>

    <main>
      <div class="dashboard-grid">
        <div class="card alert">
          <div class="card-header">
            <div class="card-title">FORENSIC SIGNALS</div>
          </div>
          <div class="card-value">128</div>
        </div>
        <div class="card">
          <div class="card-header">
            <div class="card-title">INGESTION RATE</div>
          </div>
          <div class="card-value">1,420 <span style="font-size: 0.8rem; color: var(--text-dim)">EPS</span></div>
        </div>
        <div class="card">
          <div class="card-header">
            <div class="card-title">ACTIVE INVARIANTS</div>
          </div>
          <div class="card-value">14</div>
        </div>
      </div>

      <div class="card" style="flex: 1; display: flex; flex-direction: column;">
        <div class="card-header">
          <div class="card-title">LIVE TACTICAL STREAM</div>
          <div class="status-indicator" style="background: none; border-color: var(--accent-blue); color: var(--accent-blue)">
            <span>NIST AU-12</span>
          </div>
        </div>
        <div class="signals-list" id="signals-list">
          <!-- Signals will be injected here -->
        </div>
      </div>

      <div class="brief-container">
        <div style="color: var(--accent-blue); margin-bottom: 15px; border-bottom: 1px solid var(--border-color); padding-bottom: 5px;">
          --- 🛡️ AEGIS COMMANDER'S TACTICAL BRIEF ---
        </div>
        <div class="brief-line">STATUS: <span style="color: var(--accent-red)">🔴 COMPROMISED</span></div>
        <div class="brief-line">TIMESTAMP: 2026-05-10T07:49:54Z</div>
        <div class="brief-line">SCANNED ARTIFACT: arniki_T1053.005-1_T1053.005-1_Application.evtx</div>
        <div class="brief-line">FIDELITY: 100% (CERTIFIED)</div>
        <div class="brief-line" style="margin-top: 15px; color: var(--accent-orange)">## 🧠 AI AUGMENTED SITREP</div>
        <div class="brief-line" style="color: var(--text-dim); font-style: italic;">> **AI SYNOPSIS**: Evidence suggests a coordinated lateral movement attempt. DCSync GUIDs detected in conjunction with logon token manipulation (PtH). Host isolation is MANDATORY.</div>
      </div>
    </main>
  </div>
`

function renderSignals() {
  const list = document.querySelector('#signals-list');
  if (!list) return;

  list.innerHTML = mockSignals.map(s => `
    <div class="signal-row">
      <div class="severity ${s.severity.toLowerCase()}">${s.severity.toUpperCase()}</div>
      <div class="timestamp">${s.timestamp.split('T')[1].replace('Z', '')}</div>
      <div class="message">${s.message}</div>
      <div class="control-id">${s.control_id}</div>
    </div>
  `).join('');
}

function updateClock() {
  const clock = document.querySelector('#live-clock');
  if (clock) {
    clock.textContent = new Date().toISOString().replace('T', ' ').split('.')[0];
  }
}

renderSignals();
setInterval(updateClock, 1000);
updateClock();
