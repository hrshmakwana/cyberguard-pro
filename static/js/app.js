const reportState = {
  lastHash: null,
  lastIntegrityCheck: null,
  lastScan: null,
  reconSections: [],
  lastEncryptionOp: null,
};
function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  event.currentTarget.classList.add('active');
}
const bootLines = [
  ['$ ', 'Starting CyberGuard Pro v2.0...'],
  ['✓ ', 'Flask API: http:
  ['✓ ', 'hashlib → File Integrity module ready'],
  ['✓ ', 'requests + bs4 → Vuln Scanner ready'],
  ['✓ ', 'socket + threading → Port Scanner ready'],
  ['✓ ', 'cryptography → AES-256 Encryption ready'],
  ['✓ ', 'reportlab → PDF Report Generator ready'],
  ['★ ', 'All modules online. Ready.'],
];
let li = 0;
const term = document.getElementById('term-boot');
function bootLine() {
  if (li >= bootLines.length) return;
  const [prefix, text] = bootLines[li++];
  const d = document.createElement('div');
  d.className = 'line';
  d.innerHTML = `<span class="prompt">${prefix}</span><span class="cmd">${text}</span>`;
  term.appendChild(d);
  term.scrollTop = term.scrollHeight;
  setTimeout(bootLine, 340);
}
setTimeout(bootLine, 500);
function showSpinner(id, show) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('show', show);
}
function showProgress(id, show) {
  const el = document.getElementById(id);
  if (el) el.style.display = show ? 'block' : 'none';
}
function showResult(id, html) {
  const el = document.getElementById(id);
  el.innerHTML = html;
  el.classList.add('show');
}
function riskColor(r) {
  return r === 'HIGH' ? 'red' : r === 'MEDIUM' ? 'orange' : 'green';
}
function showDownloadBtn(id) {
  const btn = document.getElementById(id);
  if (btn) btn.classList.remove('hidden');
}
function hideDownloadBtn(id) {
  const btn = document.getElementById(id);
  if (btn) btn.classList.add('hidden');
}
async function downloadPDF(endpoint, data, defaultFilename) {
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      alert('PDF generation failed: ' + (err.error || 'Unknown error'));
      return;
    }
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = defaultFilename || 'CyberGuard_Report.pdf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  } catch (e) {
    alert('PDF download failed: ' + e.message);
  }
}
async function computeHash() {
  const file = document.getElementById('hash-file').files[0];
  if (!file) return alert('Please select a file.');
  showSpinner('hash-spinner', true);
  hideDownloadBtn('btn-dl-hash');
  const form = new FormData();
  form.append('file', file);
  try {
    const res = await fetch('/api/hash', { method: 'POST', body: form });
    const d = await res.json();
    showSpinner('hash-spinner', false);
    const table = document.getElementById('hash-table');
    const tbody = table.querySelector('tbody');
    table.style.display = 'table';
    tbody.innerHTML = ['md5','sha1','sha256','sha512'].map(algo => `
      <tr>
        <td style="color:var(--cyan);font-weight:600;white-space:nowrap">${algo.toUpperCase()}</td>
        <td style="color:var(--green)">${d[algo]}</td>
      </tr>
    `).join('');
    document.getElementById('hash-meta').textContent =
      `File: ${d.filename} · Size: ${(d.size_bytes/1024).toFixed(2)} KB · ${d.timestamp}`;
    reportState.lastHash = { ...d, report_type: 'hash' };
    showDownloadBtn('btn-dl-hash');
  } catch(e) {
    showSpinner('hash-spinner', false);
    alert('Error: ' + e.message);
  }
}
async function saveBaseline() {
  const file = document.getElementById('baseline-file').files[0];
  if (!file) return alert('Please select a file.');
  showSpinner('bl-spinner', true);
  const form = new FormData();
  form.append('file', file);
  const res = await fetch('/api/integrity/save', { method: 'POST', body: form });
  const d = await res.json();
  showSpinner('bl-spinner', false);
  showResult('bl-result', d.error
    ? `<span class="err">❌ ${d.error}</span>`
    : `<span class="ok">✅ Baseline saved for '${file.name}'</span>\n` +
      Object.entries(d.hashes).map(([k,v]) => `<span class="key">${k.toUpperCase()}</span>: ${v}`).join('\n')
  );
}
async function checkIntegrity() {
  const file = document.getElementById('check-file').files[0];
  if (!file) return alert('Please select a file.');
  showSpinner('chk-spinner', true);
  hideDownloadBtn('btn-dl-integrity');
  const form = new FormData();
  form.append('file', file);
  const res = await fetch('/api/integrity/check', { method: 'POST', body: form });
  const d = await res.json();
  showSpinner('chk-spinner', false);
  if (d.error) {
    showResult('chk-result', `<span class="err">❌ ${d.error}</span>`);
    return;
  }
  let html = d.intact
    ? `<span class="ok">✅ File is INTACT — No changes detected</span>\n`
    : `<span class="err">⚠️  File has been MODIFIED — ${d.changes.length} hash(es) changed</span>\n`;
  html += `\n<span class="info">── Current Hashes ──</span>\n`;
  for (const [k,v] of Object.entries(d.current_hashes)) {
    const changed = d.changes.some(c => c.algo === k);
    html += `<span class="key">${k.toUpperCase()}</span>: <span class="${changed?'err':'ok'}">${v}</span>\n`;
  }
  if (d.changes.length) {
    html += `\n<span class="warn">── Baseline Values (original) ──</span>\n`;
    for (const c of d.changes) {
      html += `<span class="key">${c.algo.toUpperCase()}</span>: <span class="warn">${c.baseline}</span>\n`;
    }
  }
  showResult('chk-result', html);
  reportState.lastIntegrityCheck = { ...d, report_type: 'check' };
  showDownloadBtn('btn-dl-integrity');
}
function downloadHashPDF() {
  if (!reportState.lastHash) return alert('Run a hash computation first.');
  downloadPDF('/api/report/integrity', reportState.lastHash, `CyberGuard_Hash_${reportState.lastHash.filename}.pdf`);
}
function downloadIntegrityPDF() {
  if (!reportState.lastIntegrityCheck) return alert('Run an integrity check first.');
  downloadPDF('/api/report/integrity', reportState.lastIntegrityCheck, `CyberGuard_Integrity_${reportState.lastIntegrityCheck.filename}.pdf`);
}
async function runScan() {
  const url = document.getElementById('scan-url').value.trim();
  if (!url) return alert('Please enter a URL.');
  showSpinner('scan-spinner', true);
  showProgress('scan-progress', true);
  hideDownloadBtn('btn-dl-scan');
  document.getElementById('scan-status').textContent = 'Scanning… this may take 10–20 seconds';
  document.getElementById('scan-results').style.display = 'none';
  const res = await fetch('/api/scan', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({url})
  });
  const d = await res.json();
  showSpinner('scan-spinner', false);
  showProgress('scan-progress', false);
  document.getElementById('scan-status').textContent = `Done · ${d.summary?.total||0} issue(s) found`;
  document.getElementById('scan-results').style.display = 'block';
  const rc = riskColor(d.risk);
  document.getElementById('scan-risk-content').innerHTML = `
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <div class="pill pill-${rc==='green'?'green':rc==='orange'?'orange':'red'}">
        ${d.risk} RISK
      </div>
      <div style="font-size:13px;color:var(--muted)">
        ${d.summary?.total||0} total issues ·
        <span style="color:var(--red)">${d.summary?.high||0} HIGH</span> ·
        <span style="color:var(--orange)">${d.summary?.medium||0} MEDIUM</span> ·
        ${d.summary?.missing_headers||0} missing headers
      </div>
    </div>
    ${(d.info||[]).map(i=>`<div style="font-size:12px;color:var(--muted);margin-top:6px;font-family:var(--font)">${i}</div>`).join('')}
  `;
  const vulnEl = document.getElementById('scan-vulns');
  if (!d.vulnerabilities?.length) {
    vulnEl.innerHTML = '<span style="color:var(--green);font-size:13px">✅ No direct vulnerabilities detected in forms.</span>';
  } else {
    vulnEl.innerHTML = d.vulnerabilities.map(v => `
      <div class="vuln-item vuln-${(v.severity||'medium').toLowerCase()}">
        <div class="vuln-title">${v.type} <span class="pill pill-${v.severity==='HIGH'?'red':'orange'}" style="font-size:10px">${v.severity}</span></div>
        <div class="vuln-meta">${v.form||v.path||''} ${v.payload?'· payload: '+v.payload:''} ${v.evidence?'· evidence: '+v.evidence:''}</div>
      </div>
    `).join('');
  }
  const mh = d.headers?.missing||[];
  document.getElementById('missing-headers').innerHTML = mh.length
    ? mh.map(h=>`<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px">
        <span style="color:var(--red)">✗</span>
        <span style="color:var(--text);font-family:var(--font)">${h.header}</span>
      </div>`).join('')
    : '<span style="color:var(--green);font-size:13px">✅ All security headers present!</span>';
  const ph = d.headers?.present||[];
  document.getElementById('present-headers').innerHTML = ph.map(h=>`
    <div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:12px">
      <span style="color:var(--green)">✓</span>
      <span style="color:var(--text);font-family:var(--font);margin-left:8px">${h.header}</span>
    </div>`).join('') || '<span style="color:var(--muted)">None</span>';
  const ssl = d.ssl||{};
  document.getElementById('ssl-info').innerHTML = `
    <div style="font-size:13px;margin-bottom:8px">
      ${ssl.has_ssl
        ? `<span class="pill pill-green">✅ HTTPS Enabled</span>`
        : `<span class="pill pill-red">❌ HTTP Only</span>`}
    </div>
    ${ssl.version?`<div style="font-size:12px;color:var(--muted);font-family:var(--font)">Version: ${ssl.version}</div>`:''}
    ${ssl.cipher?`<div style="font-size:12px;color:var(--muted);font-family:var(--font)">Cipher: ${ssl.cipher}</div>`:''}
    ${(ssl.issues||[]).map(i=>`<div style="font-size:12px;color:var(--red);margin-top:4px">⚠ ${i}</div>`).join('')}
  `;
  document.getElementById('page-info').innerHTML = (d.info||[]).map(i=>
    `<div style="font-size:12px;padding:5px 0;border-bottom:1px solid var(--border);font-family:var(--font);color:var(--muted)">${i}</div>`
  ).join('');
  reportState.lastScan = d;
  showDownloadBtn('btn-dl-scan');
}
function downloadScanPDF() {
  if (!reportState.lastScan) return alert('Run a vulnerability scan first.');
  downloadPDF('/api/report/scan', reportState.lastScan, 'CyberGuard_VulnScan_Report.pdf');
}
async function runPortScan() {
  const host = document.getElementById('ps-host').value.trim();
  const mode = document.getElementById('ps-mode').value;
  if (!host) return alert('Please enter a host.');
  showSpinner('ps-spinner', true);
  showProgress('ps-progress', true);
  document.getElementById('ps-status').textContent = 'Scanning… please wait';
  document.getElementById('ps-results').innerHTML = '';
  const res = await fetch('/api/portscan', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({host, mode})
  });
  const d = await res.json();
  showSpinner('ps-spinner', false);
  showProgress('ps-progress', false);
  if (d.error) {
    document.getElementById('ps-status').textContent = '❌ ' + d.error;
    return;
  }
  document.getElementById('ps-status').textContent =
    `${d.total_open} open port(s) found · ${d.ports_scanned} scanned · ${d.duration_s}s`;
  const el = document.getElementById('ps-results');
  if (!d.open_ports.length) {
    el.innerHTML = '<span style="color:var(--muted);font-size:13px">No open ports found in selected range.</span>';
    return;
  }
  el.innerHTML = `
    <div style="font-size:12px;color:var(--muted);margin-bottom:10px;font-family:var(--font)">
      Host: <span style="color:var(--cyan)">${d.host}</span> → IP: <span style="color:var(--green)">${d.ip}</span>
    </div>
    <div class="port-grid">
      ${d.open_ports.map(p=>`
        <div class="port-card">
          <div class="port-num">${p.port}</div>
          <div class="port-svc">${p.service}</div>
          <div style="margin-top:4px"><span class="pill pill-green" style="font-size:10px">OPEN</span></div>
          ${p.banner?`<div class="port-banner">${p.banner}</div>`:''}
        </div>
      `).join('')}
    </div>
  `;
  reportState.reconSections = reportState.reconSections.filter(s => s.type !== 'portscan');
  reportState.reconSections.push({ type: 'portscan', data: d });
  showDownloadBtn('btn-dl-recon');
}
async function runDNS() {
  const domain = document.getElementById('dns-domain').value.trim();
  if (!domain) return alert('Please enter a domain.');
  showSpinner('dns-spinner', true);
  const res = await fetch('/api/dns', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({domain})
  });
  const d = await res.json();
  showSpinner('dns-spinner', false);
  if (d.error) {
    showResult('dns-result', `<span class="err">❌ ${d.error}</span>`);
    return;
  }
  let html = `<span class="info">Domain: ${d.domain}</span>\n\n`;
  for (const [type, val] of Object.entries(d.records||{})) {
    html += `<span class="key">${type}</span>: <span class="ok">${val}</span>\n`;
  }
  if (d.all_ips?.length > 1) {
    html += `\n<span class="info">All IPs:</span>\n` + d.all_ips.map(ip=>`  ${ip}`).join('\n');
  }
  showResult('dns-result', html);
  reportState.reconSections = reportState.reconSections.filter(s => s.type !== 'dns');
  reportState.reconSections.push({ type: 'dns', data: d });
  showDownloadBtn('btn-dl-recon');
}
async function runPing() {
  const host = document.getElementById('ping-host').value.trim();
  if (!host) return alert('Please enter a host.');
  showSpinner('ping-spinner', true);
  const res = await fetch('/api/ping', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({host})
  });
  const d = await res.json();
  showSpinner('ping-spinner', false);
  showResult('ping-result', d.reachable
    ? `<span class="ok">✅ REACHABLE</span>\n\nHost: <span class="info">${d.host}</span>\nIP:   <span class="info">${d.ip}</span>\nLatency: <span class="ok">${d.latency_ms} ms</span>`
    : `<span class="err">❌ UNREACHABLE</span>\n\nHost: <span class="info">${d.host}</span>\n${d.error||''}`
  );
  reportState.reconSections = reportState.reconSections.filter(s => s.type !== 'ping');
  reportState.reconSections.push({ type: 'ping', data: d });
  showDownloadBtn('btn-dl-recon');
}
async function runSubdomains() {
  const domain = document.getElementById('sub-domain').value.trim();
  if (!domain) return alert('Please enter a domain.');
  showSpinner('sub-spinner', true);
  const res = await fetch('/api/subdomains', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({domain})
  });
  const d = await res.json();
  showSpinner('sub-spinner', false);
  if (d.error) {
    showResult('sub-result', `<span class="err">❌ ${d.error}</span>`);
    return;
  }
  let html = `<span class="info">Domain: ${d.domain}</span>\nFound: <span class="ok">${d.total||0}</span> subdomains\n\n`;
  if (d.found && d.found.length > 0) {
    for (const sub of d.found) {
      html += `<span class="key">${sub.subdomain}</span>: <span class="info">${sub.ip}</span>\n`;
    }
  } else {
    html += `<span class="warn">No common subdomains found.</span>`;
  }
  showResult('sub-result', html);
  reportState.reconSections = reportState.reconSections.filter(s => s.type !== 'subdomains');
  reportState.reconSections.push({ type: 'subdomains', data: d });
  showDownloadBtn('btn-dl-recon');
}
async function runGeoIP() {
  const target = document.getElementById('geo-target').value.trim();
  if (!target) return alert('Please enter a target.');
  showSpinner('geo-spinner', true);
  const res = await fetch('/api/geoip', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target})
  });
  const d = await res.json();
  showSpinner('geo-spinner', false);
  if (d.error) {
    showResult('geo-result', `<span class="err">❌ ${d.error}</span>`);
    return;
  }
  let html = `<span class="info">Target: ${d.target}</span>\nIP: <span class="ok">${d.ip}</span>\n\n`;
  html += `<span class="key">Country</span>: ${d.country || 'Unknown'}\n`;
  html += `<span class="key">City</span>: ${d.city || 'Unknown'}\n`;
  html += `<span class="key">ISP</span>: ${d.isp || 'Unknown'}\n`;
  html += `<span class="key">Coords</span>: Lat ${d.lat}, Lon ${d.lon}\n`;
  showResult('geo-result', html);
  reportState.reconSections = reportState.reconSections.filter(s => s.type !== 'geoip');
  reportState.reconSections.push({ type: 'geoip', data: d });
  showDownloadBtn('btn-dl-recon');
}
function downloadReconPDF() {
  if (!reportState.reconSections.length) return alert('Run at least one recon tool first.');
  downloadPDF('/api/report/recon', { sections: reportState.reconSections }, 'CyberGuard_Recon_Report.pdf');
}
async function encryptFile() {
  const file = document.getElementById('enc-file').files[0];
  const pass = document.getElementById('enc-pass').value;
  if (!file) return alert('Please select a file.');
  if (!pass) return alert('Please enter a password.');
  if (pass.length < 6) return alert('Password must be at least 6 characters.');
  showSpinner('enc-spinner', true);
  hideDownloadBtn('btn-dl-encrypt');
  showResult('enc-result', '<span class="info">Encrypting with AES-256-CBC…</span>');
  const form = new FormData();
  form.append('file', file);
  form.append('password', pass);
  const res = await fetch('/api/encrypt', { method:'POST', body: form });
  showSpinner('enc-spinner', false);
  if (!res.ok) {
    const err = await res.json();
    showResult('enc-result', `<span class="err">❌ ${err.error}</span>`);
    return;
  }
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = file.name + '.enc';
  a.click();
  showResult('enc-result',
    `<span class="ok">✅ File encrypted and downloaded!</span>\n\n` +
    `Original: <span class="info">${file.name}</span>\nEncrypted: <span class="ok">${file.name}.enc</span>\n` +
    `Algorithm: <span class="key">AES-256-CBC</span>\nKey derivation: <span class="key">PBKDF2-HMAC-SHA256</span>\nIterations: <span class="ok">120,000</span>`
  );
  reportState.lastEncryptionOp = {
    operation: 'encrypt',
    filename: file.name,
    output_filename: file.name + '.enc',
    status: 'success',
    algorithm: 'AES-256-CBC',
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations: '120,000',
    key_size: '256 bits',
    timestamp: new Date().toISOString(),
  };
  showDownloadBtn('btn-dl-encrypt');
}
async function decryptFile() {
  const file = document.getElementById('dec-file').files[0];
  const pass = document.getElementById('dec-pass').value;
  if (!file) return alert('Please select a .enc file.');
  if (!pass) return alert('Please enter the password.');
  showSpinner('dec-spinner', true);
  hideDownloadBtn('btn-dl-decrypt');
  showResult('dec-result', '<span class="info">Decrypting…</span>');
  const form = new FormData();
  form.append('file', file);
  form.append('password', pass);
  const res = await fetch('/api/decrypt', { method:'POST', body: form });
  showSpinner('dec-spinner', false);
  if (!res.ok) {
    const err = await res.json();
    showResult('dec-result', `<span class="err">❌ ${err.error}</span>`);
    return;
  }
  const blob = await res.blob();
  const fname = file.name.replace(/\.enc$/, '');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'decrypted_' + fname;
  a.click();
  showResult('dec-result',
    `<span class="ok">✅ File decrypted and downloaded!</span>\n\n` +
    `Encrypted: <span class="info">${file.name}</span>\nDecrypted: <span class="ok">decrypted_${fname}</span>`
  );
  reportState.lastEncryptionOp = {
    operation: 'decrypt',
    filename: file.name,
    output_filename: 'decrypted_' + fname,
    status: 'success',
    algorithm: 'AES-256-CBC',
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations: '120,000',
    key_size: '256 bits',
    timestamp: new Date().toISOString(),
  };
  showDownloadBtn('btn-dl-decrypt');
}
function downloadEncryptPDF() {
  if (!reportState.lastEncryptionOp) return alert('Perform an encryption or decryption first.');
  downloadPDF('/api/report/encryption', reportState.lastEncryptionOp, 'CyberGuard_Encryption_Report.pdf');
}
