"use strict";
// bianbu-security WebUI — 4 Tab（Agent / 能力管理 / DLP / 审计），vanilla JS
const $ = s => document.querySelector(s);
const csrfToken = () => (document.cookie.match(/(?:^|; )bnsec_csrf=([^;]+)/) || [])[1] || "";
const api = async (path, opts) => {
  const r = await fetch("/api" + path, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) {
    const error = new Error(d.error || r.statusText);
    error.status = r.status;
    throw error;
  }
  return d;
};
const post = (path, body) => api(path, {
  method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
  body: JSON.stringify(body || {})
});

let AGENTS = [];
let appStarted = false;
const CAPABILITY_OPTIONS = new Map();

function showLogin() {
  const overlay = $("#login-overlay");
  if (!overlay) return;
  overlay.hidden = false;
  const input = $("#login-token");
  if (input) window.setTimeout(() => input.focus(), 0);
}

function hideLogin() {
  const overlay = $("#login-overlay");
  if (overlay) overlay.hidden = true;
  const error = $("#login-error");
  if (error) { error.hidden = true; error.textContent = ""; }
}

async function login(event) {
  event.preventDefault();
  const input = $("#login-token");
  const error = $("#login-error");
  const token = input ? input.value.trim() : "";
  if (!token) return;
  try {
    const response = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ token })
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "认证失败");
    if (input) input.value = "";
    hideLogin();
    await startApp();
  } catch (e) {
    if (error) { error.textContent = e.message || "认证失败"; error.hidden = false; }
    if (input) { input.select(); input.focus(); }
  }
}

// ── 连接状态 ────────────────────────────────────────────
async function checkConn() {
  const el = $("#conn");
  try { await api("/health"); el.textContent = "已连接 ✓"; el.className = "conn ok"; }
  catch (e) {
    if (e.status === 401) { showLogin(); return false; }
    el.textContent = "未连接 ✗"; el.className = "conn bad";
    return false;
  }
  return true;
}

async function startApp() {
  if (appStarted) return;
  if (!await checkConn()) return;
  appStarted = true;
  initSSE();
  refreshAgents();
}

async function tryLocalAutoAuth() {
  try {
    const r = await fetch("/api/auth/local", {
      method: "POST", credentials: "same-origin"
    });
    if (r.ok) return true;
  } catch (_) { /* fall through to manual login */ }
  return false;
}

// ── Tab 切换 ────────────────────────────────────────────
function initTabs() {
  document.querySelectorAll("#tabs button").forEach(b => {
    b.onclick = () => {
      document.querySelectorAll("#tabs button").forEach(x => x.classList.remove("active"));
      document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      $("#tab-" + b.dataset.tab).classList.add("active");
      if (b.dataset.tab === "caps")  { fillSel("#caps-agent", loadCaps); loadMapping(); }
      if (b.dataset.tab === "permissions") fillSel("#perm-agent", loadPermissions);
      if (b.dataset.tab === "syscalls") fillSel("#sc-agent", loadSyscallPolicy);
      if (b.dataset.tab === "dlp")   { fillSel("#dlp-agent", loadDlp); loadDlpStats(); }
      if (b.dataset.tab === "audit") fillSel("#audit-agent");
    };
  });
}

function initCapabilityPicker() {
  const input = $("#cap-name");
  const list = $("#cap-options");
  const picker = $("#capability-picker");
  if (!input || !list || !picker) return;
  const show = () => {
    renderCapabilityOptions(input.value);
    list.hidden = false;
  };
  input.addEventListener("focus", show);
  input.addEventListener("input", show);
  input.addEventListener("keydown", e => {
    if (e.key === "Escape") list.hidden = true;
  });
  document.addEventListener("click", e => {
    if (!picker.contains(e.target)) list.hidden = true;
  });
}

function renderCapabilityOptions(filter = "") {
  const list = $("#cap-options");
  if (!list) return;
  const query = String(filter).trim().toLowerCase();
  const matches = Array.from(CAPABILITY_OPTIONS.values())
    .filter(item => !query || item.name.toLowerCase().includes(query));
  list.innerHTML = "";
  if (!matches.length) {
    list.innerHTML = '<div class="cap-options-empty">没有匹配的能力</div>';
    return;
  }
  matches.forEach(item => {
    const option = document.createElement("div");
    option.className = "cap-option";
    option.textContent = item.label;
    option.addEventListener("mousedown", e => {
      // mousedown 先于 input blur，确保点击选项不会丢失选择。
      e.preventDefault();
      const input = $("#cap-name");
      if (input) input.value = item.name;
      list.hidden = true;
    });
    list.appendChild(option);
  });
}

function fillSel(sel, cb) {
  const el = $(sel); if (!el) return;
  const prev = el.value; el.innerHTML = "";
  AGENTS.forEach(a => {
    const o = document.createElement("option");
    o.value = a.agent_id; o.textContent = a.agent_id;
    el.appendChild(o);
  });
  if (prev) el.value = prev;
  if (cb) cb();
}

// ── SSE 连接状态 ────────────────────────────────────────
function initSSE() {
  const es = new EventSource("/api/events");
  es.onerror = function() { /* 重连由浏览器自动处理 */ };
}

// ── Tab 1: Agent 列表 ───────────────────────────────────
async function refreshAgents() {
  const tb = $("#agents-table tbody");
  tb.innerHTML = "<tr><td colspan=6>加载中…</td></tr>";
  try {
    const { agents } = await api("/agents");
    AGENTS = agents || [];
    if (!agents.length) { tb.innerHTML = "<tr><td colspan=6 class=dim>暂无已注册 Agent</td></tr>"; return; }
    tb.innerHTML = "";
    agents.forEach(a => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><b>${a.agent_id}</b></td><td>${a.name||"-"}</td><td>${a.version||"-"}</td>` +
        `<td>${a.status||"-"}</td><td>${a.capability_count||0}</td>` +
        `<td><button onclick="goTab('caps','${a.agent_id}')">管理能力</button> ` +
        `<button class=warn onclick="suspendAgent('${a.agent_id}')">暂停</button></td>`;
      tb.appendChild(tr);
    });
  } catch(e) { tb.innerHTML = `<tr><td colspan=6 class=err>${e.message}</td></tr>`; }
}

function goTab(tab, agentId) {
  document.querySelector(`#tabs button[data-tab="${tab}"]`).click();
  setTimeout(() => { $(["caps","audit","sandbox","terminal"].map(t=>t===tab?`#${t}-agent`:null).find(Boolean))
    && (document.querySelector(`#${tab}-agent`).value = agentId) && loadCaps && loadCaps(); }, 100);
}

async function installAgent() {
  const path = $("#install-path").value.trim();
  if (!path) return;
  try {
    const r = await post("/install", { pkg_path: path });
    $("#install-result").textContent = r.ok ? `✓ 安装成功：${r.agent_id}（${r.count} 条能力）` : `✗ 失败：${r.reason}`;
    refreshAgents();
  } catch(e) { $("#install-result").textContent = "✗ " + e.message; }
}

async function suspendAgent(aid) {
  if (!confirm(`暂停 Agent：${aid}？`)) return;
  try { await post(`/agents/${encodeURIComponent(aid)}/suspend`, { reason: "WebUI 手动暂停" }); alert("已发送暂停信号"); }
  catch(e) { alert(e.message); }
}

// ── Tab 2: 能力管理 ─────────────────────────────────────
async function loadCaps() {
  const agent = $("#caps-agent").value;
  const tb = $("#caps-table tbody");
  if (!agent) { tb.innerHTML = "<tr><td colspan=7 class=dim>请选择 Agent</td></tr>"; return; }
  tb.innerHTML = "<tr><td colspan=7>加载中…</td></tr>";
  try {
    const info = await api(`/agents/${encodeURIComponent(agent)}`);
    const caps = info.capabilities || [];
    // 保证当前 Agent 已有的能力也在选择器中，即使它来自旧版本字典。
    addCapabilityOptions(caps.map(c => ({ capability: c.capability })));
    tb.innerHTML = "";
    caps.forEach(c => tb.appendChild(capRow(agent, c)));
    if (!caps.length) tb.innerHTML = "<tr><td colspan=7 class=dim>无能力记录</td></tr>";
  } catch(e) { tb.innerHTML = `<tr><td colspan=7>${e.message}</td></tr>`; }
  await loadCapsMode(agent);
}

// YOLO 开关按 Agent 持久化在 securityd；只影响 tool 判权，不改动已保存的策略。
async function loadCapsMode(agent) {
  const card = $("#caps-mode-card");
  if (!card || !agent) return;
  let mode = "normal";
  try { mode = (await api(`/agents/${encodeURIComponent(agent)}/security-mode`)).mode || "normal"; }
  catch(e) { card.classList.add("dim"); return; }
  const yolo = mode === "yolo";
  card.classList.toggle("is-yolo", yolo);
  $("#caps-mode-badge").textContent = yolo ? "YOLO · 高风险" : "标准模式";
  $("#caps-mode-badge").className = "badge " + (yolo ? "risk-L4" : "risk-L1");
  $("#caps-mode-desc").textContent = yolo
    ? "工具默认放行；跳过 DLP 扫描、网络限制与审批；保留审计记录。"
    : "按每个工具的 allow / ask / deny 策略执行。";
  const btn = $("#caps-mode-toggle");
  btn.textContent = yolo ? "关闭 YOLO" : "⚠ 启用 YOLO";
  btn.className = yolo ? "ghost" : "danger";
}

const POLICY_TEXT = { allow: "allow 放行", ask: "ask 确认", deny: "deny 拒绝" };

function capRow(agent, c) {
  const tr = document.createElement("tr");
  const pClass = `pol-${c.policy}`;
  tr.innerHTML = `<td><b>${c.tool}</b></td>` +
    `<td><span class="badge ${pClass}">${POLICY_TEXT[c.policy]||c.policy}</span></td>` +
    `<td>${c.framework||"-"}</td><td class=ops></td>`;
  const ops = tr.querySelector(".ops");
  const mk = (label, policy, cls) => {
    const b = document.createElement("button"); b.textContent = label; b.className = cls||"ghost";
    b.onclick = async () => {
      try { await post(`/agents/${encodeURIComponent(agent)}/capabilities/policy`,
          { tool: c.tool, policy }); loadCaps(); }
      catch(e) { alert(e.message); }
    };
    return b;
  };
  ["allow","ask","deny"].forEach(p => {
    if (c.policy !== p) ops.appendChild(mk(POLICY_TEXT[p], p,
        p === "allow" ? "ok" : p === "deny" ? "danger" : "ghost"));
  });
  const edit = document.createElement("button");
  edit.textContent = "编辑"; edit.className = "ghost";
  edit.onclick = () => editCap(c);
  ops.appendChild(edit);
  return tr;
}

// 把某行工具策略回填进"新增/编辑"表单
function editCap(c) {
  addCapabilityOptions([{ tool: c.tool }]);
  $("#cap-name").value = c.tool;
  $("#cap-policy").value = c.policy || "allow";
  $("#cap-name").focus();
}

// 新增/更新一条工具策略
async function addCap() {
  const agent = $("#caps-agent").value;
  const res = $("#cap-add-result");
  if (!agent) { res.textContent = "请先选择 Agent"; return; }
  const tool = $("#cap-name").value.trim();
  if (!tool) { res.textContent = "请填写工具名"; return; }
  const body = { tool, policy: $("#cap-policy").value };
  try {
    await post(`/agents/${encodeURIComponent(agent)}/capabilities/add`, body);
    res.textContent = `✓ 已保存工具策略 ${tool}`; res.className = "ok";
    loadCaps();
  } catch(e) { res.textContent = "✗ " + e.message; res.className = "err"; }
}

// 加载工具目录（按框架）
async function loadMapping() {
  const box = $("#mapping-box");
  try {
    const framework = $("#caps-framework") ? $("#caps-framework").value : "";
    const m = await api("/tools" + (framework ? `?framework=${encodeURIComponent(framework)}` : ""));
    addCapabilityOptions(m.tools || []);
    const pol = m.unmapped_policy || "allow";
    const groups = { runtime: [], hermes: [] };
    (m.tools || []).forEach(t => { (groups[t.framework] ||= []).push(t); });
    const NAMES = { runtime: "runtime 工具", hermes: "hermes 工具" };
    box.innerHTML = Object.keys(groups).filter(f => groups[f].length).map(f =>
      `<div><b>${NAMES[f]||f}</b>（${groups[f].length}）</div>` +
      groups[f].map(t => `<div class=dim> · ${t.tool} → ${t.default_policy}` +
        (t.summary ? ` — ${t.summary}` : "") + `</div>`).join("")
    ).join("") +
      `<div class=dim style="margin-top:6px">未映射工具默认策略 unmapped=` +
      `<b>${pol}</b>（改用环境变量 BIANBU_SECURITY_UNMAPPED）</div>`;
  } catch(e) { box.textContent = "工具目录加载失败: " + e.message; }
}

// 能力名使用可搜索的固定高度列表，而不是原生 select/datalist。原生下拉菜单在
// 能力很多时会超出视口，datalist 又会按已选文本过滤。所有新增能力仍须先进入
// securityd/capabilities.py，WebUI 不提供绕过权威字典的自由文本入口。
function addCapabilityOptions(items) {
  (items || []).forEach(item => {
    const name = typeof item === "string" ? item : (item.tool || item.capability);
    if (!name || CAPABILITY_OPTIONS.has(name)) return;
    const fw = item.framework ? ` [${item.framework}]` : "";
    CAPABILITY_OPTIONS.set(name, { name, label: name + fw });
  });
  renderCapabilityOptions($("#cap-name")?.value || "");
}

// ── Tab: DLP / PII 策略（DLP-10）──────────────────────────
const DLP_ACTIONS = ["allow", "ask", "deny", "mask"];

async function loadDlp() {
  const agent = $("#dlp-agent").value;
  const tb = $("#dlp-matrix tbody");
  if (!agent) { tb.innerHTML = "<tr><td colspan=4 class=dim>请先选 Agent</td></tr>"; return; }
  tb.innerHTML = "<tr><td colspan=4>加载中…</td></tr>";
  try {
    const r = await api("/dlp/matrix?agent=" + encodeURIComponent(agent));
    tb.innerHTML = "";
    (r.rows || []).forEach(x => {
      const opts = DLP_ACTIONS.map(a =>
        `<option value="${a}"${a === x.action ? " selected" : ""}>${a}</option>`).join("");
      const src = x.explicit
        ? "<span style='color:#2563eb'>显式配置</span>"
        : "<span class=dim>继承/兜底</span>";
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td><b>${x.pii_type}</b></td>` +
        `<td><select data-type="${x.pii_type}" onchange="setDlpPolicy(this)">${opts}</select></td>` +
        `<td>${src}</td>` +
        `<td>${x.explicit ? `<button onclick="delDlpPolicy('${x.pii_type}')">恢复默认</button>` : ""}</td>`;
      tb.appendChild(tr);
    });
    $("#dlp-hint").textContent = `${agent}：8 类 PII 策略`;
  } catch(e) { tb.innerHTML = `<tr><td colspan=4>${e.message}</td></tr>`; }
}

async function setDlpPolicy(sel) {
  const agent = $("#dlp-agent").value;
  try {
    await post("/dlp/policy", { agent_id: agent, pii_type: sel.dataset.type,
                                action: sel.value });
    $("#dlp-hint").textContent = `✓ ${sel.dataset.type} → ${sel.value}（已生效，下次调用即应用）`;
    loadDlp();
  } catch(e) { $("#dlp-hint").textContent = "✗ " + e.message; }
}

async function delDlpPolicy(piiType) {
  const agent = $("#dlp-agent").value;
  try {
    await api("/dlp/policy", {
      method: "DELETE", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: agent, pii_type: piiType })
    });
    $("#dlp-hint").textContent = `✓ ${piiType} 已恢复兜底策略`;
    loadDlp();
  } catch(e) { $("#dlp-hint").textContent = "✗ " + e.message; }
}

async function dlpScan() {
  const text = $("#dlp-test-text").value.trim();
  const agent = $("#dlp-agent").value;
  const tb = $("#dlp-scan-result tbody");
  if (!text) return;
  tb.innerHTML = "<tr><td colspan=5>扫描中…</td></tr>";
  try {
    const r = await post("/dlp/scan", { text, agent_id: agent });
    const fs = r.findings || [];
    if (!fs.length) {
      tb.innerHTML = "<tr><td colspan=5 class=dim>未检出 PII</td></tr>";
      $("#dlp-masked").textContent = "";
      return;
    }
    tb.innerHTML = "";
    fs.forEach(f => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td>${f.pii_type}</td>` +
        `<td><code>${f.value}</code></td><td>${f.confidence}</td>` +
        `<td class=dim>${f.detector}</td><td><b>${f.action}</b></td>`;
      tb.appendChild(tr);
    });
    $("#dlp-masked").textContent = `脱敏后：${r.masked_text}`;
  } catch(e) { tb.innerHTML = `<tr><td colspan=5>${e.message}</td></tr>`; }
}

async function loadDlpStats() {
  const el = $("#dlp-stats");
  try {
    const r = await api("/dlp/stats");
    if (r.degraded) { el.textContent = "统计不可用：" + (r.reason || ""); return; }
    if (!r.total) { el.textContent = "暂无 DLP 触发记录"; return; }
    const pt = (r.by_hook_point || []).map(x => `${x.name} ${x.count}`).join(" · ");
    const dc = (r.by_decision || []).map(x => `${x.name} ${x.count}`).join(" · ");
    el.innerHTML = `共 <b>${r.total}</b> 次 DLP 干预<br>按干预点：${pt}<br>按决策：${dc}`;
  } catch(e) { el.textContent = e.message; }
}

// ── Tab 4: 审计日志 ─────────────────────────────────────
async function loadAudit() {
  const agent = $("#audit-agent").value;
  const tb = $("#audit-table tbody");
  tb.innerHTML = "<tr><td colspan=5>加载中…</td></tr>";
  try {
    const r = await api("/audit?agent=" + encodeURIComponent(agent));
    const chip = $("#audit-chain");
    chip.textContent = r.intact ? "✓ 哈希链完整" : "✗ 校验失败";
    chip.className = r.intact ? "ok" : "err";
    const recs = r.records || [];
    if (!recs.length) { tb.innerHTML = "<tr><td colspan=5 class=dim>无记录</td></tr>"; return; }
    tb.innerHTML = "";
    recs.slice(-200).forEach(x => {
      const tr = document.createElement("tr");
      const res = x.result.includes("deny")||x.result.includes("fail") ? "style='color:#dc2626'" : "";
      tr.innerHTML = `<td>${x.seq}</td><td>${x.ts.split("T").join(" ").split(".")[0]}</td>` +
        `<td>${x.op_type}</td><td>${x.target}</td><td ${res}>${x.result}</td>`;
      tb.appendChild(tr);
    });
  } catch(e) { tb.innerHTML = `<tr><td colspan=5>${e.message}</td></tr>`; }
}

// ── 启动 ────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initCapabilityPicker();
  const modeToggle = $("#caps-mode-toggle");
  if (modeToggle) modeToggle.addEventListener("click", toggleCapsMode);
  const form = $("#login-form");
  if (form) form.addEventListener("submit", login);
  tryLocalAutoAuth().then(() => startApp());
});

async function loadSyscallPolicy(){
  const aid=document.getElementById('sc-agent')?.value; const arch=document.getElementById('sc-arch')?.value||'x86_64'; if(!aid)return;
  const [p,c]=await Promise.all([fetch(`/api/agents/${encodeURIComponent(aid)}/syscall-policy?arch=${arch}`).then(r=>r.json()),fetch(`/api/syscall-catalog?arch=${arch}`).then(r=>r.json())]);
  const selected=new Set((p.agent_additions||[]));
  document.getElementById('sc-list').innerHTML=(c.syscalls||[]).map(x=>`<label style="display:block"><input type="checkbox" data-syscall="${x.name}" ${selected.has(x.name)?'checked':''}> <code>${x.name}</code> — ${x.description}</label>`).join('');
  document.getElementById('sc-status').textContent=`策略版本 ${p.policy_version}，已应用 ${p.applied_policy_version}：${p.pending_restart?'待重启生效':'已生效'}`;
}
async function saveSyscallPolicy(){
  const aid=document.getElementById('sc-agent')?.value; const arch=document.getElementById('sc-arch')?.value||'x86_64'; if(!aid)return;
  const additions=[...document.querySelectorAll('#sc-list input[data-syscall]:checked')].map(x=>x.dataset.syscall);
  const r=await fetch(`/api/agents/${encodeURIComponent(aid)}/syscall-policy`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({arch,additions})}); const p=await r.json();
  document.getElementById('sc-status').textContent=r.ok?`已保存，策略版本 ${p.policy_version}，重启 Worker 后生效`:(p.error||'保存失败');
}

async function toggleCapsMode() {
  const agent = $("#caps-agent")?.value;
  if (!agent) return;
  const yolo = $("#caps-mode-badge").textContent.includes("YOLO");
  const btn = $("#caps-mode-toggle");
  btn.disabled = true;
  try {
    await post(`/agents/${encodeURIComponent(agent)}/security-mode`, { mode: yolo ? "normal" : "yolo" });
    await loadCapsMode(agent);
  } catch(e) { alert(e.message); }
  finally { btn.disabled = false; }
}

// ── 安全权限设置（可读/可写/网络 + 执行模式）────────────
const linesToPaths = (id) => (document.getElementById(id)?.value || '')
  .split('\n').map(s => s.trim()).filter(Boolean);

// 执行模式是推导结果，不是可点的开关：声明了安全设置才需要沙箱。
function renderExecutionMode(boundary) {
  const badge = document.getElementById('perm-exec-badge');
  const desc = document.getElementById('perm-exec-desc');
  const value = boundary || {};
  const mode = value.mode || 'host';
  const reasons = value.reasons || [];
  badge.textContent = mode;
  badge.className = 'badge ' + (mode === 'sandbox' ? 'risk-L4' : 'risk-L1');
  desc.textContent = mode === 'sandbox'
    ? `已声明 ${reasons.join('、')}，需要沙箱命名空间/ seccomp 落实；运行中的 Worker 需重启才换模式。`
    : '未声明额外安全设置，在宿主上以受约束的 systemd 单元运行。';
}

async function loadPermissions() {
  const aid = document.getElementById('perm-agent')?.value;
  if (!aid) return;
  const r = await fetch(`/api/agents/${encodeURIComponent(aid)}/permissions`).then(x => x.json());
  if (r.error) { document.getElementById('perm-result').textContent = r.error; return; }
  const read = r.read || {};
  const write = r.write || {};
  document.getElementById('perm-read-include').value = (read.include || []).join('\n');
  document.getElementById('perm-read-exclude').value = (read.exclude || []).join('\n');
  document.getElementById('perm-write-include').value = (write.include || []).join('\n');
  document.getElementById('perm-write-exclude').value = (write.exclude || []).join('\n');
  document.getElementById('perm-net-mode').value = (r.network || {}).mode || 'allow_all';
  document.getElementById('perm-net-domains').value = ((r.network || {}).domains || []).join('\n');
  document.getElementById('perm-result').textContent = '';
  renderExecutionMode(r.execution_mode);
}

async function savePermissionGroup(group) {
  const aid = document.getElementById('perm-agent')?.value;
  const out = document.getElementById('perm-result');
  if (!aid) return;
  let body;
  if (group === 'network') {
    body = { mode: document.getElementById('perm-net-mode').value,
             domains: linesToPaths('perm-net-domains') };
  } else {
    body = { include: linesToPaths(`perm-${group}-include`),
             exclude: linesToPaths(`perm-${group}-exclude`) };
  }
  const r = await fetch(`/api/agents/${encodeURIComponent(aid)}/permissions/${group}`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(x => x.json());
  out.textContent = r.error ? r.error : `${group} 已保存`;
  if (!r.error) loadPermissions();
}
