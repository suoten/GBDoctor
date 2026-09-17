/* ===== GBDoctor Web UI —— 前端逻辑 ===== */

// ===== 全局状态 =====
let ws = null;
let logCollapsed = false;
let lastDeviceCount = -1;
let isQuickStarting = false;

// 12 个体检环节定义
const STAGES = [
  { key: 'register',   label: '注册' },
  { key: 'keepalive',  label: '保活' },
  { key: 'catalog',    label: '目录' },
  { key: 'invite',     label: '点播' },
  { key: 'rtp',         label: '媒体流' },
  { key: 'clock',      label: '时钟' },
  { key: 'deviceinfo', label: '设备信息' },
  { key: 'ptz',        label: '云台' },
  { key: 'alarm',      label: '报警' },
  { key: 'record',     label: '录像' },
  { key: 'voice',      label: '语音' },
  { key: 'gb2022',     label: '2022新标' },
];

// ===== 初始化 =====
document.addEventListener('DOMContentLoaded', () => {
  initWebSocket();
  loadStatus();
  // 每 5 秒刷新状态
  setInterval(loadStatus, 5000);
});

// ===== WebSocket =====
function initWebSocket() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleMessage(msg);
    } catch (e) {
      console.error('消息解析失败', e);
    }
  };
  ws.onclose = () => {
    addLog('warn', 'WebSocket 连接断开，3 秒后重连…');
    setTimeout(initWebSocket, 3000);
  };
}

function handleMessage(msg) {
  switch (msg.type) {
    case 'log':
      const level = msg.payload.level || 'info';
      addLog(level, msg.payload.text);
      break;
    case 'status':
      if (msg.payload.status === 'checking' || msg.payload.status === 'selftest' ||
          msg.payload.status === 'platform_check' || msg.payload.status === 'netdiag') {
        showProgressPanel();
      }
      if (msg.payload.status === 'idle') {
        loadStatus();
        loadReports();
      }
      if (msg.payload.status === 'session_update') {
        loadStatus();
        // 检测新设备注册
        checkNewDeviceRegistration();
      }
      break;
    case 'stage':
      updateStageProgress(msg);
      break;
    case 'done':
      onCheckDone(msg.payload);
      break;
    case 'error':
      addLog('error', msg.payload.text);
      break;
  }
}

// ===== 日志面板 =====
function addLog(level, text) {
  const content = document.getElementById('log-content');
  const entry = document.createElement('div');
  entry.className = `log-entry ${level}`;
  const now = new Date();
  const ts = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
  entry.innerHTML = `<span class="log-time">[${ts}]</span>${escapeHtml(text)}`;
  content.appendChild(entry);
  content.scrollTop = content.scrollHeight;

  // 限制日志条数
  while (content.children.length > 500) {
    content.removeChild(content.firstChild);
  }
}

function clearLog() {
  document.getElementById('log-content').innerHTML = '<div class="log-entry info">日志已清空</div>';
}

function toggleLog() {
  const panel = document.getElementById('log-panel');
  logCollapsed = !logCollapsed;
  const icon = document.getElementById('log-toggle-icon');
  const text = document.getElementById('log-toggle-text');
  if (logCollapsed) {
    icon.innerHTML = '<use href="#i-chevron-up"/>';
    text.textContent = '展开';
    panel.style.maxHeight = '44px';
  } else {
    icon.innerHTML = '<use href="#i-chevron-down"/>';
    text.textContent = '折叠';
    panel.style.maxHeight = '200px';
  }
}

// ===== Tab 切换 =====
function switchTab(tabName) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById(`tab-${tabName}`).classList.add('active');
  document.querySelector(`.nav-item[data-tab="${tabName}"]`).classList.add('active');

  if (tabName === 'reports') {
    loadReports();
  }
}

// ===== API 调用 =====
async function apiCall(url, method = 'GET', body = null) {
  const opts = { method, headers: {} };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(url, opts);
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || `HTTP ${resp.status}`);
  }
  return data;
}

async function loadStatus() {
  try {
    const data = await apiCall('/api/status');
    document.getElementById('version').textContent = `v${data.version}`;
    document.getElementById('rule-count').textContent = `规则: ${data.rule_count} 条`;

    if (data.sipsim_up) {
      document.getElementById('sipsim-status').textContent = `平台运行中 :${data.sipsim_port}`;
      document.getElementById('sipsim-status').className = 'status-badge online';
      document.getElementById('btn-start-sipsim').classList.add('hidden');
      document.getElementById('btn-stop-sipsim').classList.remove('hidden');
      document.getElementById('device-card').classList.remove('hidden');
      document.getElementById('check-config').classList.remove('hidden');
      document.getElementById('simcam-card').classList.remove('hidden');
      // 平台已启动但无设备注册时，显示排查面板
      const hasDevices = data.device_list && data.device_list.length > 0;
      const troubleshootCard = document.getElementById('troubleshoot-card');
      if (troubleshootCard) {
        troubleshootCard.classList.toggle('hidden', hasDevices);
      }
      // 端口回退后同步实际端口到输入框
      const portInput = document.getElementById('sim-port');
      if (parseInt(portInput.value) !== data.sipsim_port) {
        portInput.value = data.sipsim_port;
        portInput.style.color = '#fab387';
        addLog('info', `SIP 端口已自动切换为 ${data.sipsim_port}（原端口被占用）`);
      }
      // 更新模拟设备按钮状态
      if (data.simcam_running) {
        document.getElementById('btn-start-cam').classList.add('hidden');
        document.getElementById('btn-stop-cam').classList.remove('hidden');
        document.getElementById('simcam-actions').classList.remove('hidden');
      } else {
        document.getElementById('btn-start-cam').classList.remove('hidden');
        document.getElementById('btn-stop-cam').classList.add('hidden');
        document.getElementById('simcam-actions').classList.add('hidden');
      }
    } else {
      document.getElementById('sipsim-status').textContent = '平台未启动';
      document.getElementById('sipsim-status').className = 'status-badge offline';
      document.getElementById('btn-start-sipsim').classList.remove('hidden');
      document.getElementById('btn-stop-sipsim').classList.add('hidden');
      document.getElementById('device-card').classList.add('hidden');
      document.getElementById('check-config').classList.add('hidden');
      document.getElementById('simcam-card').classList.add('hidden');
      const tc = document.getElementById('troubleshoot-card');
      if (tc) tc.classList.add('hidden');
    }

    // 渲染设备列表
    const deviceList = document.getElementById('device-list');
    if (data.device_list && data.device_list.length > 0) {
      // 首次加载时初始化 lastDeviceCount，避免误触发 Toast
      if (lastDeviceCount === -1) {
        lastDeviceCount = data.device_list.length;
      }
      deviceList.innerHTML = data.device_list.map(d => `
        <div class="device-item">
          <div class="device-info">
            <span class="device-id">${d.device_id}</span>
            <span class="device-meta">算法=${d.algorithm} | 心跳=${d.keepalive_count} | 注册=${d.register_count}</span>
          </div>
          <div class="device-status">
            <span class="status-dot"></span>
            <button class="btn btn-primary" onclick="startCheck('${d.device_id}')">
              <svg width="16" height="16"><use href="#i-stethoscope"/></svg> 体检
            </button>
          </div>
        </div>
      `).join('');
    } else {
      deviceList.innerHTML = '<p class="empty-hint">暂无设备注册。请在摄像头上配置 SIP 服务器地址指向本机，或点击「注册模拟设备」用虚拟设备测试</p>';
    }

    // 更新向导步骤状态
    updateGuideSteps(data);
  } catch (e) {
    console.error('状态获取失败', e);
  }
}

// ===== SIP 仿真控制 =====
async function startSipSim() {
  const body = {
    host: document.getElementById('sim-host').value,
    port: parseInt(document.getElementById('sim-port').value),
    server_id: document.getElementById('sim-server-id').value,
    password: document.getElementById('sim-password').value,
    algorithm: document.getElementById('sim-algorithm').value,
    use_tcp: document.getElementById('sim-tcp').checked,
  };
  try {
    addLog('info', '正在启动模拟上级平台...');
    const data = await apiCall('/api/sipsim/start', 'POST', body);
    // 同步实际端口（可能因占用而回退）
    document.getElementById('sim-port').value = data.port;
    addLog('success', `平台已启动，监听端口 ${data.port}`);
    // 显示设备配置指引
    const hostIP = body.host === '0.0.0.0' ? '本机IP' : body.host;
    addLog('info', `在摄像头上配置 SIP 服务器地址: ${hostIP} 端口: ${data.port}，服务器编码: ${body.server_id}`);
    loadStatus();
  } catch (e) {
    addLog('error', e.message);
  }
}

async function stopSipSim() {
  try {
    await apiCall('/api/sipsim/stop', 'POST');
    addLog('info', '模拟平台已停止');
    // 同时隐藏模拟设备面板
    document.getElementById('simcam-card').classList.add('hidden');
    document.getElementById('simcam-actions').classList.add('hidden');
    document.getElementById('btn-start-cam').classList.remove('hidden');
    document.getElementById('btn-stop-cam').classList.add('hidden');
    loadStatus();
  } catch (e) {
    addLog('error', '停止失败: ' + e.message);
  }
}

// ===== 模拟设备控制 =====
async function startSimCam() {
  const body = {
    device_id: document.getElementById('cam-device-id').value,
    password: document.getElementById('cam-password').value,
    auto_keepalive: document.getElementById('cam-auto-keepalive').checked,
  };
  try {
    addLog('info', `正在注册模拟设备 ${body.device_id}…`);
    const data = await apiCall('/api/simcam/start', 'POST', body);
    addLog('success', `模拟设备已注册成功（算法=${data.algorithm}）`);
    document.getElementById('btn-start-cam').classList.add('hidden');
    document.getElementById('btn-stop-cam').classList.remove('hidden');
    document.getElementById('simcam-actions').classList.remove('hidden');
    loadStatus();
  } catch (e) {
    addLog('error', '注册失败: ' + e.message);
  }
}

async function stopSimCam() {
  const deviceID = document.getElementById('cam-device-id').value;
  try {
    await apiCall('/api/simcam/stop', 'POST', { device_id: deviceID });
    addLog('info', '模拟设备已停止');
    document.getElementById('btn-start-cam').classList.remove('hidden');
    document.getElementById('btn-stop-cam').classList.add('hidden');
    document.getElementById('simcam-actions').classList.add('hidden');
    loadStatus();
  } catch (e) {
    addLog('error', '停止失败: ' + e.message);
  }
}

async function simCamKeepalive() {
  const deviceID = document.getElementById('cam-device-id').value;
  try {
    const data = await apiCall('/api/simcam/keepalive', 'POST', { device_id: deviceID });
    addLog('success', `心跳已发送 (SN=${data.sn}, ${data.code})`);
    loadStatus();
  } catch (e) {
    addLog('error', '心跳失败: ' + e.message);
  }
}

async function simCamCatalog() {
  const deviceID = document.getElementById('cam-device-id').value;
  try {
    addLog('info', '正在发送目录应答…');
    await apiCall('/api/simcam/catalog', 'POST', { device_id: deviceID });
    addLog('success', '目录应答已发送');
    setTimeout(loadStatus, 500);
  } catch (e) {
    addLog('error', '发送失败: ' + e.message);
  }
}

async function simCamDeviceInfo() {
  const deviceID = document.getElementById('cam-device-id').value;
  try {
    addLog('info', '正在发送设备信息…');
    await apiCall('/api/simcam/deviceinfo', 'POST', { device_id: deviceID });
    addLog('success', '设备信息已发送');
  } catch (e) {
    addLog('error', '发送失败: ' + e.message);
  }
}

async function simCamRecordInfo() {
  const deviceID = document.getElementById('cam-device-id').value;
  try {
    addLog('info', '正在发送录像应答…');
    await apiCall('/api/simcam/recordinfo', 'POST', { device_id: deviceID });
    addLog('success', '录像应答已发送');
  } catch (e) {
    addLog('error', '发送失败: ' + e.message);
  }
}

async function simCamAlarm() {
  const deviceID = document.getElementById('cam-device-id').value;
  try {
    addLog('info', '正在发送报警通知…');
    await apiCall('/api/simcam/alarm', 'POST', { device_id: deviceID });
    addLog('success', '报警通知已发送');
  } catch (e) {
    addLog('error', '发送失败: ' + e.message);
  }
}

// ===== 体检 =====
async function startCheck(deviceID) {
  const body = {
    device_id: deviceID,
    skip_catalog:   document.getElementById('skip-catalog').checked,
    skip_invite:    document.getElementById('skip-invite').checked,
    skip_deviceinfo: document.getElementById('skip-deviceinfo').checked,
    skip_ptz:       document.getElementById('skip-ptz').checked,
    skip_alarm:     document.getElementById('skip-alarm').checked,
    skip_record:    document.getElementById('skip-record').checked,
    skip_voice:     document.getElementById('skip-voice').checked,
    skip_gb2022:    document.getElementById('skip-gb2022').checked,
  };
  try {
    addLog('info', `开始对设备 ${deviceID} 执行全链路体检…`);
    showProgressPanel();
    initStageProgress();
    await apiCall('/api/check', 'POST', body);
  } catch (e) {
    addLog('error', '体检启动失败: ' + e.message);
  }
}

async function runSelftest() {
  try {
    addLog('info', '开始本机回环自检…');
    showProgressPanel();
    initStageProgress();
    await apiCall('/api/selftest', 'POST');
  } catch (e) {
    addLog('error', '自检启动失败: ' + e.message);
  }
}

async function runPlatform() {
  const body = {
    server_addr: document.getElementById('plat-server-addr').value,
    server_id:  document.getElementById('plat-server-id').value,
    device_id:  document.getElementById('plat-device-id').value,
    password:   document.getElementById('plat-password').value,
    transport:  document.getElementById('plat-transport').value,
    timeout:    document.getElementById('plat-timeout').value,
  };
  if (!body.server_addr) {
    addLog('error', '请填写平台地址');
    return;
  }
  try {
    addLog('info', `开始平台侧体检: ${body.server_addr}`);
    await apiCall('/api/platform', 'POST', body);
  } catch (e) {
    addLog('error', '启动失败: ' + e.message);
  }
}

// ===== 注册排查 =====
async function runTroubleshoot() {
  const resultDiv = document.getElementById('troubleshoot-result');
  resultDiv.classList.remove('hidden');
  resultDiv.innerHTML = '<p style="color:var(--gray)">正在获取排查信息…</p>';
  try {
    const data = await apiCall('/api/troubleshoot');
    const tips = data.tips || [];
    const tipsHtml = tips.map(t => {
      if (t === '') return '<hr style="border:0;border-top:1px solid var(--gray-light);margin:8px 0">';
      return `<div class="log-entry info" style="padding:4px 0"><span class="log-time" style="color:var(--primary)">●</span>${escapeHtml(t)}</div>`;
    }).join('');
    resultDiv.innerHTML = `<div class="troubleshoot-tips">${tipsHtml}</div>`;
    tips.forEach(t => { if (t) addLog('info', t); });
  } catch (e) {
    resultDiv.innerHTML = `<p style="color:var(--danger)">获取失败: ${escapeHtml(e.message)}</p>`;
  }
}

async function runNetdiag() {
  const body = {
    target: document.getElementById('netdiag-target').value,
    port:   parseInt(document.getElementById('netdiag-port').value),
  };
  if (!body.target) {
    addLog('error', '请填写目标 IP');
    return;
  }
  try {
    addLog('info', `开始网络诊断: ${body.target}:${body.port}`);
    await apiCall('/api/netdiag', 'POST', body);
  } catch (e) {
    addLog('error', '启动失败: ' + e.message);
  }
}

// ===== 内置抓包 =====
async function refreshCaptureStats() {
  try {
    const data = await apiCall('/api/status');
    if (data.sipsim_up && data.capture_count !== undefined) {
      document.getElementById('capture-stats').style.display = 'flex';
      document.getElementById('capture-count').textContent = data.capture_count;
      document.getElementById('capture-in').textContent = data.capture_in;
      document.getElementById('capture-out').textContent = data.capture_out;
      addLog('info', `捕获统计: ${data.capture_count} 个报文 (入站 ${data.capture_in}, 出站 ${data.capture_out})`);
    } else {
      document.getElementById('capture-stats').style.display = 'none';
      addLog('warn', '模拟平台未启动，无捕获数据');
    }
  } catch (e) {
    addLog('error', '获取捕获统计失败: ' + e.message);
  }
}

function downloadLivePcap() {
  const a = document.createElement('a');
  a.href = '/api/pcap/live';
  a.download = `gbdoctor-capture-${Date.now()}.pcap`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  addLog('info', '正在下载 pcap 文件...');
}

// ===== pcap 上传 =====
async function uploadPcap(event) {
  const file = event.target.files[0];
  if (!file) return;

  addLog('info', `上传文件: ${file.name} (${file.size} 字节)`);

  const formData = new FormData();
  formData.append('file', file);

  try {
    const resp = await fetch('/api/pcap', {
      method: 'POST',
      body: formData,
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || '上传失败');

    addLog('success', `解析成功: ${data.packet_count} 个报文`);
    if (data.issues && data.issues.length > 0) {
      data.issues.forEach(iss => {
        addLog('warn', `[${iss.severity}] ${iss.title}: ${iss.explain}`);
      });
    } else {
      addLog('success', '未发现问题');
    }
  } catch (e) {
    addLog('error', 'pcap 分析失败: ' + e.message);
  }
}

// ===== 进度面板 =====
function showProgressPanel() {
  document.getElementById('progress-panel').classList.remove('hidden');
}

function initStageProgress() {
  const container = document.getElementById('stage-progress');
  container.innerHTML = STAGES.map(s => `
    <div class="stage-item pending" data-stage="${s.key}">
      <div class="stage-icon-wrap">
        <svg><use href="#i-circle"/></svg>
      </div>
      <span class="stage-label">${s.label}</span>
      <span class="stage-status">等待</span>
    </div>
  `).join('');
}

function updateStageProgress(msg) {
  const stageKey = msg.stage || (msg.payload && msg.payload.stage);
  const item = document.querySelector(`.stage-item[data-stage="${stageKey}"]`);
  if (!item) return;

  item.classList.remove('pending');

  const status = msg.payload.status;
  const iconWrap = item.querySelector('.stage-icon-wrap');
  if (status === 'pass') {
    item.classList.add('pass');
    iconWrap.innerHTML = '<svg><use href="#i-check"/></svg>';
    item.querySelector('.stage-status').textContent = '通过';
  } else if (status === 'fail') {
    item.classList.add('fail');
    iconWrap.innerHTML = '<svg><use href="#i-x"/></svg>';
    item.querySelector('.stage-status').textContent = '失败';
  } else if (status === 'skipped') {
    item.classList.add('skip');
    iconWrap.innerHTML = '<svg><use href="#i-circle"/></svg>';
    item.querySelector('.stage-status').textContent = '跳过';
  }

  // 显示环节事实
  if (msg.payload.facts && msg.payload.facts.length > 0) {
    addLog('info', `[${stageKey}] ${msg.payload.facts.join('; ')}`);
  }
}

function onCheckDone(payload) {
  const scoreEl = document.getElementById('progress-score');
  scoreEl.textContent = `${payload.score}/100`;
  if (payload.score >= 80) {
    scoreEl.className = 'progress-score pass';
  } else if (payload.score >= 60) {
    scoreEl.className = 'progress-score warn';
  } else {
    scoreEl.className = 'progress-score fail';
  }

  addLog('success', `体检完成: 得分 ${payload.score}/100, 报告 ID: ${payload.report_id}`);

  // 提供查看报告链接
  const content = document.getElementById('log-content');
  const entry = document.createElement('div');
  entry.className = 'log-entry info';
  entry.innerHTML = `<span class="log-time">[完成]</span><a href="/api/report/${payload.report_id}" target="_blank" style="color:#89b4fa"><svg width="14" height="14" style="display:inline;vertical-align:-2px"><use href="#i-file"/></svg> 查看完整报告</a>`;
  content.appendChild(entry);
  content.scrollTop = content.scrollHeight;

  // 自动弹出报告摘要
  showReportModal(payload);
  // 重置一键体检状态
  isQuickStarting = false;
}

// ===== 历史报告 =====
async function loadReports() {
  try {
    const data = await apiCall('/api/reports');
    const list = document.getElementById('report-list');
    if (!data || data.length === 0) {
      list.innerHTML = '<p class="empty-hint">暂无历史报告</p>';
      return;
    }
    list.innerHTML = data.map(r => {
      const cls = r.score >= 80 ? 'pass' : (r.score >= 60 ? 'warn' : 'fail');
      return `
        <div class="report-item" onclick="window.open('/api/report/${r.report_id}', '_blank')">
          <div class="report-info">
            <span class="report-id">${r.report_id}</span>
            <span class="report-meta">设备: ${r.device_id} | ${r.start_time} | 证据: ${r.evidence_count} 条 | 问题: ${r.issue_count} 个</span>
          </div>
          <div class="report-score ${cls}">${r.score}</div>
        </div>
      `;
    }).join('');
  } catch (e) {
    console.error('报告列表加载失败', e);
  }
}

// ===== 拖拽上传 =====
document.addEventListener('DOMContentLoaded', () => {
  const uploadArea = document.getElementById('upload-area');
  if (uploadArea) {
    uploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadArea.classList.add('dragover');
    });
    uploadArea.addEventListener('dragleave', () => {
      uploadArea.classList.remove('dragover');
    });
    uploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('dragover');
      const file = e.dataTransfer.files[0];
      if (file) {
        const input = document.getElementById('pcap-file');
        const dt = new DataTransfer();
        dt.items.add(file);
        input.files = dt.files;
        input.dispatchEvent(new Event('change'));
      }
    });
  }
});

// ===== 工具函数 =====
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ===== 向导步骤更新 =====
function updateGuideSteps(data) {
  const step1 = document.getElementById('guide-step-1');
  const step2 = document.getElementById('guide-step-2');
  const step3 = document.getElementById('guide-step-3');
  if (!step1) return;

  // 重置
  [step1, step2, step3].forEach(s => s.classList.remove('active', 'done'));

  if (!data.sipsim_up) {
    step1.classList.add('active');
  } else {
    step1.classList.add('done');
    if (data.device_list && data.device_list.length > 0) {
      step2.classList.add('done');
      step3.classList.add('active');
    } else {
      step2.classList.add('active');
    }
  }

  // 更新智能状态提示
  updateSmartHint(data);
}

// ===== 智能状态提示 =====
function updateSmartHint(data) {
  const hintCard = document.getElementById('smart-hint-card');
  const hintBody = document.getElementById('smart-hint-body');
  if (!hintCard || !hintBody) return;

  if (!data.sipsim_up) {
    hintCard.classList.add('hidden');
    return;
  }

  hintCard.classList.remove('hidden');
  const hasDevices = data.device_list && data.device_list.length > 0;

  if (!hasDevices) {
    hintBody.className = 'smart-hint warn';
    hintBody.innerHTML = `
      <svg width="20" height="20"><use href="#i-info"/></svg>
      <div>
        <strong>平台已启动，等待设备注册</strong><br>
        在摄像头上配置 SIP 服务器地址指向本机（端口 ${data.sipsim_port}），或点击「注册模拟设备」用虚拟设备测试
      </div>
    `;
  } else {
    hintCard.classList.add('hidden');
  }
}

// ===== 一键体检 =====
async function quickStart() {
  if (isQuickStarting) {
    addLog('warn', '体检正在进行中，请稍候...');
    return;
  }
  isQuickStarting = true;
  const btn = document.getElementById('btn-quickstart');
  btn.disabled = true;
  btn.innerHTML = '<svg width="20" height="20"><use href="#i-refresh"/></svg> 体检中...';

  try {
    addLog('info', '一键体检启动...');
    showProgressPanel();
    initStageProgress();
    await apiCall('/api/quickstart', 'POST');
  } catch (e) {
    addLog('error', '一键体检启动失败: ' + e.message);
    isQuickStarting = false;
    btn.disabled = false;
    btn.innerHTML = '<svg width="20" height="20"><use href="#i-rocket"/></svg> 一键体检';
  }
}

// ===== 报告弹窗 =====
function showReportModal(payload) {
  const modal = document.getElementById('report-modal');
  const body = document.getElementById('report-modal-body');

  const scoreClass = payload.score >= 80 ? 'pass' : (payload.score >= 60 ? 'warn' : 'fail');
  const scoreLabel = payload.score >= 80 ? '体检通过' : (payload.score >= 60 ? '存在风险' : '不通过');

  // 从进度面板提取环节结果
  const stages = [];
  document.querySelectorAll('.stage-item').forEach(item => {
    const label = item.querySelector('.stage-label')?.textContent || '';
    const status = item.querySelector('.stage-status')?.textContent || '';
    const cls = item.classList.contains('pass') ? 'pass' : (item.classList.contains('fail') ? 'fail' : 'skip');
    stages.push({ label, cls, status });
  });

  const stagesHtml = stages.map(s =>
    `<span class="report-stage ${s.cls}">${s.label}: ${s.status}</span>`
  ).join('');

  body.innerHTML = `
    <div class="report-summary">
      <div class="score-big ${scoreClass}">${payload.score}<span style="font-size:24px;color:var(--gray)">/100</span></div>
      <div class="score-label">${scoreLabel}（共 ${payload.issues || 0} 个问题）</div>
      <div class="report-stages">${stagesHtml}</div>
      <div class="report-actions">
        <a href="/api/report/${payload.report_id}" target="_blank" class="btn btn-primary">
          <svg width="16" height="16"><use href="#i-file"/></svg> 查看完整报告
        </a>
        <button class="btn btn-secondary" onclick="closeReportModal()">
          关闭
        </button>
      </div>
    </div>
  `;
  modal.classList.remove('hidden');
}

function closeReportModal(event) {
  if (event && event.target !== event.currentTarget) return;
  document.getElementById('report-modal').classList.add('hidden');
  // 恢复一键体检按钮
  const btn = document.getElementById('btn-quickstart');
  if (btn) {
    btn.disabled = false;
    btn.innerHTML = '<svg width="20" height="20"><use href="#i-rocket"/></svg> 一键体检';
  }
}

// ===== Toast 通知 =====
function showToast(text, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  const icon = type === 'success' ? 'i-check' : (type === 'warn' ? 'i-info' : 'i-x');
  toast.innerHTML = `
    <svg width="20" height="20" style="color:var(--${type === 'success' ? 'success' : (type === 'warn' ? 'warn' : 'danger')})"><use href="#${icon}"/></svg>
    <span>${escapeHtml(text)}</span>
  `;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ===== 设备注册检测 =====
async function checkNewDeviceRegistration() {
  try {
    const data = await apiCall('/api/status');
    const currentCount = data.device_list ? data.device_list.length : 0;
    if (currentCount > lastDeviceCount && lastDeviceCount >= 0) {
      const newDev = data.device_list[currentCount - 1];
      if (newDev) {
        showToast(`设备 ${newDev.device_id} 已注册成功！点击「体检」开始诊断`);
      }
    }
    lastDeviceCount = currentCount;
  } catch (e) {
    // ignore
  }
}
