import { apiGet, apiPost } from "./api.js";

const state = {
  targets: [],
  terminalText: "",
  resultsByCommand: {},
  sshSession: null,
  unprotectedSession: null,
  latestResult: null
};

const views = {
  overview: "概览",
  connections: "连接",
  unprotected: "无防护 POC",
  protected: "有防护 SSH / 数据采集",
  compare: "性能结果对比"
};

const phaseLabels = {
  idle: "待机",
  starting: "启动中",
  communicating: "通信中",
  recovering: "密钥恢复中",
  "key-recovered": "密钥已恢复",
  eavesdropping: "Eve 已启用",
  "message-recovered": "窃听成功",
  "recover-failed": "恢复失败",
  "start-failed": "启动失败",
  stopped: "已停止"
};

const commandLabels = {
  runProtectionTest: "防护功能测试",
  runPerformanceTest: "完整性能测试",
  runPerfCoremark: "CoreMark 基准测试",
  runPerfProc: "进程上下文切换压力测试",
  runPerfThread: "线程上下文切换压力测试",
  runPerfConcurrent: "Hackbench 并发调度压力测试"
};

const chartColors = {
  unprotected: "#2b78aa",
  protected: "#dd7416",
  missNoProtection: "#e84b40",
  hitNoProtection: "#ef9289",
  missProtected: "#31c976",
  hitProtected: "#82d9a4",
  partition: "#2b78aa"
};

const fixedReportData = {
  cacheLatency: {
    type: "line-area",
    selector: "#cacheLatencyChart",
    unit: "Clock Cycles",
    categories: ["1st", "2nd", "3rd", "4th"],
    series: [
      { name: "Miss 无防护", color: chartColors.missNoProtection, values: [105, 70, 60, 59] },
      { name: "Hit 无防护", color: chartColors.hitNoProtection, values: [12, 12, 0, 12] }
    ]
  },
  partition: {
    type: "zero-delta",
    selector: "#coremarkChart",
    unit: "cyc",
    categories: ["8", "16", "32"],
    fallbackValues: [0, 0, 0]
  },
  processSwitch: {
    type: "combo",
    selector: "#processSwitchChart",
    unit: "us/switch",
    categories: ["100", "1000", "100000"],
    baseline: [846.59, 815.32, 826.93]
  },
  threadSwitch: {
    type: "combo",
    selector: "#threadSwitchChart",
    unit: "us/switch",
    categories: ["100", "1000", "200000"],
    baseline: [985.34, 930.22, 898.43]
  },
  hackbench: {
    type: "combo",
    selector: "#hackbenchChart",
    unit: "us/switch",
    categories: ["10", "100", "1000", "10000"],
    baseline: [1454.6, 873.12, 825.73, 821.6]
  }
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(node.dataset.timer);
  node.dataset.timer = setTimeout(() => node.classList.remove("show"), 1800);
}

async function safeAction(action) {
  try {
    return await action();
  } catch (error) {
    toast(error.message);
    return null;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function stripAnsi(value) {
  return String(value ?? "")
    .replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
}

function collectResultOutputs(preferredResult = null) {
  const outputs = [];
  const seen = new Set();
  const push = (result) => {
    const output = stripAnsi(result?.output || "");
    if (!output || seen.has(output)) return;
    seen.add(output);
    outputs.push(output);
  };

  push(preferredResult);
  push(state.latestResult);
  Object.values(state.resultsByCommand || {}).forEach(push);
  return outputs.join("\n");
}

function parseSignedInt(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function parsePartitionSummaries(output) {
  const text = stripAnsi(output);
  const summaries = [];
  const blockPattern = /====[^\n]*EVICT_PAGES=(\d+)[^\n]*====([\s\S]*?)(?=\n====[^\n]*EVICT_PAGES=|\s*$)/g;
  let match;

  while ((match = blockPattern.exec(text))) {
    const block = match[2];
    const deltaAvg = block.match(/SUMMARY:\s*delta_avg\(mean\/median\)=(-?\d+)\/(-?\d+)\s*cyc/);
    const deltaP50 = block.match(/SUMMARY:\s*delta_p50\(mean\/median\/min\/max\)=(-?\d+)\/(-?\d+)\/(-?\d+)\/(-?\d+)\s*cyc/);
    const deltaP90 = block.match(/SUMMARY:\s*delta_p90\(mean\/median\/min\/max\)=(-?\d+)\/(-?\d+)\/(-?\d+)\/(-?\d+)\s*cyc/);
    const sid = block.match(/SUMMARY:\s*sid_not_separated_runs=(\d+)\/(\d+),\s*total_timeout\(base\/attack\)=(\d+)\/(\d+)/);
    const sidPair = block.match(/SID\(parent\/child\)=(\d+)\/(\d+)/) || block.match(/SID=(\d+)\/(\d+)/);
    const verdict = block.match(/VERDICT:\s*([^\n]+)/);

    summaries.push({
      evictPages: parseSignedInt(match[1]),
      deltaAvg: deltaAvg ? { mean: parseSignedInt(deltaAvg[1]), median: parseSignedInt(deltaAvg[2]) } : null,
      deltaP50: deltaP50
        ? {
            mean: parseSignedInt(deltaP50[1]),
            median: parseSignedInt(deltaP50[2]),
            min: parseSignedInt(deltaP50[3]),
            max: parseSignedInt(deltaP50[4])
          }
        : null,
      deltaP90: deltaP90
        ? {
            mean: parseSignedInt(deltaP90[1]),
            median: parseSignedInt(deltaP90[2]),
            min: parseSignedInt(deltaP90[3]),
            max: parseSignedInt(deltaP90[4])
          }
        : null,
      sidNotSeparatedRuns: sid ? parseSignedInt(sid[1]) : 0,
      sidTotalRuns: sid ? parseSignedInt(sid[2]) : 0,
      sidParent: sidPair ? parseSignedInt(sidPair[1]) : null,
      sidChild: sidPair ? parseSignedInt(sidPair[2]) : null,
      timeoutBase: sid ? parseSignedInt(sid[3]) : 0,
      timeoutAttack: sid ? parseSignedInt(sid[4]) : 0,
      verdict: verdict ? verdict[1].trim() : ""
    });
  }

  return summaries.sort((a, b) => a.evictPages - b.evictPages);
}

function parseSwitchResults(output, type) {
  const patterns = {
    process: /ctxswitch_proc\s+iterations=(\d+)\s+total=([0-9.]+)\s*ms\s+per_switch=([0-9.]+)\s*ns/g,
    thread: /ctxswitch_thread\s+iterations=(\d+)\s+total=([0-9.]+)\s*ms\s+per_switch=([0-9.]+)\s*ns/g,
    hackbench: /hackbench_like\s+process\s+groups=(\d+)\s+loops=(\d+)\s+total=([0-9.]+)\s*ms\s+per_switch=([0-9.]+)\s*ns/g
  };
  const pattern = patterns[type];
  const results = new Map();
  let match;

  while ((match = pattern.exec(stripAnsi(output)))) {
    const key = type === "hackbench" ? match[2] : match[1];
    const totalMs = Number.parseFloat(type === "hackbench" ? match[3] : match[2]);
    const perSwitchNs = Number.parseFloat(type === "hackbench" ? match[4] : match[3]);
    results.set(key, {
      key,
      totalMs,
      perSwitchNs,
      perSwitchUs: perSwitchNs / 1000
    });
  }

  return results;
}

function parseCoremarkResults(output) {
  const text = stripAnsi(output);
  const results = [];
  const seen = new Set();
  const patterns = [
    /Iterations\/Sec\s*[:=]\s*([0-9.]+)/gi,
    /CoreMark\s+1(?:\.0)?\s*:\s*([0-9.]+)/gi,
    /CoreMark\s*[:=]\s*([0-9.]+)/gi
  ];

  patterns.forEach((pattern) => {
    let match;
    while ((match = pattern.exec(text))) {
      const iterationsPerSec = Number.parseFloat(match[1]);
      if (!Number.isFinite(iterationsPerSec)) continue;
      const key = iterationsPerSec.toFixed(6);
      if (seen.has(key)) continue;
      seen.add(key);
      results.push({ iterationsPerSec });
    }
  });

  return results;
}

function parseCollectedMeasurements(preferredResult = null) {
  const output = collectResultOutputs(preferredResult);
  return {
    partition: parsePartitionSummaries(output),
    coremark: parseCoremarkResults(output),
    process: parseSwitchResults(output, "process"),
    thread: parseSwitchResults(output, "thread"),
    hackbench: parseSwitchResults(output, "hackbench")
  };
}

function valuesFromMap(resultMap, categories) {
  return categories.map((category) => resultMap.get(category)?.perSwitchUs ?? null);
}

function realValuesFromMap(resultMap, categories) {
  return categories.map((category) => resultMap.get(category)?.perSwitchUs ?? null);
}

function formatPercent(value) {
  if (!Number.isFinite(value)) return "--";
  const abs = Math.abs(value);
  const digits = abs >= 10 ? 1 : 2;
  return `${value.toFixed(digits).replace(/\.?0+$/, "")}%`;
}

function formatOverheadRange(baseline, realValues) {
  const values = realValues
    .map((value, index) => {
      if (!Number.isFinite(value) || !Number.isFinite(baseline[index]) || baseline[index] === 0) return null;
      return ((value - baseline[index]) / baseline[index]) * 100;
    })
    .filter((value) => Number.isFinite(value));

  if (!values.length) return "等待采集";
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (Math.abs(max - min) < 0.01) return formatPercent(max);
  return `${formatPercent(min)} - ${formatPercent(max)}`;
}

function buildReportCharts(parsed = parseCollectedMeasurements()) {
  const partitionByEvict = new Map(parsed.partition.map((item) => [String(item.evictPages), item]));
  const partitionP50Values = fixedReportData.partition.categories.map((category) => {
    const summary = partitionByEvict.get(category);
    return summary?.deltaP50 ? summary.deltaP50.median : null;
  });
  const partitionP90Values = fixedReportData.partition.categories.map((category) => {
    const summary = partitionByEvict.get(category);
    return summary?.deltaP90 ? summary.deltaP90.median : null;
  });
  const partitionSeries = parsed.partition.length
    ? [
        { name: "delta_p50 median", color: chartColors.partition, values: partitionP50Values },
        { name: "delta_p90 median", color: chartColors.protected, values: partitionP90Values }
      ]
    : [];
  const processSeries = [
    { name: "无防护", color: chartColors.unprotected, values: fixedReportData.processSwitch.baseline }
  ];
  const threadSeries = [
    { name: "无防护", color: chartColors.unprotected, values: fixedReportData.threadSwitch.baseline }
  ];
  const hackbenchSeries = [
    { name: "无防护", color: chartColors.unprotected, values: fixedReportData.hackbench.baseline }
  ];

  if (parsed.process.size) {
    processSeries.push({
      name: "有防护",
      color: chartColors.protected,
      values: valuesFromMap(parsed.process, fixedReportData.processSwitch.categories)
    });
  }
  if (parsed.thread.size) {
    threadSeries.push({
      name: "有防护",
      color: chartColors.protected,
      values: valuesFromMap(parsed.thread, fixedReportData.threadSwitch.categories)
    });
  }
  if (parsed.hackbench.size) {
    hackbenchSeries.push({
      name: "有防护",
      color: chartColors.protected,
      values: valuesFromMap(parsed.hackbench, fixedReportData.hackbench.categories)
    });
  }

  return {
    cacheLatency: fixedReportData.cacheLatency,
    partition: {
      type: fixedReportData.partition.type,
      selector: fixedReportData.partition.selector,
      unit: fixedReportData.partition.unit,
      categories: fixedReportData.partition.categories,
      series: partitionSeries
    },
    processSwitch: {
      type: fixedReportData.processSwitch.type,
      selector: fixedReportData.processSwitch.selector,
      unit: fixedReportData.processSwitch.unit,
      categories: fixedReportData.processSwitch.categories,
      series: processSeries
    },
    threadSwitch: {
      type: fixedReportData.threadSwitch.type,
      selector: fixedReportData.threadSwitch.selector,
      unit: fixedReportData.threadSwitch.unit,
      categories: fixedReportData.threadSwitch.categories,
      series: threadSeries
    },
    hackbench: {
      type: fixedReportData.hackbench.type,
      selector: fixedReportData.hackbench.selector,
      unit: fixedReportData.hackbench.unit,
      categories: fixedReportData.hackbench.categories,
      series: hackbenchSeries
    }
  };
}

function updateReportBadges(parsed = parseCollectedMeasurements()) {
  const sidBadRuns = parsed.partition.reduce((sum, item) => sum + item.sidNotSeparatedRuns, 0);
  const sidTotalRuns = parsed.partition.reduce((sum, item) => sum + item.sidTotalRuns, 0);
  const timeoutTotal = parsed.partition.reduce((sum, item) => sum + item.timeoutBase + item.timeoutAttack, 0);
  const hasPartition = parsed.partition.length > 0;
  const partitionOk = hasPartition && sidBadRuns === 0 && timeoutTotal === 0;
  const sidPairs = [...new Set(parsed.partition
    .filter((item) => item.sidParent !== null && item.sidChild !== null)
    .map((item) => `${item.sidParent}/${item.sidChild}`))];

  setBadge(
    $("#partitionOverheadBadge"),
    !hasPartition ? "muted" : partitionOk ? "good" : "bad",
    !hasPartition
      ? "等待采集"
      : partitionOk
        ? `SID ${sidPairs.join(", ") || "分离"} 正常`
        : "SID分离异常"
  );
  setBadge(
    $("#processOverheadBadge"),
    parsed.process.size ? "idle" : "muted",
    formatOverheadRange(fixedReportData.processSwitch.baseline, realValuesFromMap(parsed.process, fixedReportData.processSwitch.categories))
  );
  setBadge(
    $("#threadOverheadBadge"),
    parsed.thread.size ? "idle" : "muted",
    formatOverheadRange(fixedReportData.threadSwitch.baseline, realValuesFromMap(parsed.thread, fixedReportData.threadSwitch.categories))
  );
  setBadge(
    $("#hackbenchOverheadBadge"),
    parsed.hackbench.size ? "idle" : "muted",
    formatOverheadRange(fixedReportData.hackbench.baseline, realValuesFromMap(parsed.hackbench, fixedReportData.hackbench.categories))
  );
}

function summarizeLatestResult(result) {
  const output = stripAnsi(result?.output || "");
  if (!output) return "暂无采集数据";

  const lines = [];
  const partitions = parsePartitionSummaries(output);
  if (partitions.length) {
    lines.push("防护有效性 SUMMARY");
    partitions.forEach((item) => {
      const deltaAvg = item.deltaAvg ? `${item.deltaAvg.mean}/${item.deltaAvg.median}` : "--";
      const deltaP50 = item.deltaP50
        ? `${item.deltaP50.mean}/${item.deltaP50.median}/${item.deltaP50.min}/${item.deltaP50.max}`
        : "--";
      const deltaP90 = item.deltaP90
        ? `${item.deltaP90.mean}/${item.deltaP90.median}/${item.deltaP90.min}/${item.deltaP90.max}`
        : "--";
      lines.push(
        `EVICT_PAGES=${item.evictPages}: delta_avg mean/median=${deltaAvg} cyc; ` +
          `delta_p50 mean/median/min/max=${deltaP50} cyc; ` +
          `delta_p90 mean/median/min/max=${deltaP90} cyc; ` +
          `SID(parent/child)=${item.sidParent ?? "--"}/${item.sidChild ?? "--"}; ` +
          `timeout=${item.timeoutBase}/${item.timeoutAttack}; verdict=${item.verdict || "--"}`
      );
    });
  }

  const process = parseSwitchResults(output, "process");
  const thread = parseSwitchResults(output, "thread");
  const hackbench = parseSwitchResults(output, "hackbench");
  const coremark = parseCoremarkResults(output);

  const appendSwitchLines = (title, resultMap, keyLabel) => {
    if (!resultMap.size) return;
    if (lines.length) lines.push("");
    lines.push(title);
    resultMap.forEach((item) => {
      lines.push(
        `${keyLabel}=${item.key}: total=${item.totalMs.toFixed(3)} ms; per_switch=${item.perSwitchUs.toFixed(2)} us`
      );
    });
  };

  if (coremark.length) {
    if (lines.length) lines.push("");
    lines.push("CoreMark 基准测试");
    coremark.forEach((item, index) => {
      const label = coremark.length > 1 ? `run=${index + 1}: ` : "";
      lines.push(`${label}Iterations/Sec=${formatChartNumber(item.iterationsPerSec)}`);
    });
  }
  appendSwitchLines("进程上下文切换", process, "iterations");
  appendSwitchLines("线程上下文切换", thread, "iterations");
  appendSwitchLines("Hackbench 并发调度", hackbench, "loops");

  return lines.filter(Boolean).join("\n") || "暂无可绘制采集数据";
}

function setPill(node, className, text) {
  if (!node) return;
  node.className = `status-pill ${className}`;
  node.innerHTML = `<i></i> ${escapeHtml(text)}`;
}

function setBadge(node, className, text) {
  if (!node) return;
  node.className = `badge ${className}`;
  node.textContent = text;
}

function setView(view) {
  if (!views[view]) return;
  $$(".view").forEach((node) => node.classList.toggle("active", node.id === view));
  $$(".nav-item[data-view]").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  $("#pageTitle").textContent = views[view];
  if (view === "compare") renderReportCharts();
}

function appendTerminal(text) {
  state.terminalText += stripAnsi(text);
  if (state.terminalText.length > 60000) {
    state.terminalText = state.terminalText.slice(-60000);
  }
  const node = $("#terminalOutput");
  node.textContent = state.terminalText || "等待远程终端输出...";
  node.scrollTop = node.scrollHeight;
}

function currentTarget() {
  return state.sshSession?.target || null;
}

function targetKindLabel(target) {
  if (!target) return "--";
  if (target.kind === "remote-wsl") return "远程 WSL";
  if (target.protection === "cache") return "远程 WSL";
  if (target.protection === "tlb") return "FPGA SSH";
  return target.kind || "SSH";
}

function protectionLabel(target) {
  if (!target) return "--";
  if (target.protection === "cache") return "Cache";
  if (target.protection === "tlb") return "TLB";
  return target.label || target.name;
}

function renderTargets() {
  $("#targetSelect").innerHTML = state.targets
    .map((target) => `<option value="${escapeHtml(target.name)}">${escapeHtml(target.label || target.name)}</option>`)
    .join("");
  renderConnectionCards();
  renderOverview();
}

function targetByProtection(protection) {
  return state.targets.find((target) => target.protection === protection);
}

function setMeta(prefix, target) {
  $(`#${prefix}Host`).textContent = target?.host || "--";
  $(`#${prefix}Port`).textContent = String(target?.port || "--");
  $(`#${prefix}User`).textContent = target?.username || "--";
  $(`#${prefix}Workdir`).textContent = target?.workingDirectory || "~";
}

function renderConnectionCards() {
  const active = currentTarget();
  const connected = Boolean(state.sshSession?.connected);
  const cache = targetByProtection("cache");
  const tlb = targetByProtection("tlb");

  setMeta("cache", cache);
  setMeta("tlb", tlb);

  const activeProtection = connected ? active?.protection : null;
  setBadge($("#cacheConnectionState"), activeProtection === "cache" ? "good" : "idle", activeProtection === "cache" ? "已连接" : "未连接");
  setBadge($("#tlbConnectionState"), activeProtection === "tlb" ? "good" : "idle", activeProtection === "tlb" ? "已连接" : "未连接");
  $("#cacheConnectionCard")?.classList.toggle("active-target", activeProtection === "cache");
  $("#tlbConnectionCard")?.classList.toggle("active-target", activeProtection === "tlb");
}

function setStatus(session = {}) {
  state.sshSession = session;
  const connected = Boolean(session.connected);
  const target = session.target;
  const label = connected ? `${protectionLabel(target)} 已连接` : `远程 ${session.status || "未连接"}`;
  setPill($("#sshStatus"), connected ? "online" : "offline", label);
  $("#sideStatus").textContent = connected ? protectionLabel(target) : "未连接";
  setBadge($("#sshBadge"), connected ? "good" : "muted", connected ? "已连接" : "未连接");
  renderConnectionCards();
  renderProtectedState();
  renderOverview();
}

function renderOverview() {
  const latest = state.latestResult;
  const connected = Boolean(state.sshSession?.connected);
  const target = currentTarget();

  $("#overviewBackend").textContent = $("#backendMini")?.textContent || "检查中";
  $("#overviewActiveTarget").textContent = connected ? `${protectionLabel(target)} / ${target?.host || "--"}` : "未连接";
  $("#overviewScript").textContent = state.unprotectedSession?.running
    ? (phaseLabels[state.unprotectedSession.phase] || state.unprotectedSession.phase || "运行中")
    : "待机";
  $("#overviewLastRun").textContent = latest?.status === "captured"
    ? `${protectionLabel(latest)} ${commandLabels[latest.commandKey] || latest.commandKey || ""}`.trim()
    : latest?.status === "running"
      ? "采集中"
      : "暂无";

  $("#overviewCacheTarget").textContent = "缓存侧信道隔离";
  $("#overviewTlbTarget").textContent = "地址转换分区";
}

function renderProtectedState() {
  const connected = Boolean(state.sshSession?.connected);
  const target = currentTarget();
  $("#protectedActiveTarget").textContent = connected ? `${target?.label || target?.name} / ${target?.host}` : "未连接";
  $("#protectedConnectionKind").textContent = connected ? targetKindLabel(target) : "--";
  $("#activeTargetNote").textContent = connected
    ? `当前会话连接到 ${target?.label || target?.name}，可手动输入命令或使用一键采集。`
    : "请先在连接页连接一个目标。";
  $("#terminalInput").disabled = !connected;
  $("#terminalForm button[type='submit']").disabled = !connected;
  $("#runProtectionBtn").disabled = !connected;
  $("#runPerformanceBtn").disabled = !connected;
  $("#markCompleteBtn").disabled = !connected || state.latestResult?.status !== "running";
}

function setTimelineDone(step, done) {
  const item = $(`#attackTimeline li[data-step="${step}"]`);
  if (item) item.classList.toggle("done", Boolean(done));
}

function setInputValue(selector, value) {
  const node = $(selector);
  if (!node || document.activeElement === node) return;
  if (value !== undefined && value !== null) node.value = value;
}

function renderUnprotectedStatus(session = {}) {
  state.unprotectedSession = session;
  const phase = session.phase || "idle";
  const phaseText = phaseLabels[phase] || phase;
  const running = Boolean(session.running);
  const active = running && phase !== "stopped";

  setInputValue("#unprotectedKey", session.key);
  setInputValue("#unprotectedCore", session.core);
  setInputValue("#mallorySamples", session.recovery?.samples);
  setInputValue("#malloryCacheSets", session.recovery?.cacheSets);
  setInputValue("#malloryLineShift", session.recovery?.lineShift);
  setInputValue("#malloryCacheLevel", session.recovery?.cacheLevel);
  setInputValue("#malloryStart", session.recovery?.start);
  setInputValue("#malloryCount", session.recovery?.count);
  $("#recoveredKey").textContent = session.recoveredKey || "--";
  $("#eveState").textContent = session.eveReady ? "已启用" : "未启用";
  $("#attackPhase").textContent = phaseText;
  $("#eavesdropPreview").textContent = session.lastEavesdrop?.text || session.lastCiphertext || "--";
  $("#scriptStateMini").textContent = running ? phaseText : "待机";
  $("#aliceMessageInput").disabled = !active;
  $("#aliceMessageForm button[type='submit']").disabled = !active;
  $("#recoverKeyBtn").disabled = !active;
  $("#demoRecoverKeyBtn").disabled = !active;
  $("#eavesdropBtn").disabled = !active;
  $("#stopUnprotectedBtn").disabled = !running;

  const statusClass = phase.endsWith("failed") ? "offline" : session.eveReady ? "done" : "idle";
  setPill($("#unprotectedStatus"), statusClass, `POC ${phaseText}`);

  const badge = $("#unprotectedPhaseBadge");
  badge.textContent = phaseText;
  badge.className = `badge ${phase.endsWith("failed") ? "bad" : session.recoveredKey ? "done" : "idle"}`;

  setTimelineDone("start", active);
  setTimelineDone("send", active && Boolean(session.lastMessage));
  setTimelineDone("recover", ["recovering", "key-recovered", "eavesdropping", "message-recovered"].includes(phase));
  setTimelineDone("key", Boolean(session.recoveredKey));
  setTimelineDone("eve", active && Boolean(session.eveReady));
  setTimelineDone("result", phase === "message-recovered");
  renderOverview();
}

function clearUnprotectedLogs() {
  $("#logAlice").textContent = "[idle] 等待发送消息";
  $("#logBob").textContent = "[idle] 等待 Bob 解密输出";
  $("#logObserver").textContent = "[idle] 等待 Prime+Probe 与窃听输出";
}

function appendLog(selector, text) {
  const node = $(selector);
  node.textContent = node.textContent.includes("[idle]") ? text : `${node.textContent}\n${text}`;
  node.scrollTop = node.scrollHeight;
}

function appendUnprotectedLog(entry) {
  if (!entry?.text) return;
  const text = `[${entry.role}] ${entry.text}`;
  if (entry.role === "alice") {
    appendLog("#logAlice", text);
  } else if (entry.role === "bob") {
    appendLog("#logBob", text);
  } else {
    appendLog("#logObserver", text);
  }
}

function renderUnprotectedLogs(logs = []) {
  clearUnprotectedLogs();
  logs.forEach(appendUnprotectedLog);
}

function getStatusMeta(status) {
  const statusMeta = {
    running: { label: "结果采集中", className: "idle" },
    captured: { label: "结果已采集", className: "done" },
    idle: { label: "结果待采集", className: "idle" }
  };
  return statusMeta[status || "idle"] || { label: status, className: "idle" };
}

function renderLatestResult(result) {
  state.latestResult = result || null;
  const status = result?.status || "idle";
  const meta = getStatusMeta(status);
  setPill($("#resultStatus"), meta.className, meta.label);
  $("#latestCommand").textContent = result?.command || "--";
  $("#latestStartedAt").textContent = result?.startedAt || "--";
  $("#latestEndedAt").textContent = result?.endedAt || "--";
  $("#latestOutput").textContent = summarizeLatestResult(result);
  renderReportCharts();
  renderProtectedState();
  renderOverview();
}

function renderResultPayload(payload) {
  if (payload?.resultsByCommand) {
    state.resultsByCommand = payload.resultsByCommand;
    renderLatestResult(payload.latestResult);
    return;
  }
  const key = payload?.resultKey || payload?.commandKey;
  if (key) state.resultsByCommand[key] = payload;
  renderLatestResult(payload);
}

function bindEvents() {
  $$(".nav-item[data-view]").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });

  $$("[data-jump]").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.jump));
  });

  $("#connectBtn").addEventListener("click", () => safeAction(async () => {
    const session = await apiPost("/api/fpga/ssh/connect", { targetName: $("#targetSelect").value });
    setStatus(session);
    toast(session.connected ? "目标已连接" : "连接请求已发送");
  }));

  $("#disconnectBtn").addEventListener("click", () => safeAction(async () => {
    const session = await apiPost("/api/fpga/ssh/disconnect");
    setStatus(session);
    toast("当前连接已断开");
  }));

  $("#startUnprotectedBtn").addEventListener("click", () => safeAction(async () => {
    const session = await apiPost("/api/unprotected/start", {
      key: $("#unprotectedKey").value,
      core: $("#unprotectedCore").value,
      samples: $("#mallorySamples").value,
      cacheSets: $("#malloryCacheSets").value,
      lineShift: $("#malloryLineShift").value,
      cacheLevel: $("#malloryCacheLevel").value,
      start: $("#malloryStart").value,
      count: $("#malloryCount").value
    });
    renderUnprotectedStatus(session);
    renderUnprotectedLogs(session.logs);
    toast("无防护 POC 已启动");
  }));

  $("#recoverKeyBtn").addEventListener("click", () => safeAction(async () => {
    renderUnprotectedStatus(await apiPost("/api/unprotected/recover-key", {
      samples: $("#mallorySamples").value,
      cacheSets: $("#malloryCacheSets").value,
      lineShift: $("#malloryLineShift").value,
      cacheLevel: $("#malloryCacheLevel").value,
      start: $("#malloryStart").value,
      count: $("#malloryCount").value
    }));
    toast("Mallory 已开始恢复密钥");
  }));

  $("#demoRecoverKeyBtn").addEventListener("click", () => safeAction(async () => {
    renderUnprotectedStatus(await apiPost("/api/unprotected/demo-recover-key"));
    toast("已使用快速演示恢复密钥");
  }));

  $("#eavesdropBtn").addEventListener("click", () => safeAction(async () => {
    const session = await apiPost("/api/unprotected/eavesdrop");
    renderUnprotectedStatus(session);
    toast(session.lastEavesdrop?.readable ? "Eve 已窃听到明文" : "Eve 只能看到密文");
  }));

  $("#stopUnprotectedBtn").addEventListener("click", () => safeAction(async () => {
    renderUnprotectedStatus(await apiPost("/api/unprotected/stop"));
    toast("无防护 POC 已停止");
  }));

  $("#clearUnprotectedBtn").addEventListener("click", clearUnprotectedLogs);

  $("#aliceMessageForm").addEventListener("submit", (event) => {
    event.preventDefault();
    safeAction(async () => {
      const input = $("#aliceMessageInput");
      const session = await apiPost("/api/unprotected/send", { message: input.value });
      input.value = "";
      renderUnprotectedStatus(session);
      toast("Alice 消息已发送");
    });
  });

  $("#terminalForm").addEventListener("submit", (event) => {
    event.preventDefault();
    safeAction(async () => {
      const input = $("#terminalInput");
      const value = input.value;
      if (!value.trim()) return;
      await apiPost("/api/fpga/terminal/input", { data: `${value}\n` });
      input.value = "";
    });
  });

  $("#clearBtn").addEventListener("click", () => {
    state.terminalText = "";
    $("#terminalOutput").textContent = "终端已清空";
  });

  $("#copyBtn").addEventListener("click", () => safeAction(async () => {
    await navigator.clipboard.writeText($("#terminalOutput").textContent);
    toast("终端输出已复制");
  }));

  $("#runProtectionBtn").addEventListener("click", () => safeAction(async () => {
    const payload = await apiPost("/api/fpga/run/preset", { commandKey: "runProtectionTest" });
    setStatus(payload);
    renderResultPayload(payload);
    toast("已开始防护功能测试采集");
  }));

  $("#runPerformanceBtn").addEventListener("click", () => safeAction(async () => {
    const payload = await apiPost("/api/fpga/run/preset", { commandKey: "runPerformanceTest" });
    setStatus(payload);
    renderResultPayload(payload);
    toast("已开始完整性能测试采集");
  }));

  $("#markCompleteBtn").addEventListener("click", () => safeAction(async () => {
    const result = await apiPost("/api/fpga/results/mark-complete");
    renderResultPayload(result);
    toast("当前采集已结束");
  }));

  $("#refreshResultBtn").addEventListener("click", () => safeAction(async () => {
    renderResultPayload(await apiGet("/api/fpga/results"));
    toast("采集记录已刷新");
  }));
}

function bindEventSource() {
  const source = new EventSource("/events/terminal");
  source.addEventListener("terminal", (event) => {
    const payload = JSON.parse(event.data);
    appendTerminal(payload.text);
  });
  source.addEventListener("status", (event) => setStatus(JSON.parse(event.data)));
  source.addEventListener("result", (event) => renderResultPayload(JSON.parse(event.data)));
  source.addEventListener("unprotected-status", (event) => renderUnprotectedStatus(JSON.parse(event.data)));
  source.addEventListener("unprotected-log", (event) => appendUnprotectedLog(JSON.parse(event.data)));
  source.onerror = () => {
    setPill($("#backendStatus"), "idle", "事件流重连中");
    $("#backendMini").textContent = "重连中";
  };
}

function renderReportCharts() {
  const parsed = parseCollectedMeasurements();
  Object.values(buildReportCharts(parsed)).forEach(drawChart);
  updateReportBadges(parsed);
  updatePerformanceSummary(parsed);
}

function updatePerformanceSummary(parsed) {
  const sidBadRuns = parsed.partition.reduce((sum, item) => sum + item.sidNotSeparatedRuns, 0);
  const timeoutTotal = parsed.partition.reduce((sum, item) => sum + item.timeoutBase + item.timeoutAttack, 0);
  const partitionOk = parsed.partition.length > 0 && sidBadRuns === 0 && timeoutTotal === 0;
  const partitionMaxDelta = Math.max(
    0,
    ...parsed.partition.flatMap((item) => [
      Math.abs(item.deltaP50?.median ?? 0),
      Math.abs(item.deltaP90?.median ?? 0)
    ])
  );

  setText("#summaryPartitionValue", parsed.partition.length ? (partitionOk ? "SID 正常" : "SID 异常") : "等待采集");
  setText(
    "#summaryPartitionNote",
    parsed.partition.length ? `最大中位偏移 ${formatChartNumber(partitionMaxDelta)} cyc` : "SID 分离状态与 TLB 扰动幅度"
  );

  updateOverheadSummary(
    "#summaryProcessValue",
    "#summaryProcessNote",
    fixedReportData.processSwitch.baseline,
    realValuesFromMap(parsed.process, fixedReportData.processSwitch.categories)
  );
  updateOverheadSummary(
    "#summaryThreadValue",
    "#summaryThreadNote",
    fixedReportData.threadSwitch.baseline,
    realValuesFromMap(parsed.thread, fixedReportData.threadSwitch.categories)
  );
  updateOverheadSummary(
    "#summaryHackbenchValue",
    "#summaryHackbenchNote",
    fixedReportData.hackbench.baseline,
    realValuesFromMap(parsed.hackbench, fixedReportData.hackbench.categories)
  );
}

function updateOverheadSummary(valueSelector, noteSelector, baseline, realValues) {
  const overheads = realValues
    .map((value, index) => Number.isFinite(value) && baseline[index] ? ((value - baseline[index]) / baseline[index]) * 100 : null)
    .filter((value) => Number.isFinite(value));
  if (!overheads.length) {
    setText(valueSelector, "等待采集");
    setText(noteSelector, "采集后显示开销范围");
    return;
  }
  const avg = overheads.reduce((sum, value) => sum + value, 0) / overheads.length;
  setText(valueSelector, formatOverheadRange(baseline, realValues));
  setText(noteSelector, `平均开销 ${formatPercent(avg)}`);
}

function setText(selector, text) {
  const node = $(selector);
  if (node) node.textContent = text;
}

function drawChart(config) {
  if (config.type === "line-area") {
    drawLineAreaChart(config);
  } else if (config.type === "zero-delta") {
    drawZeroDeltaChart(config);
  } else if (config.type === "combo") {
    drawComboChart(config);
  } else {
    drawGroupedBarChart(config);
  }
}

function createChartContext(config, options = {}) {
  const svg = $(config.selector);
  if (!svg) return null;

  const ns = "http://www.w3.org/2000/svg";
  const viewBox = svg.getAttribute("viewBox").split(/\s+/).map(Number);
  const width = viewBox[2];
  const height = viewBox[3];
  const padding = options.padding || { top: 62, right: 24, bottom: 58, left: 64 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  svg.replaceChildren();

  const add = (tag, attrs = {}, text = "") => {
    const node = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    if (text) node.textContent = text;
    svg.appendChild(node);
    return node;
  };

  return { svg, ns, width, height, padding, plotWidth, plotHeight, add };
}

function drawGrid(ctx, unit, minValue, maxValue, ticks = 4) {
  const { width, height, padding, plotHeight, add } = ctx;
  for (let i = 0; i <= ticks; i += 1) {
    const y = padding.top + (plotHeight / ticks) * i;
    const value = maxValue - ((maxValue - minValue) / ticks) * i;
    add("line", { x1: padding.left, y1: y, x2: width - padding.right, y2: y, stroke: "#d3dbd0", "stroke-width": 1 });
    add("text", { x: padding.left - 10, y: y + 4, "text-anchor": "end", fill: "#657064", "font-size": 11 }, formatChartNumber(value));
  }
  add("line", { x1: padding.left, y1: height - padding.bottom, x2: width - padding.right, y2: height - padding.bottom, stroke: "#869283", "stroke-width": 1.2 });
  add("line", { x1: padding.left, y1: padding.top, x2: padding.left, y2: height - padding.bottom, stroke: "#869283", "stroke-width": 1.2 });
  add("text", { x: padding.left, y: 18, fill: "#657064", "font-size": 11, "font-weight": 700 }, unit);
}

function valueToY(ctx, value, minValue, maxValue) {
  const range = maxValue - minValue || 1;
  return ctx.padding.top + ((maxValue - value) / range) * ctx.plotHeight;
}

function categoryX(ctx, categories, index) {
  if (categories.length <= 1) return ctx.padding.left + ctx.plotWidth / 2;
  return ctx.padding.left + (ctx.plotWidth / (categories.length - 1)) * index;
}

function drawCategoryLabels(ctx, categories) {
  categories.forEach((category, index) => {
    const x = categoryX(ctx, categories, index);
    ctx.add("text", {
      x,
      y: ctx.height - 24,
      "text-anchor": "middle",
      fill: "#20251f",
      "font-size": 12,
      "font-weight": 700
    }, category);
  });
}

function drawLegend(ctx, series) {
  const legendColumns = series.length > 2 ? 2 : Math.max(1, series.length);
  const legendItemWidth = series.length > 2 ? 138 : 96;
  const legendBoxWidth = legendColumns * legendItemWidth + 18;
  const legendBoxX = ctx.width - ctx.padding.right - legendBoxWidth - 10;
  const legendBoxY = 18;

  series.forEach((item, index) => {
    const x = legendBoxX + 10 + (index % legendColumns) * legendItemWidth;
    const y = legendBoxY + Math.floor(index / legendColumns) * 18;
    ctx.add(item.legendShape === "line" ? "circle" : "rect",
      item.legendShape === "line"
        ? { cx: x + 5, cy: y - 4, r: 5, fill: item.color }
        : { x, y: y - 9, width: 10, height: 10, rx: 2, fill: item.color });
    ctx.add("text", { x: x + 16, y, fill: "#20251f", "font-size": 11, "font-weight": 700 }, item.name);
  });
}

function drawLineAreaChart(config) {
  const ctx = createChartContext(config);
  if (!ctx) return;
  const values = config.series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const maxValue = Math.max(1, ...values) * 1.18;
  const minValue = 0;
  drawGrid(ctx, config.unit, minValue, maxValue);

  const defs = ctx.add("defs");
  config.series.forEach((series, seriesIndex) => {
    const gradient = document.createElementNS(ctx.ns, "linearGradient");
    gradient.setAttribute("id", `${config.selector.slice(1)}Gradient${seriesIndex}`);
    gradient.setAttribute("x1", "0");
    gradient.setAttribute("x2", "0");
    gradient.setAttribute("y1", "0");
    gradient.setAttribute("y2", "1");
    const stopA = document.createElementNS(ctx.ns, "stop");
    stopA.setAttribute("offset", "0%");
    stopA.setAttribute("stop-color", series.color);
    stopA.setAttribute("stop-opacity", seriesIndex === 0 ? "0.26" : "0.14");
    const stopB = document.createElementNS(ctx.ns, "stop");
    stopB.setAttribute("offset", "100%");
    stopB.setAttribute("stop-color", series.color);
    stopB.setAttribute("stop-opacity", "0");
    gradient.append(stopA, stopB);
    defs.appendChild(gradient);
  });

  config.series.forEach((series, seriesIndex) => {
    const points = series.values
      .map((value, index) => Number.isFinite(value) ? [categoryX(ctx, config.categories, index), valueToY(ctx, value, minValue, maxValue), value] : null)
      .filter(Boolean);
    if (!points.length) return;
    const linePath = points.map((point, index) => `${index ? "L" : "M"} ${point[0]} ${point[1]}`).join(" ");
    const areaPath = `${linePath} L ${points.at(-1)[0]} ${ctx.height - ctx.padding.bottom} L ${points[0][0]} ${ctx.height - ctx.padding.bottom} Z`;
    ctx.add("path", { d: areaPath, fill: `url(#${config.selector.slice(1)}Gradient${seriesIndex})` });
    ctx.add("path", { d: linePath, fill: "none", stroke: series.color, "stroke-width": 3, "stroke-linecap": "round", "stroke-linejoin": "round" });
    points.forEach(([x, y, value]) => {
      ctx.add("circle", { cx: x, cy: y, r: 5, fill: series.color, stroke: "#fbfcf8", "stroke-width": 2 });
      ctx.add("text", { x, y: y - 10, "text-anchor": "middle", fill: "#20251f", "font-size": 10, "font-weight": 800 }, formatChartNumber(value));
    });
  });

  drawCategoryLabels(ctx, config.categories);
  drawLegend(ctx, config.series.map((item) => ({ ...item, legendShape: "line" })));
}

function drawZeroDeltaChart(config) {
  const ctx = createChartContext(config, { padding: { top: 60, right: 24, bottom: 58, left: 62 } });
  if (!ctx) return;
  const values = config.series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const magnitude = Math.max(5, ...values.map((value) => Math.abs(value))) * 1.35;
  const minValue = -magnitude;
  const maxValue = magnitude;
  drawGrid(ctx, config.unit, minValue, maxValue);

  const safeTop = valueToY(ctx, 5, minValue, maxValue);
  const safeBottom = valueToY(ctx, -5, minValue, maxValue);
  ctx.add("rect", {
    x: ctx.padding.left,
    y: safeTop,
    width: ctx.plotWidth,
    height: safeBottom - safeTop,
    rx: 4,
    fill: "#dff0df",
    opacity: 0.72
  });
  const zeroY = valueToY(ctx, 0, minValue, maxValue);
  ctx.add("line", { x1: ctx.padding.left, y1: zeroY, x2: ctx.width - ctx.padding.right, y2: zeroY, stroke: "#2d7a35", "stroke-width": 2, "stroke-dasharray": "5 5" });
  ctx.add("text", { x: ctx.width - ctx.padding.right, y: safeTop - 6, "text-anchor": "end", fill: "#2d7a35", "font-size": 11, "font-weight": 800 }, "安全带 ±5 cyc");

  config.series.forEach((series) => {
    series.values.forEach((value, index) => {
      if (!Number.isFinite(value)) return;
      const x = categoryX(ctx, config.categories, index);
      const y = valueToY(ctx, value, minValue, maxValue);
      ctx.add("line", { x1: x, y1: zeroY, x2: x, y2: y, stroke: series.color, "stroke-width": 2, opacity: 0.72 });
      ctx.add("circle", { cx: x, cy: y, r: 6, fill: series.color, stroke: "#fbfcf8", "stroke-width": 2 });
      ctx.add("text", { x, y: y - 11, "text-anchor": "middle", fill: "#20251f", "font-size": 10, "font-weight": 800 }, formatChartNumber(value));
    });
  });

  if (!config.series.length) {
    ctx.add("text", { x: ctx.width / 2, y: ctx.height / 2, "text-anchor": "middle", fill: "#657064", "font-size": 14, "font-weight": 800 }, "等待防护有效性采集");
  }
  drawCategoryLabels(ctx, config.categories);
  drawLegend(ctx, config.series.map((item) => ({ ...item, legendShape: "line" })));
}

function drawComboChart(config) {
  const ctx = createChartContext(config);
  if (!ctx) return;
  const values = config.series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const maxValue = Math.max(1, ...values) * 1.18;
  const minValue = 0;
  const baseline = config.series[0];
  const protectedSeries = config.series[1];
  const categoryWidth = ctx.plotWidth / config.categories.length;
  const barWidth = Math.max(18, categoryWidth * 0.28);
  drawGrid(ctx, config.unit, minValue, maxValue);

  config.categories.forEach((category, index) => {
    const centerX = ctx.padding.left + categoryWidth * index + categoryWidth / 2;
    const baseValue = baseline?.values[index];
    if (Number.isFinite(baseValue)) {
      const y = valueToY(ctx, baseValue, minValue, maxValue);
      const barHeight = ctx.height - ctx.padding.bottom - y;
      ctx.add("rect", { x: centerX - barWidth / 2, y, width: barWidth, height: barHeight, rx: 4, fill: baseline.color, opacity: 0.78 });
      ctx.add("text", { x: centerX, y: y - 6, "text-anchor": "middle", fill: "#20251f", "font-size": 10, "font-weight": 800 }, formatChartNumber(baseValue));
    }
    ctx.add("text", {
      x: centerX,
      y: ctx.height - 24,
      "text-anchor": "middle",
      fill: "#20251f",
      "font-size": 12,
      "font-weight": 700
    }, category);
  });

  if (protectedSeries) {
    const points = protectedSeries.values
      .map((value, index) => Number.isFinite(value)
        ? [ctx.padding.left + categoryWidth * index + categoryWidth / 2, valueToY(ctx, value, minValue, maxValue), value, baseline.values[index]]
        : null)
      .filter(Boolean);
    if (points.length) {
      const path = points.map((point, index) => `${index ? "L" : "M"} ${point[0]} ${point[1]}`).join(" ");
      ctx.add("path", { d: path, fill: "none", stroke: protectedSeries.color, "stroke-width": 3, "stroke-linecap": "round", "stroke-linejoin": "round" });
      points.forEach(([x, y, value, baseValue]) => {
        ctx.add("circle", { cx: x, cy: y, r: 6, fill: protectedSeries.color, stroke: "#fbfcf8", "stroke-width": 2 });
        ctx.add("text", { x, y: y - 12, "text-anchor": "middle", fill: "#20251f", "font-size": 10, "font-weight": 800 }, formatChartNumber(value));
        if (Number.isFinite(baseValue) && baseValue !== 0) {
          const pct = ((value - baseValue) / baseValue) * 100;
          ctx.add("text", { x, y: y + 20, "text-anchor": "middle", fill: protectedSeries.color, "font-size": 10, "font-weight": 800 }, formatPercent(pct));
        }
      });
    }
  }

  drawLegend(ctx, config.series.map((item, index) => ({ ...item, legendShape: index === 0 ? "bar" : "line" })));
}

function drawGroupedBarChart(config) {
  const ctx = createChartContext(config);
  if (!ctx) return;

  const values = config.series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const maxValue = Math.max(1, ...values) * 1.18;
  const minValue = 0;
  const categoryWidth = ctx.plotWidth / config.categories.length;
  const barGap = 5;
  const seriesCount = Math.max(1, config.series.length);
  const groupPadding = Math.max(16, categoryWidth * 0.16);
  const barWidth = Math.max(7, (categoryWidth - groupPadding * 2 - barGap * (seriesCount - 1)) / seriesCount);

  drawGrid(ctx, config.unit, minValue, maxValue);

  config.categories.forEach((category, categoryIndex) => {
    const groupX = ctx.padding.left + categoryIndex * categoryWidth;
    config.series.forEach((series, seriesIndex) => {
      const value = series.values[categoryIndex];
      if (!Number.isFinite(value)) return;
      const x = groupX + groupPadding + seriesIndex * (barWidth + barGap);
      const y = valueToY(ctx, value, minValue, maxValue);
      const barHeight = ctx.height - ctx.padding.bottom - y;
      ctx.add("rect", { x, y, width: barWidth, height: barHeight, rx: 2, fill: series.color });
      ctx.add("text", { x: x + barWidth / 2, y: y - 5, "text-anchor": "middle", fill: "#20251f", "font-size": 10, "font-weight": 700 }, formatChartNumber(value));
    });
    ctx.add("text", {
      x: groupX + categoryWidth / 2,
      y: ctx.height - 24,
      "text-anchor": "middle",
      fill: "#20251f",
      "font-size": 12,
      "font-weight": 700
    }, category);
  });

  drawLegend(ctx, config.series);
}

function formatChartNumber(value) {
  if (!Number.isFinite(value)) return "--";
  if (Math.abs(value) >= 100) return value.toFixed(value % 1 === 0 ? 0 : 2);
  if (Math.abs(value) >= 10) return value.toFixed(value % 1 === 0 ? 0 : 2);
  return value.toFixed(0);
}

async function init() {
  bindEvents();
  bindEventSource();
  setView("overview");
  renderReportCharts();
  renderProtectedState();

  const health = await apiGet("/api/health");
  setPill($("#backendStatus"), "online", "后端在线");
  $("#backendMini").textContent = "在线";
  setStatus(health.session);
  renderResultPayload(health.session);
  renderUnprotectedStatus(health.unprotected);
  renderUnprotectedLogs(health.unprotected?.logs || []);

  const payload = await apiGet("/api/fpga/targets");
  state.targets = payload.targets;
  renderTargets();
  appendTerminal("后端已连接，等待远程会话...\n");
}

init().catch((error) => {
  setPill($("#backendStatus"), "offline", "后端异常");
  $("#backendMini").textContent = "异常";
  appendTerminal(`[frontend error] ${error.message}\n`);
});
