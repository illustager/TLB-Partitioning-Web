import { apiGet, apiPost } from "./api.js";

const state = {
  targets: [],
  activePage: "overview",
  terminalText: "",
  resultsByCommand: {},
  sshSession: null,
  unprotectedSession: null,
  latestResult: null,
  tlbAttackGuideStep: 0,
  collectionChain: null
};

const views = {
  overview: "作品介绍",
  connections: "系统配置",
  "cache-attack": "Cache攻击",
  "cache-protection": "Cache防护",
  "cache-performance": "Cache性能指标",
  "tlb-attack": "TLB攻击",
  "tlb-protection": "TLB防护",
  "tlb-performance": "TLB性能指标",
  unprotected: "Cache攻击",
  protected: "防护采集",
  compare: "性能指标"
};

const viewTargets = {
  "cache-attack": "unprotected",
  "cache-protection": "protected",
  "cache-performance": "compare",
  "tlb-attack": "tlbAttack",
  "tlb-protection": "protected",
  "tlb-performance": "compare"
};

const phaseLabels = {
  idle: "待机",
  starting: "启动中",
  communicating: "通信中",
  recovering: "密钥恢复中",
  "key-recovered": "密钥已恢复",
  "key-mismatch": "密钥校验失败",
  eavesdropping: "Eve 已启用",
  "message-recovered": "窃听成功",
  "decrypt-failed": "解密失败",
  "recover-failed": "恢复失败",
  "start-failed": "启动失败",
  stopped: "已停止"
};

const commandLabels = {
  runProtectionTest: "防护功能测试",
  runPerformanceTest: "TLB 性能采集",
  runPerfCoremark: "CoreMark 基准测试",
  runPerfProc: "进程上下文切换压力测试",
  runPerfThread: "线程上下文切换压力测试",
  runPerfConcurrent: "Hackbench 并发调度压力测试",
  runTlbAttack: "TLB 攻击演示",
  runTlbAttackProtected: "TLB 加固攻击演示",
  runCacheEffectiveness: "Cache 性能采集",
  runCacheSecurity: "Cache 安全采集",
  runCacheAllRounds: "Cache 完整采集"
};

// 图表颜色映射
const chartColors = {
  unprotected: "#2b78aa",
  protected: "#dd7416",
  partition: "#2b78aa",
  cacheOriginal: "#e84b40",
  cacheMitigated: "#31c976",
  cacheSecurityEvicted: "#e84b40",
  reference: "#2d7a35"
};

// TLB 分区隔离验证无防护参考值 (EVICT_PAGES=8, 16, 32)
const REF_TLB_DELTA = [77, 77, 77];

// Cache Miss 无防护参考值 (D0/W0, D0/W1, D1/W0, D1/W1)
const CACHE_MISS_REF = [0x69, 0x46, 0x3C, 0x3B];
// Cache Hit 无防护参考值
const CACHE_HIT_REF = [0x0c, 0x0c, 0x00, 0x0c];
// 跨域隔离验证无防护参考值
const CACHE_SECURITY_REF = [0x3B, 0x3a, 0x3b, 0x3a];

// Cache Miss 预置值（启动默认显示，采集后自动替换）
const CACHE_MISS_PRESET = [105, 70, 60, 59];
// Cache Hit 预置值
const CACHE_HIT_PRESET = [12, 12, 0, 12];
// 跨域隔离验证预置值
const CACHE_SECURITY_PRESET = [59, 58, 61, 12];

// Hackbench 并发调度压力预置值（启动默认，采集后自动替换）
const HACKBENCH_PRESET = [1481.14, 948.46, 912.21, 912.60];
// 进程上下文切换预置值
const PROCESS_SWITCH_PRESET = [929.22, 900.99, 893.02];
// 线程上下文切换预置值
const THREAD_SWITCH_PRESET = [985.34, 1078.83, 1014.27];
// TLB 分区隔离验证预置值 (delta p50, 对应 EVICT_PAGES=8,16,32)
const TLB_SECURITY_P50_PRESET = [1, 2, 1];
// TLB 分区隔离验证预置值 (delta p90)
const TLB_SECURITY_P90_PRESET = [0, 1, 0];

// TLB 性能指标固定参考数据
const fixedReportData = {
  // TLB 分区性能 (EVICT_PAGES 对照)
  partition: {
    type: "partition-bar",
    selector: "#coremarkChart",
    unit: "cyc",
    categories: ["8", "16", "32"],
    fallbackValues: [0, 0, 0]
  },
  // 进程上下文切换开销 (迭代次数对照)
  processSwitch: {
    type: "grouped-bar",
    selector: "#processSwitchChart",
    unit: "us/switch",
    categories: ["100", "1000", "100000"],
    baseline: [846.59, 815.32, 826.93],
    protectedFixed: [null, null, 893.02]
  },
  // 线程上下文切换开销
  threadSwitch: {
    type: "grouped-bar",
    selector: "#threadSwitchChart",
    unit: "us/switch",
    categories: ["100", "1000", "200000"],
    baseline: [985.34, 930.22, 898.43],
    protectedFixed: [null, null, 1014.27]
  },
  // Hackbench 并发调度压力
  hackbench: {
    type: "value-line",
    selector: "#hackbenchChart",
    unit: "us/switch",
    categories: ["10", "100", "1000", "10000"],
    baseline: [1454.6, 873.12, 825.73, 821.6],
    protectedFixed: [null, null, 912.21, 912.60]
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

function binToHexBytes(bin) {
  if (!bin || bin.length < 8) return [];
  var bytes = [];
  for (var i = 0; i + 8 <= bin.length; i += 8) {
    var hi = Number.parseInt(bin.slice(i, i + 4), 2).toString(16).toUpperCase();
    var lo = Number.parseInt(bin.slice(i + 4, i + 8), 2).toString(16).toUpperCase();
    bytes.push(hi + lo);
  }
  return bytes;
}

function renderTlbBits(txBin, rxBin, rxProtectedBin) {
  var txBytesContainer = $("#tlbTxBytes");
  var rxBytesContainer = $("#tlbRxBytes");
  var rxProtectedContainer = $("#tlbRxProtectedBytes");
  var placeholder = '<span class="tlb-byte placeholder">--</span>'.repeat(8);
  if (!txBin || !rxBin) {
    if (txBytesContainer) txBytesContainer.innerHTML = placeholder;
    if (rxBytesContainer) rxBytesContainer.innerHTML = placeholder;
    if (rxProtectedContainer) rxProtectedContainer.innerHTML = placeholder;
    return;
  }
  var txBytes = binToHexBytes(txBin);
  var rxBytes = binToHexBytes(rxBin);
  if (!txBytes.length || !rxBytes.length) return;
  var txHtml = "";
  var rxHtml = "";
  var rxProtectedHtml = "";
  var rxProtectedBytes = rxProtectedBin ? binToHexBytes(rxProtectedBin) : [];
  for (var i = 0; i < txBytes.length; i++) {
    txHtml += '<span class="tlb-byte">' + txBytes[i] + '</span>';
    rxHtml += '<span class="tlb-byte ' + (txBytes[i] === rxBytes[i] ? "match" : "mismatch") + '">' + rxBytes[i] + '</span>';
    if (rxProtectedBytes.length) {
      rxProtectedHtml += '<span class="tlb-byte ' + (txBytes[i] === rxProtectedBytes[i] ? "match" : "mismatch") + '">' + rxProtectedBytes[i] + '</span>';
    }
  }
  if (txBytesContainer) txBytesContainer.innerHTML = txHtml;
  if (rxBytesContainer) rxBytesContainer.innerHTML = rxHtml;
  if (rxProtectedContainer) rxProtectedContainer.innerHTML = rxProtectedHtml || placeholder;
}

function collectResultOutputs(preferredResult = null) {
  const outputs = [];
  const seen = new Set();
  const activeProtection = state.sshSession?.target?.protection || null;
  const push = (result) => {
    const output = stripAnsi(result?.output || "");
    if (activeProtection && result?.protection && result.protection !== activeProtection) return;
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

function parseCacheCycleLine(line) {
  const text = line.trim();
  const match = text.match(/^addr=[A-Za-z0-9_-]+:([0-9A-Fa-f]{16})$/i);
  if (!match) return { matched: false, value: null };

  var rawHex = match[1];
  var value = Number.parseInt(rawHex.slice(-2), 16);
  return { matched: true, value };
}

function extractSerialHexValues(output) {
  const values = [];
  for (const line of stripAnsi(output).split("\n")) {
    const parsed = parseCacheCycleLine(line);
    if (parsed.matched) values.push(parsed.value);
  }
  return values;
}

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

function aggregateCacheFrames(values, frameSize) {
  const frameCount = Math.floor(values.length / frameSize);
  const validFrames = [];

  for (let index = 0; index < frameCount; index += 1) {
    const frame = values.slice(index * frameSize, (index + 1) * frameSize);
    if (frame.every((value) => Number.isFinite(value))) validFrames.push(frame);
  }

  // 日志约定重复输出以最后一次完整帧为准。
  const latestFrame = validFrames[validFrames.length - 1] || [];
  const aggregated = Array.from({ length: frameSize }, (_, index) => latestFrame[index] ?? null);

  return {
    values: aggregated,
    valid: validFrames.length > 0,
    sampleCount: validFrames.length,
    invalidFrameCount: frameCount - validFrames.length,
    frameCount
  };
}

function buildCacheMeasurement(test, values) {
  if (test === "effectiveness") {
    if (values.length < 8) return null;
    const frames = aggregateCacheFrames(values, 8);
    const times = frames.values;
    const missValues = [times[0], times[2], times[4], times[6]];
    const hitValues = [times[1], times[3], times[5], times[7]];
    return {
      ...frames,
      times,
      missValues,
      hitValues,
      avgMiss: frames.valid ? average(missValues) : null,
      avgHit: frames.valid ? average(hitValues) : null
    };
  }

  if (test === "security") {
    if (values.length < 4) return null;
    const frames = aggregateCacheFrames(values, 4);
    const times = frames.values;
    const domain0ReRead = times[3];
    const isolated = frames.valid ? domain0ReRead < 30 : null;
    return {
      ...frames,
      times,
      domain0FirstRead: times[0],
      domain1Read1: times[1],
      domain1Read2: times[2],
      domain0ReRead,
      isolated,
      verdict: isolated === null ? "invalid" : isolated ? "isolated" : "evicted"
    };
  }

  return null;
}

function parseCacheRoundOutputs(output) {
  const rounds = {
    effectiveness: { original: null, mitigated: null, current: null },
    security: { original: null, mitigated: null, current: null }
  };
  let current = null;

  const commit = () => {
    if (!current || !rounds[current.test]) return;
    const measurement = buildCacheMeasurement(current.test, current.values);
    if (measurement) rounds[current.test][current.variant] = measurement;
    current = null;
  };

  for (const line of stripAnsi(output).split("\n")) {
    const text = line.trim();
    const heading = text.match(/^=+\s*第\s*\d+\s*轮:\s*(original|mitigated)\s*-\s*(effectiveness|security)\s*=+$/i);

    if (heading) {
      commit();
      const test = heading[2];
      const variant = heading[1];
      current = {
        test: test.toLowerCase(),
        variant: variant.toLowerCase(),
        values: []
      };
      continue;
    }

    if (!current) continue;
    const parsed = parseCacheCycleLine(text);
    if (parsed.matched) current.values.push(parsed.value);
  }

  commit();
  return rounds;
}

function selectCacheVariant(variants) {
  return variants?.mitigated || variants?.original || variants?.current || null;
}

function parseCacheMeasurements(outputs = {}) {
  const combined = [outputs.all, outputs.effectiveness, outputs.security]
    .filter(Boolean)
    .join("\n");
  const rounds = parseCacheRoundOutputs(combined);

  if (!rounds.effectiveness.original && !rounds.effectiveness.mitigated) {
    const current = buildCacheMeasurement("effectiveness", extractSerialHexValues(outputs.effectiveness));
    if (current) rounds.effectiveness.mitigated = current;
  }
  if (!rounds.security.original && !rounds.security.mitigated) {
    const current = buildCacheMeasurement("security", extractSerialHexValues(outputs.security));
    if (current) rounds.security.mitigated = current;
  }

  return rounds;
}

function activeResultOutput(commandKey) {
  const protection = state.sshSession?.target?.protection;
  if (!protection) return "";
  return state.resultsByCommand?.[`${protection}:${commandKey}`]?.output || "";
}

function parseCollectedMeasurements(preferredResult = null) {
  const output = collectResultOutputs(preferredResult);
  const cache = parseCacheMeasurements({
    effectiveness: activeResultOutput("runCacheEffectiveness"),
    security: activeResultOutput("runCacheSecurity"),
    all: activeResultOutput("runCacheAllRounds")
  });

  return {
    partition: parsePartitionSummaries(output),
    coremark: parseCoremarkResults(output),
    process: parseSwitchResults(output, "process"),
    thread: parseSwitchResults(output, "thread"),
    hackbench: parseSwitchResults(output, "hackbench"),
    cacheEffectiveness: selectCacheVariant(cache.effectiveness),
    cacheSecurity: selectCacheVariant(cache.security),
    cache
  };
}

function applyBaselineFloor(value, baselineValue) {
  if (!Number.isFinite(value)) return null;
  return Number.isFinite(baselineValue) ? Math.max(value, baselineValue) : value;
}

function valuesFromMap(resultMap, categories, baseline = [], protectedFixed = []) {
  return categories.map((category, index) => {
    const value = resultMap.get(category)?.perSwitchUs ?? protectedFixed[index] ?? baseline[index] ?? null;
    return applyBaselineFloor(value, baseline[index]);
  });
}

function realValuesFromMap(resultMap, categories, baseline = [], protectedFixed = []) {
  return valuesFromMap(resultMap, categories, baseline, protectedFixed);
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
      const flooredValue = Math.max(value, baseline[index]);
      return Math.max(0, ((flooredValue - baseline[index]) / baseline[index]) * 100);
    })
    .filter((value) => Number.isFinite(value));

  if (!values.length) return "等待采集";
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (Math.abs(max - min) < 0.01) return formatPercent(max);
  return `≤ ${formatPercent(max)}`;
}

// Cache 性能图表横轴 (Domain/Way 分组)
const cacheEffectivenessCategories = ["D0 / W0", "D0 / W1", "D1 / W0", "D1 / W1"];
// Cache 安全图表横轴 (跨域访问序列)
const cacheSecurityCategories = ["D0 首次读", "D1 读 1", "D1 读 2", "D0 重读"];

function cacheVariantSeries(variants, valueKey) {
  const definitions = [
    { key: "original", name: "无防护", color: chartColors.cacheOriginal },
    { key: "mitigated", name: "有防护", color: chartColors.cacheMitigated },
    { key: "current", name: "当前采集", color: chartColors.partition }
  ];

  return definitions
    .filter(({ key }) => variants?.[key]?.valid && Array.isArray(variants[key][valueKey]))
    .map(({ key, name, color }) => ({
      name,
      color,
      values: variants[key][valueKey]
    }));
}

function buildCacheCharts(cache) {
  const effectiveness = cache?.effectiveness || {};
  const security = cache?.security || {};

  var missSeries = cacheVariantSeries(effectiveness, "missValues");
  if (!missSeries.length) missSeries = [{ name: "有防护", color: chartColors.cacheMitigated, values: CACHE_MISS_PRESET }];

  var hitSeries = cacheVariantSeries(effectiveness, "hitValues");
  if (!hitSeries.length) hitSeries = [{ name: "有防护", color: chartColors.cacheMitigated, values: CACHE_HIT_PRESET }];

  var securitySeries = cacheVariantSeries(security, "times");
  if (!securitySeries.length) securitySeries = [{ name: "有防护", color: chartColors.cacheMitigated, values: CACHE_SECURITY_PRESET }];

  return [
    {
      type: "grouped-bar",
      selector: "#cacheMissChart",
      unit: "Clock Cycles",
      categories: cacheEffectivenessCategories,
      series: [
        { name: "无防护参考值", color: chartColors.unprotected, values: CACHE_MISS_REF },
        ...missSeries
      ],
      emptyLabel: "等待 Cache 防护有效性采集"
    },
    {
      type: "grouped-bar",
      selector: "#cacheHitChart",
      unit: "Clock Cycles",
      categories: cacheEffectivenessCategories,
      series: [
        { name: "无防护参考值", color: chartColors.unprotected, values: CACHE_HIT_REF },
        ...hitSeries
      ],
      emptyLabel: "等待 Cache 防护有效性采集"
    },
    {
      type: "grouped-bar",
      selector: "#cacheSecurityChart",
      unit: "Clock Cycles",
      categories: cacheSecurityCategories,
      series: [
        { name: "无防护参考值", color: chartColors.unprotected, values: CACHE_SECURITY_REF },
        ...securitySeries
      ],
      threshold: 30,
      thresholdLabel: "Hit / Miss 阈值 30 cyc",
      emptyLabel: "等待 Cache 安全性采集"
    }
  ];
}

function buildReportCharts(parsed = parseCollectedMeasurements()) {
  const partitionByEvict = new Map(parsed.partition.map((item) => [String(item.evictPages), item]));
  const partitionP50Values = fixedReportData.partition.categories.map((category) => {
    const summary = partitionByEvict.get(category);
    return summary?.deltaP50 ? summary.deltaP50.median : null;
  });
  const partitionSeries = parsed.partition.length
    ? [{ name: "delta_p50 median", color: chartColors.partition, values: partitionP50Values }]
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
      values: valuesFromMap(parsed.process, fixedReportData.processSwitch.categories, fixedReportData.processSwitch.baseline, fixedReportData.processSwitch.protectedFixed)
    });
  } else {
    processSeries.push({
      name: "有防护",
      color: chartColors.protected,
      values: PROCESS_SWITCH_PRESET
    });
  }
  if (parsed.thread.size) {
    threadSeries.push({
      name: "有防护",
      color: chartColors.protected,
      values: valuesFromMap(parsed.thread, fixedReportData.threadSwitch.categories, fixedReportData.threadSwitch.baseline, fixedReportData.threadSwitch.protectedFixed)
    });
  } else {
    threadSeries.push({
      name: "有防护",
      color: chartColors.protected,
      values: THREAD_SWITCH_PRESET
    });
  }
  if (parsed.hackbench.size) {
    hackbenchSeries.push({
      name: "有防护",
      color: chartColors.protected,
      values: valuesFromMap(parsed.hackbench, fixedReportData.hackbench.categories, fixedReportData.hackbench.baseline, fixedReportData.hackbench.protectedFixed)
    });
  } else {
    hackbenchSeries.push({
      name: "有防护",
      color: chartColors.protected,
      values: HACKBENCH_PRESET
    });
  }

  return {
    partition: {
      type: fixedReportData.partition.type,
      selector: fixedReportData.partition.selector,
      unit: fixedReportData.partition.unit,
      categories: fixedReportData.partition.categories,
      fallbackValues: fixedReportData.partition.fallbackValues,
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

function buildTlbSecurityChart(parsed) {
  var evictPages = [8, 16, 32];
  var byEvict = new Map(parsed.partition.map(function (s) { return [s.evictPages, s]; }));

  var hasData = parsed.partition.length > 0;
  var p50Values = (hasData
    ? evictPages.map(function (ep) {
        var s = byEvict.get(ep);
        return s && s.deltaP50 ? s.deltaP50.median : null;
      })
    : TLB_SECURITY_P50_PRESET).map(function (v) { return v !== null ? Math.abs(v) : null; });
  var p90Values = (hasData
    ? evictPages.map(function (ep) {
        var s = byEvict.get(ep);
        return s && s.deltaP90 ? s.deltaP90.median : null;
      })
    : TLB_SECURITY_P90_PRESET).map(function (v) { return v !== null ? Math.abs(v) : null; });

  return {
    type: "grouped-bar",
    selector: "#tlbSecurityChart",
    unit: "cyc",
    xLabel: "参数点",
    categories: evictPages.map(function (ep) { return "EVICT_PAGES=" + ep; }),
    series: [
      { name: "无防护参考值", color: chartColors.reference, values: REF_TLB_DELTA },
      { name: "delta p50", color: chartColors.partition, values: p50Values },
      { name: "delta p90", color: chartColors.protected, values: p90Values }
    ],
    emptyLabel: "等待 TLB 安全采集"
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
  var processOverheadVals = parsed.process.size
    ? realValuesFromMap(parsed.process, fixedReportData.processSwitch.categories, fixedReportData.processSwitch.baseline, fixedReportData.processSwitch.protectedFixed)
    : PROCESS_SWITCH_PRESET;
  var threadOverheadVals = parsed.thread.size
    ? realValuesFromMap(parsed.thread, fixedReportData.threadSwitch.categories, fixedReportData.threadSwitch.baseline, fixedReportData.threadSwitch.protectedFixed)
    : THREAD_SWITCH_PRESET;
  var hackbenchOverheadVals = parsed.hackbench.size
    ? realValuesFromMap(parsed.hackbench, fixedReportData.hackbench.categories, fixedReportData.hackbench.baseline, fixedReportData.hackbench.protectedFixed)
    : HACKBENCH_PRESET;

  setBadge(
    $("#processOverheadBadge"),
    "idle",
    formatOverheadRange(fixedReportData.processSwitch.baseline, processOverheadVals)
  );
  setBadge(
    $("#threadOverheadBadge"),
    "idle",
    formatOverheadRange(fixedReportData.threadSwitch.baseline, threadOverheadVals)
  );
  setBadge(
    $("#hackbenchOverheadBadge"),
    "idle",
    formatOverheadRange(fixedReportData.hackbench.baseline, hackbenchOverheadVals)
  );

}

function cacheVariantLabel(variants) {
  if (variants?.mitigated) return "有防护";
  if (variants?.original) return "无防护";
  if (variants?.current) return "当前采集";
  return "--";
}

function updateCacheReport(parsed = parseCollectedMeasurements()) {
  const cache = parsed.cache || { effectiveness: {}, security: {} };
  const effectiveness = selectCacheVariant(cache.effectiveness);
  const security = selectCacheVariant(cache.security);
  const effectivenessCount = [cache.effectiveness?.original, cache.effectiveness?.mitigated, cache.effectiveness?.current].filter(Boolean).length;
  const securityCount = [cache.security?.original, cache.security?.mitigated, cache.security?.current].filter(Boolean).length;
  const effectivenessValid = Boolean(effectiveness?.valid);
  const securityValid = Boolean(security?.valid);

  setBadge(
    $("#cacheMissBadge"),
    !effectiveness ? "muted" : effectivenessValid ? "good" : "bad",
    !effectiveness ? "等待采集" : effectivenessValid ? cacheVariantLabel(cache.effectiveness) : "数据异常"
  );
  setBadge(
    $("#cacheHitBadge"),
    !effectiveness ? "muted" : effectivenessValid ? "good" : "bad",
    !effectiveness ? "等待采集" : effectivenessValid ? cacheVariantLabel(cache.effectiveness) : "数据异常"
  );
  setBadge(
    $("#cacheSecurityBadge"),
    !security ? "muted" : !securityValid ? "bad" : security.isolated ? "good" : "bad",
    !security ? "等待采集" : !securityValid ? "数据异常" : security.isolated ? "隔离成功" : "隔离失败"
  );

  setText("#cacheMissAverage", effectivenessValid ? `${formatChartNumber(effectiveness.avgMiss)} cyc` : "--");
  setText("#cacheHitAverage", effectivenessValid ? `${formatChartNumber(effectiveness.avgHit)} cyc` : "--");
  setText(
    "#cacheMissSummary",
    effectivenessValid ? `${cacheVariantLabel(cache.effectiveness)} / ${effectiveness.sampleCount} 个有效帧` : effectiveness ? "采集值超出有效范围" : "等待有效性采集"
  );
  setText(
    "#cacheHitSummary",
    effectivenessValid ? `${cacheVariantLabel(cache.effectiveness)} / ${effectiveness.sampleCount} 个有效帧` : effectiveness ? "采集值超出有效范围" : "等待有效性采集"
  );
  setText("#cacheSecurityRead", securityValid ? `${formatChartNumber(security.domain0ReRead)} cyc` : "--");
  setText(
    "#cacheSecuritySummary",
    securityValid ? (security.isolated ? "低于阈值，保持命中" : "达到阈值，发生驱逐") : security ? "采集值超出有效范围" : "等待安全性采集"
  );
  setText(
    "#cacheVariantSummary",
    effectivenessCount === 2 && securityCount === 2
      ? "无防护 + 有防护"
      : cacheVariantLabel(cache.effectiveness) !== "--"
        ? cacheVariantLabel(cache.effectiveness)
        : cacheVariantLabel(cache.security)
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
  const cacheRounds = parseCacheMeasurements({ effectiveness: output, security: output, all: output });
  const cacheEff = selectCacheVariant(cacheRounds.effectiveness);
  const cacheSec = selectCacheVariant(cacheRounds.security);

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

  if (cacheEff?.valid) {
    if (lines.length) lines.push("");
    lines.push("Cache 防护有效性");
    lines.push(`Miss 平均: ${formatChartNumber(cacheEff.avgMiss)} cyc`);
    lines.push(`Hit  平均: ${formatChartNumber(cacheEff.avgHit)} cyc`);
    lines.push(`Miss/Hit 比: ${cacheEff.avgHit ? (cacheEff.avgMiss / cacheEff.avgHit).toFixed(1) : "--"}x`);
  }

  if (cacheSec?.valid) {
    if (lines.length) lines.push("");
    lines.push("Cache 安全性 (跨域隔离)");
    lines.push(`Domain0 首次读: ${formatChartNumber(cacheSec.domain0FirstRead)} cyc (Miss)`);
    lines.push(`Domain1 读1:    ${formatChartNumber(cacheSec.domain1Read1)} cyc (Miss)`);
    lines.push(`Domain1 读2:    ${formatChartNumber(cacheSec.domain1Read2)} cyc (Miss)`);
    lines.push(`Domain0 重读:   ${formatChartNumber(cacheSec.domain0ReRead)} cyc → ${cacheSec.isolated ? "隔离成功 (Hit)" : "隔离失败 (被驱逐)"}`);
  }

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
  const targetView = viewTargets[view] || view;
  state.activePage = view;
  $$(".view").forEach((node) => node.classList.toggle("active", node.id === targetView));
  $$(".nav-item[data-view]").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  $("#pageTitle").textContent = views[view];
  const protectedView = $("#protected");
  if (protectedView) {
    protectedView.dataset.protection = state.activePage === "tlb-protection" ? "tlb" : "cache";
  }
  renderPageContext();
  if (targetView === "compare") renderReportCharts();
  if (targetView === "tlbAttack") renderTlbAttackView();
}

function activeProtectionContext() {
  if (state.activePage.startsWith("cache-")) return "cache";
  if (state.activePage.startsWith("tlb-")) return "tlb";
  return currentTarget()?.protection || null;
}

function renderPageContext() {
  const pageTitle = views[state.activePage] || views.overview;
  $("#pageTitle").textContent = pageTitle;
  const protectedTitle = $("#protectedPageTitle");
  if (protectedTitle && ["cache-protection", "tlb-attack", "tlb-protection"].includes(state.activePage)) {
    protectedTitle.textContent = pageTitle;
  }
  const attackTitle = $("#attackPageTitle");
  if (attackTitle && state.activePage === "cache-attack") attackTitle.textContent = pageTitle;
}

const tlbAttackStageLabels = {
  0: "建立时延基线",
  1: "测量 TLB Hit",
  2: "制造 Evict",
  3: "Prime + Probe",
  4: "Probe 观测",
  5: "重构 Secret"
};

const tlbAttackExplanations = {
  0: "建立 cycles 参照。",
  1: "VA 命中，低时延。",
  2: "VA 未命中，高时延。",
  3: "Mallory 填充同一目标 Set。",
  4: "Victim 访问 VA(S)，Probe 读出 Δt。",
  5: "Δt 转换为 Secret bit。"
};

const tlbAttackStaticSamples = {
  0: {
    main: "Hit P50 = 71 cycles",
    compare: "Miss P50 = 232 cycles",
    verdict: "TH = 151 cycles"
  },
  1: {
    main: "Hit P50 = 71 cycles",
    compare: "低时延",
    verdict: "Hit"
  },
  2: {
    main: "Miss P50 = 232 cycles",
    compare: "TH = 151 cycles",
    verdict: "Miss"
  },
  3: {
    main: "Set k: VA(M)",
    compare: "2 Set × 2 Way",
    verdict: "Prime"
  },
  4: {
    main: "Probe Δ ≈ 161 cycles",
    compare: "Set k ↑",
    verdict: "Leak"
  },
  5: {
    main: "TX ≈ RX",
    compare: "BAC ≈ 100%",
    verdict: "Secret bit"
  }
};

function parseTlbAttackOutput(output = "") {
  const lines = stripAnsi(output).split("\n");
  const steps = new Map();
  const relation = {};
  let relationSection = false;
  let stageIndex = -1;
  let sid = null;
  let calibration = null;
  let demo = null;
  let tx = "";
  let rx = "";

  lines.forEach((line) => {
    const text = line.trim();
    if (!text) return;
    if (/^RELATION\b/i.test(text)) {
      relationSection = true;
      return;
    }
    if (/^SYNC\b|^===\s*STEP5\b/i.test(text)) relationSection = false;

    const step = text.match(/^STEP(\d+)\s+(.+?)\s+avg=(-?\d+)\s+cyc,\s+min=(-?\d+),\s+p50=(-?\d+),\s+p90=(-?\d+)/i);
    if (step) {
      const number = Number(step[1]);
      stageIndex = Math.max(stageIndex, number);
      steps.set(number, {
        label: step[2],
        avg: Number(step[3]),
        min: Number(step[4]),
        p50: Number(step[5]),
        p90: Number(step[6])
      });
    }
    if (/^===\s*STEP5\b/i.test(text)) stageIndex = Math.max(stageIndex, 5);

    const sidMatch = text.match(/SID\(parent\/child\)=(-?\d+)\/(-?\d+)/i);
    if (sidMatch) sid = { parent: Number(sidMatch[1]), child: Number(sidMatch[2]) };
    const syncMatch = text.match(/parent_sid=(-?\d+)\s+child_sid\(last\)=(-?\d+)/i);
    if (syncMatch) sid = { parent: Number(syncMatch[1]), child: Number(syncMatch[2]) };

    const cal = text.match(/^CAL:\s*hit_p50=(-?\d+)\s+miss_p50=(-?\d+)\s+threshold=(-?\d+)/i);
    if (cal) calibration = { hitP50: Number(cal[1]), missP50: Number(cal[2]), threshold: Number(cal[3]) };

    const demoMatch = text.match(/^DEMO:\s*bits=(\d+)\s+BER=([\d.]+)%\s+BAC=([\d.]+)%/i);
    if (demoMatch) demo = { bits: Number(demoMatch[1]), ber: Number(demoMatch[2]), bac: Number(demoMatch[3]) };

    const bits = text.match(/^(tx|rx)\[[^\]]+\]:\s*([01]+)/i);
    if (bits) {
      if (bits[1].toLowerCase() === "tx") tx = bits[2];
      if (bits[1].toLowerCase() === "rx") rx = bits[2];
    }

    if (relationSection) {
      const relationMatch = text.match(/^(.+?)\s*=\s*(-?\d+)\s*$/);
      if (relationMatch) relation[relationMatch[1].trim()] = Number(relationMatch[2]);
    }
  });

  const idleThrashDelta = Object.entries(relation).find(([label]) => /switch\+thrash\+load\)\s*-\s*\(switch\+idle\+load\)/i.test(label))?.[1] ?? null;
  const th = Object.entries(relation).find(([label]) => /local_miss\s*-\s*local_hit/i.test(label))?.[1] ?? null;
  const hitP50 = calibration?.hitP50 ?? steps.get(1)?.p50 ?? null;
  const missP50 = calibration?.missP50 ?? steps.get(2)?.p50 ?? null;
  const threshold = calibration?.threshold ?? (hitP50 !== null && missP50 !== null ? Math.round((hitP50 + missP50) / 2) : null);
  var idle = steps.get(3)?.p50 ?? null;
  var thrash = steps.get(4)?.p50 ?? null;

  return {
    hasOutput: /(?:^|\n)(?:===\s*Step-by-step TLB|CONFIG:|STEP\d+\b|RELATION\b)/im.test(stripAnsi(output)),
    stageIndex,
    steps,
    relation,
    sid,
    hitP50,
    missP50,
    threshold,
    idleThrashDelta,
    th,
    idle,
    thrash,
    demo,
    tx,
    rx,
    success: Boolean(demo && demo.bac >= 99.99 && tx && rx)
  };
}

function resultByCommandKey(commandKey) {
  var results = state.resultsByCommand || {};
  var target = currentTarget();
  var protection = target?.protection || "";
  for (var key in results) {
    var entry = results[key];
    if (entry.commandKey === commandKey && entry.protection === protection) return entry;
  }
  return null;
}

function tlbAttackOutput() {
  var result = resultByCommandKey("runTlbAttack");
  if (result?.status === "captured") return result.output || "";
  var latest = state.latestResult;
  if (latest?.commandKey === "runTlbAttack" && latest.status === "captured") return latest.output || "";
  var raw = state.terminalText || latest?.output || "";
  var start = raw.search(/(?:^|\n)(?:===\s*Step-by-step TLB|CONFIG:|STEP\d+\b)/i);
  return start >= 0 ? raw.slice(start).trimStart() : "";
}

function tlbProtectedRx() {
  var result = resultByCommandKey("runTlbAttackProtected");
  if (result?.status === "captured") {
    var parsed = parseTlbAttackOutput(result.output || "");
    return parsed.rx;
  }
  return "";
}

function renderTlbAttackView() {
  const outputNode = $("#tlbAttackOutput");
  if (!outputNode) return;
  const parsed = parseTlbAttackOutput(tlbAttackOutput());
  const availableStage = 5;
  state.tlbAttackGuideStep = Math.min(5, Math.max(0, state.tlbAttackGuideStep));
  const stage = state.tlbAttackGuideStep;
  const connected = Boolean(state.sshSession?.connected);
  const target = currentTarget();
  const isTlb = connected && target?.protection === "tlb";
  const collecting = state.latestResult?.status === "running" && (state.latestResult?.commandKey === "runTlbAttack" || state.latestResult?.commandKey === "runTlbAttackProtected");

  outputNode.textContent = tlbAttackOutput() || "等待 TLB 攻击脚本输出...";
  outputNode.scrollTop = outputNode.scrollHeight;
  setText("#tlbAttackTarget", isTlb ? `${target.label || target.name} / ${target.host}` : "未配置 TLB FPGA");
  setBadge($("#tlbAttackStageBadge"), parsed.hasOutput ? "good" : "idle", parsed.hasOutput ? `演示 ${stage + 1} · ${tlbAttackStageLabels[stage] || "攻击输出"}` : "静态演示");
  setBadge($("#tlbAttackVerdict"), parsed.success ? "bad" : parsed.demo ? "warn" : "muted", parsed.success ? "无防护攻击成功" : parsed.demo ? "等待结果确认" : "等待真实输出");

  setBadge($("#tlbSharingBadge"), parsed.sid ? "warn" : "muted", parsed.sid ? `SID ${parsed.sid.parent} / ${parsed.sid.child}` : "等待共享观测");

  $("#runTlbAttackBtn").disabled = !isTlb || collecting;
  $("#runTlbAttackBtn").textContent = collecting ? "攻击执行中..." : "启动TLB攻击";
  $("#tlbGuidePrevBtn").disabled = stage <= 0;
  $("#tlbGuideNextBtn").disabled = stage >= availableStage;
  $$("#tlbAttackStageList li").forEach((item) => {
    const itemStage = Number(item.dataset.tlbStage);
    const active = itemStage === 3 ? stage >= 3 && stage < 5 : itemStage === 5 ? stage >= 5 : stage === itemStage;
    const done = itemStage === 3 ? stage >= 5 : stage > itemStage;
    item.classList.toggle("active", active);
    item.classList.toggle("done", done);
  });
  $("#tlbAttackExplanation").textContent = tlbAttackExplanations[stage] || tlbAttackExplanations[0];

  const sample = tlbAttackStaticSamples[stage] || tlbAttackStaticSamples[0];
  const sampleMain = {
    1: parsed.hitP50 === null ? sample.main : `Hit P50 = ${parsed.hitP50} cycles`,
    2: parsed.missP50 === null ? sample.main : `Miss P50 = ${parsed.missP50} cycles`,
    3: parsed.sid ? `SID parent / child = ${parsed.sid.parent} / ${parsed.sid.child}` : sample.main,
    4: parsed.idleThrashDelta === null ? sample.main : `Idle / Thrash Δ = ${parsed.idleThrashDelta} cycles`,
    5: parsed.demo ? `BAC = ${parsed.demo.bac.toFixed(1)}%` : sample.main
  }[stage] || sample.main;
  const sampleCompare = {
    2: parsed.threshold === null ? sample.compare : `TH = ${parsed.threshold} cycles`,
    5: parsed.demo ? `BER = ${parsed.demo.ber.toFixed(1)}%` : sample.compare
  }[stage] || sample.compare;
  setText("#tlbDemoMetricMain", sampleMain);
  setText("#tlbDemoMetricCompare", sampleCompare);
  setText("#tlbDemoMetricVerdict", sample.verdict);

  setText("#tlbHitP50", parsed.hitP50 === null ? "--" : `${parsed.hitP50}`);
  setText("#tlbMissP50", parsed.missP50 === null ? "--" : `${parsed.missP50}`);
  setText("#tlbTH", parsed.th === null ? "--" : `${parsed.th}`);
  renderTlbBits(parsed.tx, parsed.rx, tlbProtectedRx());

  const diagram = $(".tlb-attack-diagram");
  if (diagram) {
    diagram.dataset.guideStage = String(stage);
    setText("#tlbDiagramState", ({
      0: "cycles baseline",
      1: "VA hit",
      2: "VA miss",
      3: "Prime Set k",
      4: "Probe Δt",
      5: "Secret bit"
    })[stage] || "TLB 攻击原理");
  }
}

function appendTerminal(text) {
  state.terminalText += stripAnsi(text);
  if (state.terminalText.length > 120000) {
    state.terminalText = state.terminalText.slice(-120000);
  }
  const node = $("#terminalOutput");
  node.textContent = state.terminalText || "等待远程终端输出...";
  node.scrollTop = node.scrollHeight;
  renderTlbAttackView();
}

function currentTarget() {
  return state.sshSession?.target || null;
}

function targetKindLabel(target) {
  if (!target) return "--";
  if (target.kind === "remote-wsl") return "FPGA SSH";
  if (target.protection === "cache") return "FPGA SSH";
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
  const select = $("#targetSelect");
  const previousValue = select.value;
  select.innerHTML = state.targets
    .map((target) => `<option value="${escapeHtml(target.name)}">${escapeHtml(target.label || target.name)}</option>`)
    .join("");
  if (state.targets.some((target) => target.name === previousValue)) select.value = previousValue;
  renderTargetEditor();
  renderOverview();
}

function selectedTarget() {
  const targetName = $("#targetSelect")?.value;
  return state.targets.find((target) => target.name === targetName) || null;
}

function renderTargetEditor() {
  const target = selectedTarget();
  if (!target) return;
  $("#targetLabelInput").value = target.label || target.name;
  $("#targetHostInput").value = target.host || "";
  $("#targetPortInput").value = target.port || 22;
  $("#targetUsernameInput").value = target.username || "";
  $("#targetPasswordInput").value = "";
  $("#targetWorkdirInput").value = target.workingDirectory || "";
  $("#targetPasswordInput").placeholder = target.usesPassword ? "留空则保留原密码" : "请输入 SSH 密码";
}

function targetConfigPayload() {
  return {
    targetName: $("#targetSelect").value,
    label: $("#targetLabelInput").value,
    host: $("#targetHostInput").value,
    port: $("#targetPortInput").value,
    username: $("#targetUsernameInput").value,
    password: $("#targetPasswordInput").value,
    workingDirectory: $("#targetWorkdirInput").value
  };
}

async function saveTargetConfig() {
  const selectedName = $("#targetSelect").value;
  const payload = await apiPost("/api/fpga/targets/update", targetConfigPayload());
  state.targets = payload.targets || state.targets;
  renderTargets();
  $("#targetSelect").value = selectedName;
  renderTargetEditor();
  if (payload.session) setStatus(payload.session);
  return payload;
}

function setStatus(session = {}) {
  state.sshSession = session;
  const connected = Boolean(session.connected);
  const target = session.target;
  const remoteLabel = session.status === "connecting" ? "远程配置中..." : "远程未配置";
  const label = connected ? `${protectionLabel(target)} 已连接` : remoteLabel;
  setPill($("#sshStatus"), connected ? "online" : "offline", label);
  $("#sideStatus").textContent = connected ? protectionLabel(target) : "未配置";
  setBadge($("#sshBadge"), connected ? "good" : "muted", connected ? "已连接" : "未配置");
  renderConnectionAction();
  renderProtectedState();
  renderTlbAttackView();
  renderOverview();
}

function renderConnectionAction() {
  const button = $("#connectBtn");
  if (!button) return;
  const connected = Boolean(state.sshSession?.connected);
  const connecting = state.sshSession?.status === "connecting";
  button.className = `btn ${connected ? "danger-soft" : "primary"}`;
  button.textContent = connected ? "断开连接" : connecting ? "配置中..." : "配置";
  button.disabled = connecting;
}

async function toggleConnection() {
  if (state.sshSession?.connected) {
    setStatus(await apiPost("/api/fpga/ssh/disconnect"));
    toast("当前连接已断开");
    return;
  }

  const targetName = $("#targetSelect").value;
  await saveTargetConfig();
  const session = await apiPost("/api/fpga/ssh/connect", { targetName });
  setStatus(session);
  toast(session.connected ? "目标已连接" : "连接请求已发送");
}

async function switchConnectionTarget() {
  const session = state.sshSession;
  const hasActiveSession = session?.target && !["idle", "closed"].includes(session.status);
  if (hasActiveSession) {
    setStatus(await apiPost("/api/fpga/ssh/disconnect"));
    toast("已断开原目标");
  }
  renderTargetEditor();
}

function renderOverview() {
  const latest = state.latestResult;
  const connected = Boolean(state.sshSession?.connected);
  const target = currentTarget();

  $("#overviewBackend").textContent = $("#backendMini")?.textContent || "检查中";
  $("#overviewActiveTarget").textContent = connected ? `${protectionLabel(target)} / ${target?.host || "--"}` : "未配置";
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
  const protection = connected ? target?.protection : null;
  const collecting = state.latestResult?.status === "running";
  $("#protectedActiveTarget").textContent = connected ? `${target?.label || target?.name} / ${target?.host}` : "未配置";
  $("#protectedConnectionKind").textContent = connected ? targetKindLabel(target) : "--";
  $("#terminalInput").disabled = !connected;
  $("#terminalForm button[type='submit']").disabled = !connected;
  const targetName = protection === "cache" ? "Cache" : protection === "tlb" ? "TLB" : "设备";
  const securityKey = protection === "cache" ? "runCacheSecurity" : "runProtectionTest";
  const performanceKey = protection === "cache" ? "runCacheEffectiveness" : "runPerformanceTest";
  var collectingLabel = "";
  if (collecting) {
    var cmd = state.latestResult?.commandKey;
    if (cmd === securityKey) collectingLabel = `${targetName} 安全采集中...`;
    else if (cmd === performanceKey) collectingLabel = `${targetName} 性能采集中...`;
    else collectingLabel = `${targetName} 采集中...`;
  }
  $("#runCollectionBtn").disabled = !connected || collecting;
  $("#runCollectionBtn").textContent = collecting ? collectingLabel : `采集 ${targetName} 结果`;
}

function collectionCommandKey(category) {
  const protection = currentTarget()?.protection;
  if (category === "security") return protection === "cache" ? "runCacheSecurity" : "runProtectionTest";
  return protection === "cache" ? "runCacheEffectiveness" : "runPerformanceTest";
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

function renderCacheHeatmap(heatmap) {
  const svg = $("#cacheHeatmap");
  if (!svg) return;
  const badge = $("#cacheHeatmapBadge");
  const result = $("#cacheHeatmapResult");
  const ns = "http://www.w3.org/2000/svg";
  svg.replaceChildren();

  const width = 760;
  const height = 380;
  const padding = { left: 64, right: 24, top: 24, bottom: 48 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  const add = (tag, attrs = {}) => {
    const node = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    svg.appendChild(node);
    return node;
  };

  add("rect", { x: 0, y: 0, width, height, rx: 8, fill: "#fbfcf8" });

  if (!heatmap?.values?.length) {
    add("text", {
      x: width / 2,
      y: height / 2,
      "text-anchor": "middle",
      fill: "#657064",
      "font-size": 18,
      "font-weight": 800
    }).textContent = "等待 output.csv 采样数据";
    setBadge(badge, "muted", "等待 output.csv");
    if (result) result.textContent = "等待 Mallory 生成 output.csv";
    return;
  }

  const rows = heatmap.values;
  const rowCount = heatmap.rows || rows.length;
  const colCount = heatmap.cols || Math.max(...rows.map((row) => row.length));
  const min = Number.isFinite(heatmap.min) ? heatmap.min : Math.min(...rows.flat().filter(Number.isFinite));
  const max = Number.isFinite(heatmap.max) ? heatmap.max : Math.max(...rows.flat().filter(Number.isFinite));
  const span = Math.max(1, max - min);
  const cellWidth = plotWidth / colCount;
  const cellHeight = plotHeight / rowCount;

  add("text", { x: padding.left, y: 16, fill: "#657064", "font-size": 11, "font-weight": 800 }).textContent = "Cache Set";
  add("text", { x: width - padding.right, y: height - 12, fill: "#657064", "font-size": 11, "font-weight": 800, "text-anchor": "end" }).textContent = "测试输入";

  rows.forEach((row, y) => {
    row.forEach((value, x) => {
      if (!Number.isFinite(value)) return;
      const t = Math.max(0, Math.min(1, (value - min) / span));
      let l, c, h;
      if (t < 0.5) {
        const s = t / 0.5;
        l = 44 + s * 50;
        c = 0.15 - s * 0.13;
        h = 265;
      } else {
        const s = (t - 0.5) / 0.5;
        l = 94 - s * 50;
        c = 0.02 + s * 0.13;
        h = 28;
      }
      add("rect", {
        x: padding.left + x * cellWidth,
        y: padding.top + y * cellHeight,
        width: Math.max(0.5, cellWidth + 0.2),
        height: Math.max(0.5, cellHeight + 0.2),
        fill: `oklch(${l}% ${c} ${h})`
      });
    });
  });

  for (let i = 0; i <= 4; i += 1) {
    const y = padding.top + (plotHeight * i) / 4;
    add("line", { x1: padding.left - 4, y1: y, x2: padding.left, y2: y, stroke: "#aeb8ac", "stroke-width": 1 });
    add("text", { x: padding.left - 10, y: y + 4, fill: "#657064", "font-size": 10, "text-anchor": "end" }).textContent = Math.round((rowCount * i) / 4);
  }

  for (let i = 0; i <= 4; i += 1) {
    const x = padding.left + (plotWidth * i) / 4;
    add("line", { x1: x, y1: padding.top + plotHeight, x2: x, y2: padding.top + plotHeight + 4, stroke: "#aeb8ac", "stroke-width": 1 });
    add("text", { x, y: padding.top + plotHeight + 20, fill: "#657064", "font-size": 10, "text-anchor": "middle" }).textContent = Math.round((colCount * i) / 4);
  }

  add("rect", { x: padding.left, y: padding.top, width: plotWidth, height: plotHeight, fill: "none", stroke: "#d7ded4", "stroke-width": 1 });
  setBadge(badge, "good", `${rowCount} × ${colCount} 采样矩阵`);
  if (result) result.textContent = `已载入 output.csv，采样范围 ${min} 到 ${max}`;
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
  $("#recoveredKey").textContent = session.recoveredKey || session.recoveredKeyPartial || "--";
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

  const failed = phase.endsWith("failed") || phase === "key-mismatch";
  const statusClass = failed ? "offline" : session.eveReady ? "done" : "idle";
  setPill($("#unprotectedStatus"), statusClass, `攻击演示 ${phaseText}`);

  const badge = $("#unprotectedPhaseBadge");
  badge.textContent = phaseText;
  badge.className = `badge ${failed || session.recoveredKeyValid === false ? "bad" : session.recoveredKeyValid ? "done" : "idle"}`;

  setTimelineDone("start", active);
  setTimelineDone("send", active && Boolean(session.lastMessage));
  setTimelineDone("recover", ["recovering", "key-recovered", "key-mismatch", "eavesdropping", "message-recovered", "decrypt-failed"].includes(phase));
  setTimelineDone("key", session.recoveredKeyValid === true);
  setTimelineDone("eve", active && Boolean(session.eveReady));
  setTimelineDone("result", phase === "message-recovered");
  renderCacheHeatmap(session.cacheHeatmap);
  renderOverview();
}

function clearUnprotectedLogs() {
  $("#logAlice").textContent = "[idle] 等待发送消息";
  $("#logBob").textContent = "[idle] 等待 Bob 解密输出";
  $("#logMallory").textContent = "[idle] 等待 Prime+Probe 输出";
  $("#logEve").textContent = "[idle] 等待窃听输出";
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
  } else if (entry.role === "eve") {
    appendLog("#logEve", text);
  } else {
    appendLog("#logMallory", text);
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
    interrupted: { label: "采集已中断", className: "bad" },
    failed: { label: "采集失败", className: "bad" },
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
  renderTlbAttackView();
  renderOverview();

  if (state.collectionChain && result && result.status === "captured") {
    var nextKey = state.collectionChain.next;
    var targetLabel = state.collectionChain.label;
    state.collectionChain = null;
    apiPost("/api/fpga/run/preset", { commandKey: nextKey }).then(function (payload) {
      setStatus(payload);
      renderResultPayload(payload);
      toast(`已开始${targetLabel}`);
    });
  }
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

  $("#targetSelect").addEventListener("change", () => safeAction(switchConnectionTarget));

  $("#targetConfigForm").addEventListener("submit", (event) => {
    event.preventDefault();
    safeAction(toggleConnection);
  });

  $("#connectBtn").addEventListener("click", () => safeAction(toggleConnection));

  $("#runTlbAttackBtn").addEventListener("click", () => safeAction(async () => {
    state.collectionChain = { next: "runTlbAttackProtected", label: "TLB 加固攻击采集" };
    const payload = await apiPost("/api/fpga/run/preset", { commandKey: "runTlbAttack" });
    setStatus(payload);
    renderResultPayload(payload);
    toast("已启动 TLB 无防护攻击 → 完成后自动执行加固攻击");
  }));

  $("#tlbGuidePrevBtn").addEventListener("click", () => {
    state.tlbAttackGuideStep = Math.max(0, state.tlbAttackGuideStep - 1);
    renderTlbAttackView();
  });

  $("#tlbGuideNextBtn").addEventListener("click", () => {
    state.tlbAttackGuideStep = Math.min(5, state.tlbAttackGuideStep + 1);
    renderTlbAttackView();
  });
  $$("#tlbAttackStageList li").forEach((item) => {
    item.addEventListener("click", () => {
      state.tlbAttackGuideStep = Number(item.dataset.tlbStage || 0);
      renderTlbAttackView();
    });
  });

  $("#copyTlbAttackBtn").addEventListener("click", () => safeAction(async () => {
    await navigator.clipboard.writeText($("#tlbAttackOutput").textContent);
    toast("TLB 攻击输出已复制");
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
    toast("攻击演示已启动");
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
    toast("攻击演示已停止");
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

  $("#runCollectionBtn").addEventListener("click", () => safeAction(async () => {
    const securityKey = collectionCommandKey("security");
    const performanceKey = collectionCommandKey("performance");
    state.collectionChain = { next: performanceKey, label: `${protectionLabel(currentTarget())} 性能采集` };
    const payload = await apiPost("/api/fpga/run/preset", { commandKey: securityKey });
    setStatus(payload);
    renderResultPayload(payload);
    toast(`已开始${protectionLabel(currentTarget())}安全采集 → 完成后自动执行性能采集`);
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
  const connected = Boolean(state.sshSession?.connected);
  const protection = state.activePage.startsWith("cache-") || state.activePage.startsWith("tlb-")
    ? activeProtectionContext()
    : connected ? currentTarget()?.protection : null;
  const empty = $("#compareEmptyState");
  const tlbSection = $("#tlbReportSection");
  const cacheSection = $("#cacheReportSection");

  if (empty) empty.hidden = Boolean(protection);
  if (tlbSection) tlbSection.hidden = protection !== "tlb";
  if (cacheSection) cacheSection.hidden = protection !== "cache";

  if (protection === "cache") {
    buildCacheCharts(parsed.cache).forEach(drawChart);
    updateCacheReport(parsed);
    return;
  }

  if (protection === "tlb") {
    Object.values(buildReportCharts(parsed)).forEach(drawChart);
    drawChart(buildTlbSecurityChart(parsed));
    updateReportBadges(parsed);
    setBadge(
      $("#tlbSecurityBadge"),
      parsed.partition.length ? "good" : "muted",
      parsed.partition.length ? "已有采集数据" : "等待采集"
    );
    updatePerformanceSummary(parsed);
    drawOverheadRings(parsed);
    setBadge($("#tlbReportStatus"), parsed.process.size || parsed.thread.size || parsed.hackbench.size ? "good" : "muted", parsed.process.size || parsed.thread.size || parsed.hackbench.size ? "已有采集数据" : "等待采集");
    return;
  }
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
  const light = $("#partitionStatusLight");
  if (light) {
    light.className = `status-light ${parsed.partition.length ? (partitionOk ? "good" : "bad") : ""}`;
  }
  setText(
    "#summaryPartitionNote",
    parsed.partition.length ? `最大中位偏移 ${formatChartNumber(partitionMaxDelta)} cyc` : "SID 分离状态与 TLB 扰动幅度"
  );

  updateOverheadSummary(
    "#summaryProcessValue",
    "#summaryProcessNote",
    fixedReportData.processSwitch.baseline,
    parsed.process.size ? realValuesFromMap(parsed.process, fixedReportData.processSwitch.categories, fixedReportData.processSwitch.baseline, fixedReportData.processSwitch.protectedFixed) : PROCESS_SWITCH_PRESET
  );
  updateOverheadSummary(
    "#summaryThreadValue",
    "#summaryThreadNote",
    fixedReportData.threadSwitch.baseline,
    parsed.thread.size ? realValuesFromMap(parsed.thread, fixedReportData.threadSwitch.categories, fixedReportData.threadSwitch.baseline, fixedReportData.threadSwitch.protectedFixed) : THREAD_SWITCH_PRESET
  );
  updateOverheadSummary(
    "#summaryHackbenchValue",
    "#summaryHackbenchNote",
    fixedReportData.hackbench.baseline,
    parsed.hackbench.size ? realValuesFromMap(parsed.hackbench, fixedReportData.hackbench.categories, fixedReportData.hackbench.baseline, fixedReportData.hackbench.protectedFixed) : HACKBENCH_PRESET
  );
}

function overheadValues(baseline, realValues) {
  return realValues
    .map((value, index) => {
      if (!Number.isFinite(value) || !Number.isFinite(baseline[index]) || baseline[index] === 0) return null;
      const flooredValue = Math.max(value, baseline[index]);
      return Math.max(0, ((flooredValue - baseline[index]) / baseline[index]) * 100);
    })
    .filter((value) => Number.isFinite(value));
}

function average(values) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
}

function drawOverheadRings(parsed) {
  drawOverheadRing(
    "#processRingChart",
    average(overheadValues(
      fixedReportData.processSwitch.baseline,
      parsed.process.size ? realValuesFromMap(parsed.process, fixedReportData.processSwitch.categories, fixedReportData.processSwitch.baseline, fixedReportData.processSwitch.protectedFixed) : PROCESS_SWITCH_PRESET
    ))
  );
  drawOverheadRing(
    "#threadRingChart",
    average(overheadValues(
      fixedReportData.threadSwitch.baseline,
      parsed.thread.size ? realValuesFromMap(parsed.thread, fixedReportData.threadSwitch.categories, fixedReportData.threadSwitch.baseline, fixedReportData.threadSwitch.protectedFixed) : THREAD_SWITCH_PRESET
    ))
  );
  drawOverheadRing(
    "#hackbenchRingChart",
    average(overheadValues(
      fixedReportData.hackbench.baseline,
      parsed.hackbench.size ? realValuesFromMap(parsed.hackbench, fixedReportData.hackbench.categories, fixedReportData.hackbench.baseline, fixedReportData.hackbench.protectedFixed) : HACKBENCH_PRESET
    ))
  );
}

function drawOverheadRing(selector, percent) {
  const svg = $(selector);
  if (!svg) return;
  const ns = "http://www.w3.org/2000/svg";
  svg.replaceChildren();

  const add = (tag, attrs = {}, text = "") => {
    const node = document.createElementNS(ns, tag);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    if (text) node.textContent = text;
    svg.appendChild(node);
    return node;
  };

  const value = Number.isFinite(percent) ? percent : null;
  const magnitude = value === null ? 0 : Math.min(1, Math.abs(value) / 100);
  const radius = 54;
  const circumference = Math.PI * 2 * radius;
  const color = value === null ? "#9aa49a" : Math.abs(value) <= 5 ? chartColors.protected : Math.abs(value) <= 15 ? chartColors.protected : "#b23a32";

  add("circle", { cx: 80, cy: 80, r: radius, fill: "none", stroke: "#d7ded4", "stroke-width": 14 });
  add("circle", {
    cx: 80,
    cy: 80,
    r: radius,
    fill: "none",
    stroke: color,
    "stroke-width": 14,
    "stroke-linecap": "round",
    "stroke-dasharray": `${circumference * magnitude} ${circumference}`,
    transform: "rotate(-90 80 80)"
  });
  add("text", { x: 80, y: 76, "text-anchor": "middle", fill: "#20251f", "font-size": 18, "font-weight": 900 }, value === null ? "--" : formatPercent(value));
  add("text", { x: 80, y: 96, "text-anchor": "middle", fill: "#657064", "font-size": 10, "font-weight": 800 }, "avg");
}

function updateOverheadSummary(valueSelector, noteSelector, baseline, realValues) {
  const overheads = overheadValues(baseline, realValues);
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
  } else if (config.type === "partition-bar") {
    drawPartitionBarChart(config);
  } else if (config.type === "zero-delta") {
    drawZeroDeltaChart(config);
  } else if (config.type === "combo") {
    drawComboChart(config);
  } else if (config.type === "sparkline") {
    drawSparklineChart(config);
  } else if (config.type === "value-line") {
    drawValueLineChart(config);
  } else {
    drawGroupedBarChart(config);
  }
}

function createChartContext(config, options = {}) {
  const svg = $(config.selector);
  if (!svg) return null;

  const ns = "http://www.w3.org/2000/svg";
  const viewBoxValue = svg.getAttribute("viewBox");
  const viewBox = viewBoxValue.split(/\s+/).map(Number);
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

function drawGrid(ctx, unit, minValue, maxValue, ticks = 4, skipBottom = false) {
  const { width, height, padding, plotHeight, add } = ctx;
  for (let i = 0; i <= ticks; i += 1) {
    const y = padding.top + (plotHeight / ticks) * i;
    const value = maxValue - ((maxValue - minValue) / ticks) * i;
    add("line", { x1: padding.left, y1: y, x2: width - padding.right, y2: y, stroke: "#d3dbd0", "stroke-width": 1 });
    add("text", { x: padding.left - 10, y: y + 4, "text-anchor": "end", fill: "#657064", "font-size": 11 }, formatChartNumber(value));
  }
  if (!skipBottom) {
    add("line", { x1: padding.left, y1: height - padding.bottom, x2: width - padding.right, y2: height - padding.bottom, stroke: "#869283", "stroke-width": 1.2 });
  }
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

function insetCategoryX(ctx, categories, index, insetRatio = 0.06) {
  if (categories.length <= 1) return ctx.padding.left + ctx.plotWidth / 2;
  const inset = ctx.plotWidth * insetRatio;
  const availableWidth = ctx.plotWidth - inset * 2;
  return ctx.padding.left + inset + (availableWidth / (categories.length - 1)) * index;
}

function drawCategoryLabels(ctx, categories, options = {}) {
  categories.forEach((category, index) => {
    const x = options.inset ? insetCategoryX(ctx, categories, index, options.insetRatio) : categoryX(ctx, categories, index);
    const edgeAware = Boolean(options.edgeAware);
    const textAnchor = edgeAware && index === 0
      ? "start"
      : edgeAware && index === categories.length - 1
        ? "end"
        : "middle";
    ctx.add("text", {
      x,
      y: ctx.height - 24,
      "text-anchor": textAnchor,
      fill: "#20251f",
      "font-size": 12,
      "font-weight": 700
    }, category);
  });
}

function drawLegend(ctx, series) {
  const legendColumns = series.length > 3 ? 2 : Math.max(1, series.length);
  const legendItemWidth = series.length > 3 ? 138 : 96;
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
      .map((value, index) => Number.isFinite(value) ? [insetCategoryX(ctx, config.categories, index), valueToY(ctx, value, minValue, maxValue), value] : null)
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

  drawCategoryLabels(ctx, config.categories, { edgeAware: true, inset: true });
  drawLegend(ctx, config.series.map((item) => ({ ...item, legendShape: "line" })));
}

function drawPartitionBarChart(config) {
  const ctx = createChartContext(config, { padding: { top: 58, right: 36, bottom: 58, left: 66 } });
  if (!ctx) return;
  const hasData = config.series.some((series) => series.values.some((value) => Number.isFinite(value)));
  const series = hasData
    ? config.series
    : [{ name: "delta_p50 median", color: "#9aa49a", values: config.fallbackValues || config.categories.map(() => 0) }];
  const values = series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const magnitude = hasData ? Math.max(5, ...values.map((value) => Math.abs(value))) * 1.45 : 7;
  const minValue = -magnitude;
  const maxValue = magnitude;
  const zeroY = valueToY(ctx, 0, minValue, maxValue);
  const safeTop = valueToY(ctx, 5, minValue, maxValue);
  const safeBottom = valueToY(ctx, -5, minValue, maxValue);
  const categoryWidth = ctx.plotWidth / config.categories.length;
  const barGap = hasData ? 8 : 0;
  const seriesCount = Math.max(1, series.length);
  const barWidth = Math.max(34, Math.min(72, (categoryWidth * 0.34 - barGap * (seriesCount - 1)) / seriesCount));

  drawGrid(ctx, config.unit, minValue, maxValue);
  ctx.add("line", { x1: ctx.padding.left, y1: safeTop, x2: ctx.width - ctx.padding.right, y2: safeTop, stroke: "#8bc28b", "stroke-width": 1, "stroke-dasharray": "4 7" });
  ctx.add("line", { x1: ctx.padding.left, y1: safeBottom, x2: ctx.width - ctx.padding.right, y2: safeBottom, stroke: "#8bc28b", "stroke-width": 1, "stroke-dasharray": "4 7" });
  ctx.add("line", { x1: ctx.padding.left, y1: zeroY, x2: ctx.width - ctx.padding.right, y2: zeroY, stroke: "#2d7a35", "stroke-width": 1.4 });

  config.categories.forEach((category, categoryIndex) => {
    const centerX = ctx.padding.left + categoryWidth * categoryIndex + categoryWidth / 2;
    series.forEach((item, seriesIndex) => {
      const value = item.values[categoryIndex];
      if (!Number.isFinite(value)) return;
      const x = centerX - (seriesCount * barWidth + (seriesCount - 1) * barGap) / 2 + seriesIndex * (barWidth + barGap);
      if (!hasData) {
        ctx.add("rect", {
          x,
          y: zeroY - 18,
          width: barWidth,
          height: 36,
          rx: 4,
          fill: "none",
          stroke: "#aeb8ac",
          "stroke-width": 1.4,
          "stroke-dasharray": "5 5"
        });
        return;
      }
      const y = valueToY(ctx, value, minValue, maxValue);
      const barY = Math.min(y, zeroY);
      const barHeight = Math.max(2, Math.abs(zeroY - y));
      const labelY = value < 0 ? zeroY + barHeight + 16 : y - 8;
      ctx.add("rect", { x, y: barY, width: barWidth, height: barHeight, rx: 3, fill: item.color, opacity: 0.9 });
      ctx.add("text", { x: x + barWidth / 2, y: labelY, "text-anchor": "middle", fill: "#20251f", "font-size": 11, "font-weight": 800 }, formatChartNumber(value));
    });
    ctx.add("text", {
      x: centerX,
      y: ctx.height - 24,
      "text-anchor": "middle",
      fill: "#20251f",
      "font-size": 12,
      "font-weight": 700
    }, category);
  });

  if (hasData) {
    drawLegend(ctx, series.map((item) => ({ ...item, legendShape: "bar" })));
  } else {
    ctx.add("text", { x: ctx.width / 2, y: ctx.padding.top - 18, "text-anchor": "middle", fill: "#657064", "font-size": 13, "font-weight": 800 }, "等待防护有效性采集");
  }
}

function drawZeroDeltaChart(config) {
  const ctx = createChartContext(config, { padding: { top: 58, right: 36, bottom: 58, left: 66 } });
  if (!ctx) return;
  const values = config.series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const magnitude = Math.max(5, ...values.map((value) => Math.abs(value))) * 1.45;
  const minValue = -magnitude;
  const maxValue = magnitude;
  drawGrid(ctx, config.unit, minValue, maxValue);

  const zeroY = valueToY(ctx, 0, minValue, maxValue);
  const safeTop = valueToY(ctx, 5, minValue, maxValue);
  const safeBottom = valueToY(ctx, -5, minValue, maxValue);
  ctx.add("line", { x1: ctx.padding.left, y1: safeTop, x2: ctx.width - ctx.padding.right, y2: safeTop, stroke: "#8bc28b", "stroke-width": 1, "stroke-dasharray": "4 7" });
  ctx.add("line", { x1: ctx.padding.left, y1: safeBottom, x2: ctx.width - ctx.padding.right, y2: safeBottom, stroke: "#8bc28b", "stroke-width": 1, "stroke-dasharray": "4 7" });
  ctx.add("line", { x1: ctx.padding.left, y1: zeroY, x2: ctx.width - ctx.padding.right, y2: zeroY, stroke: "#2d7a35", "stroke-width": 1.6 });

  const categoryWidth = ctx.plotWidth / config.categories.length;
  const barWidth = Math.max(28, Math.min(72, categoryWidth * 0.28));
  config.series.forEach((series) => {
    series.values.forEach((value, index) => {
      if (!Number.isFinite(value)) return;
      const x = ctx.padding.left + categoryWidth * index + categoryWidth / 2;
      const y = valueToY(ctx, value, minValue, maxValue);
      const barY = Math.min(y, zeroY);
      const barHeight = Math.max(2, Math.abs(zeroY - y));
      const labelY = value < 0 ? zeroY + barHeight + 16 : y - 8;
      ctx.add("rect", { x: x - barWidth / 2, y: barY, width: barWidth, height: barHeight, rx: 3, fill: series.color, opacity: 0.88 });
      ctx.add("text", { x, y: labelY, "text-anchor": "middle", fill: "#20251f", "font-size": 11, "font-weight": 800 }, formatChartNumber(value));
    });
  });

  if (!config.series.length) {
    ctx.add("text", { x: ctx.width / 2, y: ctx.height / 2, "text-anchor": "middle", fill: "#657064", "font-size": 14, "font-weight": 800 }, "等待防护有效性采集");
  }
  config.categories.forEach((category, index) => {
    const x = ctx.padding.left + categoryWidth * index + categoryWidth / 2;
    ctx.add("text", {
      x,
      y: ctx.height - 24,
      "text-anchor": "middle",
      fill: "#20251f",
      "font-size": 12,
      "font-weight": 700
    }, category);
  });
  if (config.series.length) {
    drawLegend(ctx, config.series.map((item) => ({ ...item, legendShape: "bar" })));
  }
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

function drawSparklineChart(config) {
  const ctx = createChartContext(config, { padding: { top: 42, right: 72, bottom: 54, left: 72 } });
  if (!ctx) return;
  const values = config.series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const maxValue = Math.max(1, ...values) * 1.12;
  const minValue = Math.min(0, ...values) * 0.92;

  for (let i = 0; i <= 2; i += 1) {
    const y = ctx.padding.top + (ctx.plotHeight / 2) * i;
    ctx.add("line", { x1: ctx.padding.left, y1: y, x2: ctx.width - ctx.padding.right, y2: y, stroke: "#d3dbd0", "stroke-width": 1 });
  }
  ctx.add("text", { x: ctx.padding.left, y: 24, fill: "#657064", "font-size": 11, "font-weight": 800 }, config.unit);

  config.series.forEach((series, seriesIndex) => {
    const points = series.values
      .map((value, index) => Number.isFinite(value) ? [insetCategoryX(ctx, config.categories, index), valueToY(ctx, value, minValue, maxValue), value] : null)
      .filter(Boolean);
    if (!points.length) return;
    const path = points.map((point, index) => `${index ? "L" : "M"} ${point[0]} ${point[1]}`).join(" ");
    ctx.add("path", {
      d: path,
      fill: "none",
      stroke: series.color,
      "stroke-width": seriesIndex === 0 ? 2 : 3,
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      opacity: seriesIndex === 0 ? 0.72 : 1
    });
    points.forEach(([x, y, value], index) => {
      ctx.add("circle", { cx: x, cy: y, r: seriesIndex === 0 ? 3.5 : 5, fill: series.color, stroke: "#fbfcf8", "stroke-width": 1.5 });
      if (seriesIndex === config.series.length - 1) {
        ctx.add("text", { x, y: y - 10, "text-anchor": "middle", fill: "#20251f", "font-size": 10, "font-weight": 800 }, formatChartNumber(value));
      }
      if (seriesIndex === 1) {
        const baseValue = config.series[0]?.values[index];
        if (Number.isFinite(baseValue) && baseValue !== 0) {
          const pct = ((value - baseValue) / baseValue) * 100;
          ctx.add("text", { x, y: y + 20, "text-anchor": "middle", fill: series.color, "font-size": 10, "font-weight": 800 }, formatPercent(pct));
        }
      }
    });
  });

  drawCategoryLabels(ctx, config.categories, { edgeAware: true, inset: true });
  drawLegend(ctx, config.series.map((item) => ({ ...item, legendShape: "line" })));
}

function drawValueLineChart(config) {
  const ctx = createChartContext(config, { padding: { top: 48, right: 72, bottom: 58, left: 72 } });
  if (!ctx) return;
  const values = config.series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const maxValue = Math.max(1, ...values) * 1.12;
  const minValue = Math.min(0, ...values) * 0.92;

  drawGrid(ctx, config.unit, minValue, maxValue);

  config.series.forEach((series, seriesIndex) => {
    const points = series.values
      .map((value, index) => Number.isFinite(value) ? [insetCategoryX(ctx, config.categories, index), valueToY(ctx, value, minValue, maxValue), value] : null)
      .filter(Boolean);
    if (!points.length) return;
    const path = points.map((point, index) => `${index ? "L" : "M"} ${point[0]} ${point[1]}`).join(" ");
    ctx.add("path", {
      d: path,
      fill: "none",
      stroke: series.color,
      "stroke-width": seriesIndex === 0 ? 2.4 : 3.2,
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      opacity: seriesIndex === 0 ? 0.78 : 1
    });
    points.forEach(([x, y, value]) => {
      ctx.add("circle", { cx: x, cy: y, r: seriesIndex === 0 ? 4 : 5.5, fill: series.color, stroke: "#fbfcf8", "stroke-width": 1.5 });
      if (seriesIndex === config.series.length - 1) {
        ctx.add("text", { x, y: y - 12, "text-anchor": "middle", fill: "#20251f", "font-size": 11, "font-weight": 800 }, formatChartNumber(value));
      }
    });
  });

  drawCategoryLabels(ctx, config.categories, { edgeAware: true, inset: true });
  drawLegend(ctx, config.series.map((item) => ({ ...item, legendShape: "line" })));
}

function drawGroupedBarChart(config) {
  const ctx = createChartContext(config);
  if (!ctx) return;

  const values = config.series.flatMap((item) => item.values).filter((value) => Number.isFinite(value));
  const maxValue = Math.max(1, ...values, Number.isFinite(config.threshold) ? config.threshold : 0) * 1.18;
  const minValue = config.minValue ?? 0;
  const categoryWidth = ctx.plotWidth / config.categories.length;
  const barGap = 5;
  const seriesCount = Math.max(1, config.series.length);
  const groupPadding = Math.max(16, categoryWidth * 0.16);
  const barWidth = Math.max(7, (categoryWidth - groupPadding * 2 - barGap * (seriesCount - 1)) / seriesCount);

  const skipBottom = minValue < 0;
  drawGrid(ctx, config.unit, minValue, maxValue, 4, skipBottom);

  const zeroY = valueToY(ctx, 0, minValue, maxValue);

  if (skipBottom) {
    ctx.add("line", {
      x1: ctx.padding.left,
      y1: zeroY,
      x2: ctx.width - ctx.padding.right,
      y2: zeroY,
      stroke: "#869283",
      "stroke-width": 1.2
    });
    ctx.add("text", {
      x: ctx.padding.left - 12,
      y: zeroY + 4,
      "text-anchor": "end",
      fill: "#869283",
      "font-size": 11,
      "font-weight": 700
    }, "0");
  }

  if (Number.isFinite(config.threshold)) {
    const thresholdY = valueToY(ctx, config.threshold, minValue, maxValue);
    ctx.add("line", {
      x1: ctx.padding.left,
      y1: thresholdY,
      x2: ctx.width - ctx.padding.right,
      y2: thresholdY,
      stroke: chartColors.cacheSecurityEvicted,
      "stroke-width": 1.5,
      "stroke-dasharray": "6 5"
    });
    ctx.add("text", {
      x: ctx.width - ctx.padding.right,
      y: thresholdY - 7,
      "text-anchor": "end",
      fill: chartColors.cacheSecurityEvicted,
      "font-size": 11,
      "font-weight": 800
    }, config.thresholdLabel || formatChartNumber(config.threshold));
  }

  config.categories.forEach((category, categoryIndex) => {
    const groupX = ctx.padding.left + categoryIndex * categoryWidth;
    config.series.forEach((series, seriesIndex) => {
      const value = series.values[categoryIndex];
      if (!Number.isFinite(value)) return;
      const x = groupX + groupPadding + seriesIndex * (barWidth + barGap);
      const barValY = valueToY(ctx, value, minValue, maxValue);
      const barY = Math.min(barValY, zeroY);
      const barHeight = Math.max(2, Math.abs(zeroY - barValY));
      const labelY = value >= 0 ? barValY - 5 : barValY + barHeight + 12;
      ctx.add("rect", { x, y: barY, width: barWidth, height: barHeight, rx: 2, fill: series.color });
      ctx.add("text", { x: x + barWidth / 2, y: labelY, "text-anchor": "middle", fill: "#20251f", "font-size": 10, "font-weight": 700 }, formatChartNumber(value));
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

  if (config.xLabel) {
    ctx.add("text", {
      x: ctx.padding.left + ctx.plotWidth / 2,
      y: ctx.height - 6,
      "text-anchor": "middle",
      fill: "#657064",
      "font-size": 10,
      "font-weight": 700
    }, config.xLabel);
  }

  if (!config.series.length) {
    ctx.add("text", {
      x: ctx.width / 2,
      y: ctx.padding.top + ctx.plotHeight / 2,
      "text-anchor": "middle",
      fill: "#657064",
      "font-size": 14,
      "font-weight": 800
    }, config.emptyLabel || "等待采集");
  }

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
