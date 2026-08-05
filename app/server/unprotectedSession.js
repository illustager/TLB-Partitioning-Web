import path from "node:path";
import { spawn } from "node:child_process";
import { timingSafeEqual } from "node:crypto";

const HEX_KEY = /^[0-9a-fA-F]{32}$/;
const CORE_LIST = /^[0-9]+(?:,[0-9]+)*$/;

function nowIso() {
  return new Date().toISOString();
}

function windowsPathToWsl(value) {
  const normalized = path.resolve(value).replaceAll("\\", "/");
  const driveMatch = normalized.match(/^([A-Za-z]):\/(.*)$/);
  if (!driveMatch) return normalized;
  return `/mnt/${driveMatch[1].toLowerCase()}/${driveMatch[2]}`;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

export class UnprotectedSession {
  constructor(config, hub) {
    this.config = config;
    this.hub = hub;
    this.processes = new Map();
    this.processOutput = new Map();
    this.logs = [];
    this.status = {
      running: false,
      phase: "idle",
      core: this.config.unprotected.defaultCore,
      key: this.config.unprotected.defaultKey,
      recovery: this.defaultRecovery(),
      recoveredKey: null,
      recoveredKeyValid: null,
      eveReady: false,
      lastMessage: null,
      lastCiphertext: null,
      lastEavesdrop: null,
      startedAt: null,
      endedAt: null
    };
    this.malloryBuffer = "";
    this.pendingAliceCiphertexts = 0;
    this.expectedStopProcesses = new WeakSet();
    this.eveReadyWaiter = null;
    this.eveCapture = null;
  }

  snapshot() {
    return {
      ...this.status,
      logs: this.logs.slice(-300)
    };
  }

  async start(options = {}) {
    const nextKey = String(options.key || this.config.unprotected.defaultKey).toLowerCase();
    const nextCore = String(options.core || this.config.unprotected.defaultCore);
    const recovery = this.normalizeRecovery(options);
    this.validateKey(nextKey);
    this.validateCore(nextCore);

    this.stop({ quiet: true });
    this.status = {
      running: true,
      phase: "starting",
      core: nextCore,
      key: nextKey,
      recovery,
      recoveredKey: null,
      recoveredKeyValid: null,
      eveReady: false,
      lastMessage: null,
      lastCiphertext: null,
      lastEavesdrop: null,
      startedAt: nowIso(),
      endedAt: null
    };
    this.malloryBuffer = "";
    this.pendingAliceCiphertexts = 0;
    this.logs = [];
    this.emitStatus();
    this.log("system", `准备在 WSL ${this.config.unprotected.distro} 的逻辑核 ${nextCore} 启动攻击 POC`);

    if (this.config.unprotected.buildOnStart) {
      try {
        await this.build();
      } catch (error) {
        this.status.running = false;
        this.status.phase = "start-failed";
        this.status.endedAt = nowIso();
        this.emitStatus();
        this.log("system", `编译失败: ${error.message}`);
        throw error;
      }
    }

    this.spawnRole("app", `taskset -c ${nextCore} ./app ${nextKey}`);
    this.spawnRole("bob", `taskset -c ${nextCore} ./bob ${nextKey}`);
    this.status.phase = "communicating";
    this.emitStatus();
    return this.snapshot();
  }

  async build() {
    this.log("system", "编译 app/bob/mallory/eve");
    await this.runOnce("bash ./build_unprotected.sh", "build");
  }

  async sendMessage(message) {
    if (!this.status.running) throw new Error("攻击 POC 尚未启动");
    const text = String(message || "").trim();
    if (!text) throw new Error("消息不能为空");
    const chunks = this.chunkMessage(text, 11);
    this.status.lastMessage = text;
    this.status.lastCiphertext = null;
    this.status.lastEavesdrop = null;
    this.pendingAliceCiphertexts = chunks.length;
    this.log("alice", `send -> app: ${text}`);
    this.emitStatus();

    for (const [index, chunk] of chunks.entries()) {
      const wireText = `A0: ${chunk}`;
      const payload = Buffer.alloc(16);
      payload.write(wireText, 0, "utf8");
      const hex = payload.toString("hex");
      this.log("alice", `chunk ${index + 1}/${chunks.length}: ${wireText}`);
      await this.runOnce(
        `python3 -c "import binascii,socket; data=binascii.unhexlify('${hex}'); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(data,('127.0.0.1',${this.config.unprotected.appPort})); s.close()"`,
        "alice"
      );
    }
    return this.snapshot();
  }

  recoverKey(options = {}) {
    if (!this.status.running) throw new Error("攻击 POC 尚未启动");
    if (this.processes.has("mallory")) throw new Error("Mallory 正在恢复密钥");
    const recovery = this.normalizeRecovery(options);
    this.status.phase = "recovering";
    this.status.recovery = recovery;
    this.status.recoveredKey = null;
    this.status.recoveredKeyValid = null;
    this.status.eveReady = false;
    this.malloryBuffer = "";
    this.emitStatus();
    this.log("mallory", `启动 Prime+Probe 密钥恢复 samples=${recovery.samples} sets=${recovery.cacheSets} lineShift=${recovery.lineShift} level=${recovery.cacheLevel} start=${recovery.start} count=${recovery.count}`);
    this.spawnRole(
      "mallory",
      [
        `taskset -c ${this.status.core} ./mallory`,
        `--num-samples ${recovery.samples}`,
        `--cache-sets ${recovery.cacheSets}`,
        `--line-shift ${recovery.lineShift}`,
        `--cache-level ${recovery.cacheLevel}`,
        `--key-start ${recovery.start}`,
        `--key-length ${recovery.count}`
      ].join(" ")
    );
    return this.snapshot();
  }

  async demoRecoverKey() {
    if (!this.status.running) throw new Error("攻击 POC 尚未启动");
    await this.stopRole("mallory");
    await this.stopRole("eve");
    this.status.recoveredKey = this.status.key;
    this.status.recoveredKeyValid = true;
    this.status.phase = "key-recovered";
    this.status.eveReady = false;
    this.emitStatus();
    this.log("mallory", "快速演示恢复：已终止正在运行的 Mallory，并使用当前实验配置密钥完成恢复");
    return this.snapshot();
  }

  async enableEve() {
    if (!this.status.recoveredKey) throw new Error("尚未恢复密钥，无法启动 Eve");
    if (!this.keysMatch(this.status.recoveredKey, this.status.key)) {
      throw new Error("恢复密钥校验失败，无法启动 Eve");
    }
    const wasReady = this.status.eveReady;
    if (!this.processes.has("eve")) {
      const ready = this.waitForEveReady();
      this.spawnRole("eve", `taskset -c ${this.status.core} ./eve ${this.status.recoveredKey}`);
      await ready;
    }
    this.status.eveReady = true;
    this.status.phase = "eavesdropping";
    this.emitStatus();
    if (!wasReady) {
      this.log("eve", `Eve 已准备使用恢复密钥窃听: ${this.status.recoveredKey}`);
    }
    return this.snapshot();
  }

  async eavesdrop() {
    if (!this.status.running) throw new Error("攻击 POC 尚未启动");
    if (!this.status.lastMessage && !this.status.lastCiphertext) {
      throw new Error("还没有可窃听的 Alice 通信");
    }
    if (!this.status.recoveredKey) {
      const observed = this.status.lastCiphertext || "等待 app 转发密文";
      this.status.lastEavesdrop = {
        readable: false,
        text: observed
      };
      this.log("eve", `未获得密钥，窃听到密文/不可读数据: ${observed}`);
      this.emitStatus();
      return this.snapshot();
    }

    if (!this.keysMatch(this.status.recoveredKey, this.status.key)) {
      this.status.recoveredKeyValid = false;
      this.status.eveReady = false;
      this.status.phase = "key-mismatch";
      this.status.lastEavesdrop = {
        readable: false,
        text: "恢复密钥与通信密钥不一致，无法解密"
      };
      this.log("eve", `密钥校验失败，拒绝将已知 Alice 明文作为窃听结果: ${this.status.recoveredKey}`);
      this.emitStatus();
      return this.snapshot();
    }

    const expectedText = this.status.lastMessage;
    this.status.recoveredKeyValid = true;
    await this.enableEve();
    const text = await this.replayForEve(expectedText);
    const readable = text === expectedText;
    this.status.lastEavesdrop = {
      readable,
      text: readable ? text : "Eve 解密输出与 Alice 原文不一致"
    };
    this.log("eve", readable ? `使用恢复密钥解密得到明文: ${text}` : `实际解密校验失败: ${text}`);
    this.status.phase = readable ? "message-recovered" : "decrypt-failed";
    this.emitStatus();
    return this.snapshot();
  }

  stop({ quiet = false } = {}) {
    for (const [role, child] of this.processes.entries()) {
      this.expectedStopProcesses.add(child);
      child.kill();
    }
    this.processes.clear();
    this.status.running = false;
    this.status.phase = "stopped";
    this.status.recoveredKey = null;
    this.status.recoveredKeyValid = null;
    this.status.eveReady = false;
    this.status.lastMessage = null;
    this.status.lastCiphertext = null;
    this.status.lastEavesdrop = null;
    this.status.endedAt = nowIso();
    this.malloryBuffer = "";
    this.pendingAliceCiphertexts = 0;
    this.rejectEveWaiters(new Error("攻击 POC 已停止"));
    if (!quiet) {
      this.log("system", "攻击 POC 已停止");
      this.emitStatus();
    }
    return this.snapshot();
  }

  spawnRole(role, command) {
    const child = this.spawnWsl(`stdbuf -oL -eL ${command}`);
    this.processes.set(role, child);
    this.processOutput.set(role, "");
    this.log("system", `[${role}] ${command}`);

    child.stdout.on("data", (chunk) => this.handleOutput(role, chunk.toString("utf8")));
    child.stderr.on("data", (chunk) => this.handleOutput(role, chunk.toString("utf8")));
    child.on("exit", (code, signal) => {
      const expectedStop = this.expectedStopProcesses.has(child);
      this.processes.delete(role);
      const output = this.processOutput.get(role) || "";
      this.processOutput.delete(role);
      this.log("system", `[${role}] exited code=${code ?? "null"} signal=${signal ?? "null"}`);
      if (role === "mallory" && /Operation not supported|Cannot allocate memory/i.test(output)) {
        this.log("system", "当前 WSL 环境不支持该 cache level 的 Mastik Prime+Probe，请使用 L1");
      }
      if (role === "mallory" && !expectedStop && !this.status.recoveredKey) {
        this.status.phase = "recover-failed";
        this.emitStatus();
      }
      if (role === "eve" && !expectedStop) {
        this.status.eveReady = false;
        this.rejectEveWaiters(new Error(`Eve 已退出，code=${code ?? "null"}`));
        this.emitStatus();
      }
    });
    child.on("error", (error) => this.log("system", `[${role}] 启动失败: ${error.message}`));
    return child;
  }

  spawnWsl(command) {
    const cwd = windowsPathToWsl(this.config.unprotected.workingDirectory);
    const args = ["-d", this.config.unprotected.distro, "--cd", cwd, "--exec", "bash", "-lc", command];
    return spawn("wsl.exe", args, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
  }

  runOnce(command, role) {
    return new Promise((resolve, reject) => {
      const child = this.spawnWsl(command);
      child.stdout.on("data", (chunk) => this.handleOutput(role, chunk.toString("utf8")));
      child.stderr.on("data", (chunk) => this.handleOutput(role, chunk.toString("utf8")));
      child.on("error", reject);
      child.on("exit", (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`${role} failed with exit code ${code}`));
        }
      });
    });
  }

  handleOutput(role, text) {
    const cleaned = this.cleanOutput(text);
    if (!cleaned) return;

    const previousOutput = this.processOutput.get(role) || "";
    const nextOutput = `${previousOutput}\n${cleaned}`;
    this.processOutput.set(role, nextOutput.length > 12000 ? nextOutput.slice(-12000) : nextOutput);
    for (const line of cleaned.split("\n").map((item) => item.trim()).filter(Boolean)) {
      if (role === "app" && /^[0-9a-fA-F]{32}$/.test(line)) {
        if (this.pendingAliceCiphertexts > 0) {
          this.pendingAliceCiphertexts -= 1;
          this.status.lastCiphertext = line.toLowerCase();
          this.log(role, line);
          this.emitStatus();
        }
        continue;
      }

      this.log(role, line);
      if (role === "eve") {
        if (line.includes("UDP server listening")) {
          this.resolveEveReady();
        } else if (this.eveCapture && line.startsWith("A0: ")) {
          this.eveCapture.chunks.push(line.slice(4));
          if (this.eveCapture.chunks.length >= this.eveCapture.expectedChunks) {
            const capture = this.eveCapture;
            this.eveCapture = null;
            clearTimeout(capture.timer);
            capture.resolve(capture.chunks.join(""));
          }
        }
      }
    }
    if (role !== "mallory") return;

    this.malloryBuffer += text;
    const match = this.malloryBuffer.match(/Recovered key:\s*([0-9a-fA-F]{32})/);
    if (!match) return;

    this.status.recoveredKey = match[1].toLowerCase();
    this.status.recoveredKeyValid = this.keysMatch(this.status.recoveredKey, this.status.key);
    this.status.eveReady = false;
    this.status.phase = this.status.recoveredKeyValid ? "key-recovered" : "key-mismatch";
    this.emitStatus();
    this.log(
      "system",
      this.status.recoveredKeyValid
        ? `Mallory 已恢复并校验密钥: ${this.status.recoveredKey}`
        : `Mallory 输出的密钥校验失败: ${this.status.recoveredKey}`
    );
  }

  async stopRole(role) {
    const child = this.processes.get(role);
    if (child) {
      this.expectedStopProcesses.add(child);
      child.kill("SIGTERM");
      this.processes.delete(role);
    }
    if (role === "mallory") {
      await this.runOnce("pkill -TERM -x mallory >/dev/null 2>&1 || true", "system");
    }
    if (role === "eve") {
      await this.runOnce("pkill -TERM -x eve >/dev/null 2>&1 || true", "system");
      this.status.eveReady = false;
      this.rejectEveWaiters(new Error("Eve 已停止"));
    }
  }

  waitForEveReady() {
    if (this.status.eveReady && this.processes.has("eve")) return Promise.resolve();
    if (this.eveReadyWaiter) return this.eveReadyWaiter.promise;
    let resolve;
    let reject;
    const promise = new Promise((onResolve, onReject) => {
      resolve = onResolve;
      reject = onReject;
    });
    const timer = setTimeout(() => {
      this.eveReadyWaiter = null;
      reject(new Error("Eve 启动超时"));
    }, 3000);
    this.eveReadyWaiter = { promise, resolve, reject, timer };
    return promise;
  }

  resolveEveReady() {
    if (!this.eveReadyWaiter) return;
    const waiter = this.eveReadyWaiter;
    this.eveReadyWaiter = null;
    clearTimeout(waiter.timer);
    waiter.resolve();
  }

  rejectEveWaiters(error) {
    if (this.eveReadyWaiter) {
      const waiter = this.eveReadyWaiter;
      this.eveReadyWaiter = null;
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    if (this.eveCapture) {
      const capture = this.eveCapture;
      this.eveCapture = null;
      clearTimeout(capture.timer);
      capture.reject(error);
    }
  }

  async replayForEve(message) {
    const chunks = this.chunkMessage(message, 11);
    let activeCapture;
    const recovered = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.eveCapture = null;
        reject(new Error("等待 Eve 解密输出超时"));
      }, 3000);
      activeCapture = { expectedChunks: chunks.length, chunks: [], resolve, reject, timer };
      this.eveCapture = activeCapture;
    });

    this.log("eve", "重放上一条密文并等待 Eve 实际解密输出");
    try {
      for (const chunk of chunks) {
        const wireText = `A0: ${chunk}`;
        const payload = Buffer.alloc(16);
        payload.write(wireText, 0, "utf8");
        const hex = payload.toString("hex");
        await this.runOnce(
          `python3 -c "import binascii,socket; data=binascii.unhexlify('${hex}'); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(data,('127.0.0.1',${this.config.unprotected.appPort})); s.close()"`,
          "alice"
        );
      }
    } catch (error) {
      if (this.eveCapture === activeCapture) this.eveCapture = null;
      clearTimeout(activeCapture.timer);
      activeCapture.resolve("");
      throw error;
    }
    return recovered;
  }

  keysMatch(left, right) {
    if (!HEX_KEY.test(left || "") || !HEX_KEY.test(right || "")) return false;
    return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
  }

  log(role, text) {
    if (!text) return;
    const entry = {
      at: nowIso(),
      role,
      text
    };
    this.logs.push(entry);
    if (this.logs.length > 1000) this.logs.splice(0, this.logs.length - 1000);
    this.hub.emit("unprotected-log", entry);
  }

  cleanOutput(text) {
    const cleaned = String(text).replaceAll("\u0000", "").trimEnd();
    if (!cleaned.trim()) return "";
    if (/^wsl:/i.test(cleaned.trim())) return "";
    return cleaned;
  }

  emitStatus() {
    this.hub.emit("unprotected-status", this.snapshot());
  }

  validateKey(key) {
    if (!HEX_KEY.test(key)) {
      throw new Error("密钥必须是 16 字节 hex 字符串，例如 00112233445566778899aabbccddeeff");
    }
  }

  validateCore(core) {
    if (!CORE_LIST.test(core)) {
      throw new Error("逻辑核只能是数字或逗号分隔的数字列表，例如 0 或 0,1");
    }
  }

  defaultRecovery() {
    return {
      samples: this.config.unprotected.defaultSamples,
      cacheSets: this.config.unprotected.defaultCacheSets,
      lineShift: this.config.unprotected.defaultLineShift,
      cacheLevel: this.config.unprotected.defaultCacheLevel,
      start: 0,
      count: 16
    };
  }

  normalizeRecovery(options = {}) {
    const defaults = this.defaultRecovery();
    const recovery = {
      samples: this.safeNumber(options.samples, defaults.samples, 1000, 5000000),
      cacheSets: this.safeNumber(options.cacheSets, defaults.cacheSets, 1, 1024),
      lineShift: this.safeNumber(options.lineShift, defaults.lineShift, 1, 12),
      cacheLevel: this.safeNumber(options.cacheLevel, defaults.cacheLevel, 1, 1),
      start: this.safeNumber(options.start, defaults.start, 0, 15),
      count: this.safeNumber(options.count, defaults.count, 1, 16)
    };
    if (recovery.count > 16 - recovery.start) recovery.count = 16 - recovery.start;
    return recovery;
  }

  safeNumber(value, fallback, min, max) {
    const number = Number(value ?? fallback);
    if (!Number.isFinite(number)) return fallback;
    return Math.min(max, Math.max(min, Math.trunc(number)));
  }

  chunkMessage(text, maxBytes) {
    const chunks = [];
    let current = "";
    for (const char of Array.from(text)) {
      const next = `${current}${char}`;
      if (Buffer.byteLength(next, "utf8") > maxBytes) {
        if (current) chunks.push(current);
        current = Buffer.byteLength(char, "utf8") > maxBytes ? "?" : char;
      } else {
        current = next;
      }
    }
    if (current) chunks.push(current);
    return chunks;
  }
}
