import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(__dirname, "..");
const configPath = path.join(appRoot, "config", "demo.config.json");

export function loadConfig() {
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  return {
    appRoot,
    publicDir: path.join(appRoot, "public"),
    server: {
      host: process.env.WEB_HOST || config.server?.host || "127.0.0.1",
      port: Number(process.env.WEB_PORT || config.server?.port || 5177)
    },
    fpgaTargets: config.fpgaTargets || [],
    ssh: {
      connectTimeoutMs: Number(config.ssh?.connectTimeoutMs || 12000),
      allowTerminalInput: config.ssh?.allowTerminalInput !== false
    },
    commands: config.commands || {},
    unprotected: {
      distro: config.unprotected?.distro || "Ubuntu",
      workingDirectory: config.unprotected?.workingDirectory || path.resolve(appRoot, "..", "e"),
      defaultCore: String(config.unprotected?.defaultCore || "0"),
      defaultKey: config.unprotected?.defaultKey || "00112233445566778899aabbccddeeff",
      defaultSamples: Number(config.unprotected?.defaultSamples || 200000),
      defaultCacheSets: Number(config.unprotected?.defaultCacheSets || 64),
      defaultLineShift: Number(config.unprotected?.defaultLineShift || 6),
      defaultCacheLevel: Number(config.unprotected?.defaultCacheLevel || 1),
      appPort: Number(config.unprotected?.appPort || 8899),
      buildOnStart: config.unprotected?.buildOnStart !== false
    }
  };
}

export function updateFpgaTarget(config, targetName, input = {}) {
  const target = config.fpgaTargets.find((item) => item.name === targetName);
  if (!target) throw new Error(`未知连接目标: ${targetName}`);

  const updates = {
    label: requiredText(input.label, "显示名称", 80),
    host: requiredText(input.host, "主机/IP", 253),
    port: validPort(input.port),
    username: requiredText(input.username, "用户名", 80),
    workingDirectory: requiredText(input.workingDirectory, "工作目录", 500)
  };
  if (/\s/.test(updates.host)) throw new Error("主机/IP 不能包含空白字符");
  if (/\s/.test(updates.username)) throw new Error("用户名不能包含空白字符");
  if (!updates.workingDirectory.startsWith("/")) throw new Error("工作目录必须是绝对路径");
  if (String(input.password || "")) updates.password = String(input.password);

  const raw = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const rawTarget = raw.fpgaTargets?.find((item) => item.name === targetName);
  if (!rawTarget) throw new Error(`配置文件中不存在连接目标: ${targetName}`);
  Object.assign(rawTarget, updates);
  fs.writeFileSync(configPath, `${JSON.stringify(raw, null, 2)}\n`, "utf8");
  Object.assign(target, updates);
  return publicTarget(target);
}

function requiredText(value, label, maxLength) {
  const text = String(value ?? "").trim();
  if (!text) throw new Error(`${label}不能为空`);
  if (text.length > maxLength) throw new Error(`${label}长度不能超过 ${maxLength} 个字符`);
  return text;
}

function validPort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("端口必须是 1 到 65535 的整数");
  }
  return port;
}

export function publicTarget(target) {
  return {
    name: target.name,
    label: target.label || target.name,
    kind: target.kind || "ssh",
    protection: target.protection || target.name,
    host: target.host,
    port: target.port,
    username: target.username,
    authProfile: target.authProfile,
    workingDirectory: target.workingDirectory,
    usesPassword: Boolean(target.password)
  };
}
