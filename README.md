# TLB Partitioning Web 演示平台

本项目是 VexRiscv Cache/TLB Partitioning 防护方案的 Web 演示与采集平台。系统包含两部分：

- 攻击 POC：在本机 WSL Ubuntu 中运行 `e/` 下的 app、Bob、Mallory、Eve 程序，展示密钥恢复与窃听差异。
- 防护采集：通过本地 Node.js 后端建立到 FPGA 板卡的 SSH 会话，执行安全与性能采集并绘制结果。

`e/` 和 `vendor/Mastik/` 已作为普通文件目录提交到仓库，不需要再拉取子模块。

## 环境要求

- Windows + PowerShell
- Node.js 18 或更高版本
- npm
- WSL Ubuntu，用于攻击 POC
- WSL Ubuntu 内安装：
  - `make`
  - `gcc`
  - `taskset`，通常来自 `util-linux`
- FPGA 板卡可通过 SSH 访问

检查 WSL 基础环境：

```powershell
wsl.exe -d Ubuntu --cd /mnt/c/Users/huangdan/Desktop/repo/TLB-Partitioning-Web/e --exec bash -lc "pwd; command -v make; command -v gcc; command -v taskset"
```

## 安装依赖

进入前端/后端应用目录安装 Node 依赖：

```powershell
cd app
npm install
```

## 配置

主要配置文件：

```text
app/config/demo.config.json
```

默认服务地址：

```json
"server": {
  "host": "127.0.0.1",
  "port": 5177
}
```

默认 FPGA 目标：

```text
Cache FPGA：192.168.1.100
TLB FPGA：192.168.1.50
用户名：root
密码：174044
工作目录：/root
```

板卡地址、显示名称、SSH 端口、用户名、密码和工作目录可直接在 Web“连接”页面修改并保存。也可以在服务启动前修改 `fpgaTargets` 中对应项。

攻击 POC 默认使用：

```json
"unprotected": {
  "distro": "Ubuntu",
  "defaultCore": "0",
  "defaultKey": "00112233445566778899aabbccddeeff",
  "appPort": 8899,
  "buildOnStart": true
}
```

## 启动服务

在 `app/` 目录启动：

```powershell
npm run dev
```

浏览器打开：

```text
http://127.0.0.1:5177
```

临时覆盖监听地址或端口：

```powershell
$env:WEB_HOST="0.0.0.0"
$env:WEB_PORT="5178"
npm run dev
```

语法检查：

```powershell
npm run check
```

## 攻击 POC 使用流程

1. 打开“攻击 POC”。
2. 确认 AES Key、逻辑核和 Mallory 参数。
3. 点击“启动实验”，后端会在 WSL Ubuntu 中编译并启动 app 和 Bob。
4. 在 Alice 输入框发送消息。
5. 点击“窃听”：未恢复密钥前只能看到密文/不可读数据。
6. 点击“恢复密钥”或“快速演示恢复”。
7. 再次点击“窃听”：恢复密钥后展示明文。
8. 点击“停止”结束本机实验。

说明：

- `e/build_unprotected.sh` 会构建 Mastik 和 `e/` 下实验程序。
- Mallory 真实 Prime+Probe 在 WSL 中可能不稳定，演示时可使用“快速演示恢复”保证流程可展示。
- 后端会过滤 Mallory 探测阶段产生的大量 app 中间密文，避免前端日志刷屏。

## 防护采集使用流程

1. 打开“防护采集”。
2. 在连接页选择 Cache FPGA 或 TLB FPGA。
3. 点击“连接 FPGA”。
4. 点击“安全结果采集”或“性能结果采集”。页面会按当前连接的 TLB/Cache 类型执行对应命令。
5. 需要补充操作时，可在右侧终端手动输入命令。
6. 在“最近采集数据”查看绘图所需摘要，在“结果对比”查看对应目标的图表。

命令映射：

- TLB 安全：`./test_with`
- TLB 性能：CoreMark、进程/线程上下文切换和 Hackbench
- Cache 安全：`CACHE_RESULT_MODE=security bash ./cache_test/cache_run.sh`
- Cache 性能：`CACHE_RESULT_MODE=effectiveness bash ./cache_test/cache_run.sh`

## 板上测试命令示例

基础性能测试：

```sh
./coremark.exe
```

进程压力测试：

```sh
./ctxswitch_proc -n 100 -w 50 -s
./ctxswitch_proc -n 1000 -w 500 -s
./ctxswitch_proc -s
```

线程压力测试：

```sh
./ctxswitch_thread -s -n 100 -w 50
./ctxswitch_thread -s -n 1000 -w 500
./ctxswitch_thread -s
```

并发压力测试：

```sh
./hackbench_like -l 10 -p -s
./hackbench_like -l 100 -p -s
./hackbench_like -l 1000 -p -s
./hackbench_like -l 10000 -p -s
```

结果解析规则：

- CoreMark：解析 `Iterations/Sec` 作为处理器性能评分。
- `ctxswitch_proc`、`ctxswitch_thread`、`hackbench_like`：解析 `per_switch=... ns`，换算为 `switches/sec`。

## 目录说明

```text
app/                  Web 前端和 Node.js 后端
app/config/           演示配置
app/public/           前端页面、样式和脚本
app/server/           API、SSE、SSH、WSL 进程管理
e/                    攻击 POC 本机实验程序
vendor/Mastik/        Mastik 源码及当前本地构建产物
prototype/            原型页面参考
```

## 常见问题

### 端口 5177 被占用

结束旧进程或修改 `app/config/demo.config.json` 中的 `server.port`。

### WSL 提示 localhost 代理未镜像

这是 WSL NAT 模式下的代理提示，通常不影响本项目本地编译和运行。

### 攻击 POC 启动失败

检查：

- `app/config/demo.config.json` 中 `unprotected.distro` 是否与本机 WSL 发行版名称一致。
- WSL 内是否存在 `make`、`gcc`、`taskset`。
- `e/` 是否位于当前仓库路径下。

### FPGA SSH 连接失败

检查：

- 板卡 IP 是否与配置一致。
- Windows 主机是否能访问该 IP。
- 板卡 SSH 服务是否启动。
- 用户名、密码、工作目录是否正确。
