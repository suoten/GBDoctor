# GBDoctor — GB/T 28181 接入诊断医生

> **3 分钟定位 GB28181 接入问题，而不是抓包抓三天。**
>
> *Diagnose GB28181 access issues in 3 minutes — not 3 days of packet capture.*

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

**[中文](#中文文档)** | **[English](#english-documentation)**

---

## 中文文档

### 这是什么

GBDoctor 是 GB/T 28181 接入链路的「全科体检医生」：同时扮演**模拟上级平台**和**模拟摄像头**两个角色，对真实链路做全自动化体检，输出一份可以截图发给厂家、同事、甲方的人话诊断报告。

**一句话定位**：让安防集成商 3 分钟定位 GB28181 接入问题。

### 核心功能

| 功能 | 说明 |
|------|------|
| **一键体检** | 自动启动模拟平台 → 注册模拟设备 → 全链路体检 → 弹窗报告，全程零配置 |
| **模拟上级平台** | GBDoctor 起一个 SIP Server，等真实摄像头注册上来，主动发起全链路检测 |
| **模拟摄像头** | GBDoctor 模拟一台摄像头，注册到你的真实上级平台，验证平台是否合规 |
| **本机自检** | 本机回环自测，模拟平台 ↔ 模拟设备全链路验证，不依赖任何外部设备 |
| **抓包分析** | 内置零依赖抓包（无需 libpcap 驱动），自动捕获 SIP/RTP 报文并导出 pcap |
| **网络诊断** | 检测目标 IP 的 SIP 端口可达性、RTP 端口范围、NAT 类型、防火墙拦截 |
| **历史报告** | 所有体检报告自动保存，可随时查看、转发 |

### 体检环节（12 项全链路检测）

```
注册 → 保活 → 目录 → 点播 → 媒体流 → 时钟 → 设备信息 → 云台 → 报警 → 录像 → 语音 → 2022新标
```

每个环节输出：**故障现象 → 报文证据 → 人话解释 → 修复建议**（具体到配置页面字段名）。

### 快速开始

#### Windows 用户（推荐）

1. 下载 `gbdoctor-windows-amd64.zip`，解压
2. 双击 `gbdoctor.exe`
3. 桌面窗口自动弹出（基于 WebView2，无需浏览器）
4. 点击「一键体检」按钮，等待 3 分钟出报告

> 无需安装 Go 环境，无需任何依赖，单文件即用。双击即弹出桌面窗口，不依赖外部浏览器。

#### Linux 用户

```bash
# 下载并解压
unzip gbdoctor-linux-amd64.zip
cd gbdoctor-linux-amd64

# 一键安装为系统服务（推荐）
sudo bash install.sh

# 或直接运行
./gbdoctor web -port 8080
```

安装为系统服务后：
```bash
sudo systemctl start gbdoctor    # 启动
sudo systemctl enable gbdoctor   # 开机自启
sudo systemctl status gbdoctor   # 查看状态
sudo systemctl stop gbdoctor     # 停止
```

#### 从源码编译

```bash
# 需要 Go 1.24+
git clone <repo-url>
cd GBDoctor
go build -o gbdoctor ./cmd/gbdoctor/

# 启动 Web UI
./gbdoctor web -port 8080
```

#### 一键打包发布

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File make-release.ps1

# 指定版本号
powershell -ExecutionPolicy Bypass -File make-release.ps1 -Version 1.3.0
```

产出 `release/` 目录下三个 zip 包（Windows / Linux amd64 / Linux arm64），每个包含二进制 + 安装脚本 + README。

### 安装部署指南

#### 场景一：Windows 现场联调（最常见）

```text
1. 下载 gbdoctor-windows-amd64.zip → 解压到任意目录
2. 双击 gbdoctor.exe → 桌面窗口自动弹出（无需浏览器）
3. 点击「一键体检」→ 3 分钟出报告
4. 无需管理员权限，无需安装任何运行时
```

**防火墙提示**：首次运行时 Windows 可能弹出防火墙提示，点击「允许访问」即可（SIP 需要 UDP 5060 端口）。

#### 场景二：Linux 服务器部署（团队共享）

```bash
# 1. 上传 zip 到服务器
scp gbdoctor-linux-amd64.zip user@server:/opt/

# 2. 解压并安装
ssh user@server
cd /opt && unzip gbdoctor-linux-amd64.zip
cd gbdoctor-linux-amd64
sudo bash install.sh

# 3. 服务自动启动，访问 http://server-ip:8080
```

**install.sh 会自动完成**：
- 复制二进制到 `/usr/local/bin/`
- 创建 systemd service 文件
- 创建配置目录 `/etc/gbdoctor/`
- 设置日志目录 `/var/log/gbdoctor/`
- 启动并设置开机自启

#### 场景三：Docker 部署

```dockerfile
FROM debian:bookworm-slim
COPY gbdoctor /usr/local/bin/gbdoctor
EXPOSE 8080 5060/udp
CMD ["gbdoctor", "web", "-port", "8080", "-no-open"]
```

```bash
docker build -t gbdoctor .
docker run -d -p 8080:8080 -p 5060:5060/udp --name gbdoctor gbdoctor
```

#### 场景四：从源码编译（开发者）

```bash
# 前置条件：安装 Go 1.24+
# 详见 https://go.dev/dl/

# 克隆项目
git clone <repo-url>
cd GBDoctor

# 编译（当前平台）
go build -o gbdoctor ./cmd/gbdoctor/

# 交叉编译 Linux amd64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gbdoctor-linux-amd64 ./cmd/gbdoctor/

# 交叉编译 Linux arm64（树莓派/ARM 服务器）
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o gbdoctor-linux-arm64 ./cmd/gbdoctor/

# 交叉编译 Windows
GOOS=windows GOARCH=amd64 go build -o gbdoctor.exe ./cmd/gbdoctor/

# 运行测试
go test ./...
```

> **零 CGO 依赖**：GBDoctor 是纯 Go 实现（仅依赖 `gopkg.in/yaml.v3`），交叉编译无需安装 C 编译器。

### 使用指南

#### 模式一：一键体检（模拟平台 + 模拟设备）

最简单的用法。点击一个按钮，GBDoctor 自动：
1. 启动模拟上级平台（SIP Server，监听 5060 端口）
2. 注册一台模拟摄像头到平台
3. 执行 12 项全链路体检
4. 弹窗显示报告

**适用场景**：验证 GBDoctor 自身功能、演示、新人体验。

#### 模式二：模拟上级平台（等真机注册）

1. 打开 GBDoctor → 体检中心 → 启动平台
2. 在摄像头上配置 SIP 服务器地址为**本机 IP**、端口 **5060**、服务器编码与页面一致
3. 摄像头注册成功后，点击「体检」按钮
4. 查看报告

**适用场景**：新设备验收、联调环境搭建、验证修复效果。

如果设备注册不上来，点击「获取排查建议」按钮，GBDoctor 会自动列出本机 IP、端口和逐项排查清单。

#### 模式三：平台侧体检（模拟摄像头注册到真实平台）

1. 切到「平台侧体检」Tab
2. 填写上级平台地址（如 `192.168.1.100:5060`）、平台编码、设备编码、密码
3. 点击「开始平台侧体检」
4. GBDoctor 模拟一台摄像头注册到你的真实平台，验证注册/心跳/目录/点播

**适用场景**：验证平台是否合规、平台排障。

#### 模式四：抓包分析

1. 启动模拟平台后，所有 SIP/RTP 报文自动被捕获
2. 切到「抓包分析」Tab，查看捕获统计
3. 点击「下载 pcap」导出 libpcap 格式文件（可用 Wireshark 打开）

**适用场景**：事后复盘、远程支持、举证材料。

> **零依赖抓包**：GBDoctor 内置抓包功能，不需要安装 libpcap/WinPcap 驱动，不占用系统端口。

#### 模式五：网络诊断

1. 切到「网络诊断」Tab
2. 输入目标 IP 和端口
3. 点击「开始诊断」
4. 自动检测 SIP 端口可达性、RTP 端口范围、NAT 类型

**适用场景**：排查网络层面问题。

### CLI 命令参考

```bash
gbdoctor desktop              # 桌面应用（WebView2 窗口，无需浏览器）
gbdoctor web [flags]           # 启动 Web UI（浏览器模式）
gbdoctor sipsim [flags]        # 模拟上级平台（CLI 模式）
gbdoctor simcam [flags]        # 模拟摄像头（CLI 模式）
gbdoctor selftest              # 本机回环自检
gbdoctor check [flags]         # 对已注册设备执行全链路体检
gbdoctor platform [flags]      # 平台侧体检
gbdoctor netdiag [flags]       # 网络诊断
gbdoctor pcap [flags]          # pcap 离线分析
gbdoctor batch [flags]         # 批量体检
gbdoctor version               # 版本号
```

常用 flags：
```bash
gbdoctor web -port 8080        # 指定 Web 端口
gbdoctor web -no-open          # 不自动打开浏览器
gbdoctor sipsim -port 5060     # 指定 SIP 端口
gbdoctor sipsim -tcp           # 同时监听 TCP
gbdoctor check -device-id 34020000001320000001  # 指定设备
```

### 项目结构

```
GBDoctor/
├── cmd/gbdoctor/           # 主程序入口
│   ├── main.go             # CLI 路由
│   ├── desktop.go          # Wails 桌面应用入口（WebView2 窗口）
│   ├── web.go              # Web UI 启动
│   └── selftest.go         # 本机自检
├── internal/
│   ├── sip/                # SIP 协议栈（纯 Go 实现）
│   │   ├── roles.go        # 模拟上级平台/摄像头角色
│   │   ├── camera_listener.go  # 模拟设备自动应答
│   │   ├── invite.go       # INVITE/SDP 解析
│   │   ├── pcap.go         # 内置抓包 + pcap 导出
│   │   └── ...
│   ├── diag/               # 体检引擎（分段推进）
│   ├── rules/              # 声明式规则库（YAML）
│   ├── report/             # HTML 报告生成
│   ├── netdiag/            # 网络诊断
│   ├── batch/              # 批量体检
│   ├── compat/             # 国标兼容性
│   ├── gbcode/             # 国标编码校验
│   └── web/                # Web UI + REST API
│       ├── api.go          # HTTP API
│       ├── ws.go           # WebSocket 推送
│       └── web/            # 前端静态资源（go:embed）
├── make-release.ps1        # 打包脚本
├── install.sh              # Linux 安装脚本
└── go.mod
```

### 技术特点

- **桌面应用窗口**：基于 Wails + WebView2，双击 exe 直接弹出桌面窗口，无需浏览器
- **纯 Go 单二进制**：零 CGO 依赖，交叉编译即走，几 MB 大小
- **go:embed 内嵌前端**：HTML/CSS/JS 全部内嵌进二进制，无外部文件依赖
- **内置零依赖抓包**：不需要 libpcap/WinPcap 驱动，内存捕获 + libpcap 格式导出
- **声明式规则库**：53+ 条规则（YAML），与代码解耦，可持续沉淀
- **分段推进引擎**：注册通了才测目录，目录通了才测点播——自动告诉你断在第几环
- **证据链**：每个问题附原始报文 + 时间戳 + SHA-256 指纹

---

## English Documentation

### What is GBDoctor

GBDoctor is a "full-body checkup doctor" for GB/T 28181 (China's national standard for video surveillance) access links. It plays **both** the role of a simulated upper-level platform **and** a simulated camera, performing fully automated health checks on the real link, and outputs a human-readable diagnostic report you can screenshot and send to vendors, colleagues, or clients.

**One-liner**: Let security integrators pinpoint GB28181 access issues in 3 minutes.

### Core Features

| Feature | Description |
|---------|-------------|
| **One-Click Checkup** | Auto-starts simulated platform → registers simulated device → full-link health check → popup report, zero configuration |
| **Simulated Upper Platform** | GBDoctor runs a SIP Server, waits for real cameras to register, and proactively runs full-link checks |
| **Simulated Camera** | GBDoctor simulates a camera, registers to your real upper-level platform, and verifies platform compliance |
| **Local Self-Test** | Loopback self-test on localhost, simulated platform ↔ simulated device, no external hardware needed |
| **Packet Capture** | Built-in zero-dependency capture (no libpcap driver needed), auto-captures SIP/RTP packets and exports pcap |
| **Network Diagnostics** | Detects SIP port reachability, RTP port range, NAT type, firewall blocking |
| **Report History** | All checkup reports auto-saved, viewable and shareable anytime |

### 12-Stage Full-Link Health Check

```
Register → Keepalive → Catalog → Invite → RTP Stream → Clock → DeviceInfo → PTZ → Alarm → Record → Voice → GB2022
```

Each stage outputs: **Symptom → Packet Evidence → Human Explanation → Fix Advice** (down to the config page field name).

### Quick Start

#### Windows Users (Recommended)

1. Download `gbdoctor-windows-amd64.zip`, extract
2. Double-click `gbdoctor.exe`
3. Desktop window opens automatically (WebView2, no browser needed)
4. Click "One-Click Checkup" button, wait 3 minutes for report

> No Go runtime needed, no dependencies, single binary. Double-click opens a desktop window, no external browser required.

#### Linux Users

```bash
# Download and extract
unzip gbdoctor-linux-amd64.zip
cd gbdoctor-linux-amd64

# One-click install as system service (recommended)
sudo bash install.sh

# Or run directly
./gbdoctor web -port 8080
```

After installing as a service:
```bash
sudo systemctl start gbdoctor    # Start
sudo systemctl enable gbdoctor   # Enable on boot
sudo systemctl status gbdoctor   # Check status
sudo systemctl stop gbdoctor     # Stop
```

#### Build from Source

```bash
# Requires Go 1.24+
git clone <repo-url>
cd GBDoctor
go build -o gbdoctor ./cmd/gbdoctor/

# Start Web UI
./gbdoctor web -port 8080
```

#### One-Click Release Packaging

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File make-release.ps1

# Specify version
powershell -ExecutionPolicy Bypass -File make-release.ps1 -Version 1.3.0
```

Produces three zip packages in `release/` (Windows / Linux amd64 / Linux arm64), each containing binary + install script + README.

### Installation & Deployment

#### Scenario 1: Windows On-Site Debugging (Most Common)

```text
1. Download gbdoctor-windows-amd64.zip → Extract to any folder
2. Double-click gbdoctor.exe → Desktop window opens (WebView2, no browser needed)
3. Click "One-Click Checkup" → Report in 3 minutes
4. No admin privileges needed, no runtime installation
```

**Firewall prompt**: Windows may show a firewall prompt on first run. Click "Allow access" (SIP needs UDP port 5060).

#### Scenario 2: Linux Server Deployment (Team Shared)

```bash
# 1. Upload zip to server
scp gbdoctor-linux-amd64.zip user@server:/opt/

# 2. Extract and install
ssh user@server
cd /opt && unzip gbdoctor-linux-amd64.zip
cd gbdoctor-linux-amd64
sudo bash install.sh

# 3. Service auto-starts, access at http://server-ip:8080
```

**install.sh automatically**:
- Copies binary to `/usr/local/bin/`
- Creates systemd service file
- Creates config directory `/etc/gbdoctor/`
- Sets up log directory `/var/log/gbdoctor/`
- Starts and enables on boot

#### Scenario 3: Docker Deployment

```dockerfile
FROM debian:bookworm-slim
COPY gbdoctor /usr/local/bin/gbdoctor
EXPOSE 8080 5060/udp
CMD ["gbdoctor", "web", "-port", "8080", "-no-open"]
```

```bash
docker build -t gbdoctor .
docker run -d -p 8080:8080 -p 5060:5060/udp --name gbdoctor gbdoctor
```

#### Scenario 4: Build from Source (Developers)

```bash
# Prerequisite: Install Go 1.24+
# See https://go.dev/dl/

# Clone
git clone <repo-url>
cd GBDoctor

# Build (current platform)
go build -o gbdoctor ./cmd/gbdoctor/

# Cross-compile for Linux amd64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gbdoctor-linux-amd64 ./cmd/gbdoctor/

# Cross-compile for Linux arm64 (Raspberry Pi / ARM servers)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o gbdoctor-linux-arm64 ./cmd/gbdoctor/

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o gbdoctor.exe ./cmd/gbdoctor/

# Run tests
go test ./...
```

> **Zero CGO dependency**: GBDoctor is pure Go (only depends on `gopkg.in/yaml.v3`), cross-compilation requires no C compiler.

### Usage Guide

#### Mode 1: One-Click Checkup (Simulated Platform + Simulated Device)

Simplest usage. One click, GBDoctor automatically:
1. Starts simulated upper platform (SIP Server, port 5060)
2. Registers a simulated camera
3. Runs 12-stage full-link health check
4. Shows popup report

**Use case**: Verify GBDoctor itself, demos, onboarding.

#### Mode 2: Simulated Upper Platform (Wait for Real Devices)

1. Open GBDoctor → Health Check Center → Start Platform
2. Configure camera's SIP server address to **your machine IP**, port **5060**, server ID matching the page
3. After camera registers, click "Checkup" button
4. View report

**Use case**: New device acceptance, integration testing, fix verification.

If devices don't register, click "Get Troubleshooting Tips" for auto-generated diagnostic checklist with your machine's IP and port.

#### Mode 3: Platform-Side Checkup (Simulated Camera → Real Platform)

1. Switch to "Platform-Side Checkup" tab
2. Fill in upper platform address (e.g., `192.168.1.100:5060`), platform ID, device ID, password
3. Click "Start Platform-Side Checkup"
4. GBDoctor simulates a camera registering to your real platform, verifies register/keepalive/catalog/invite

**Use case**: Verify platform compliance, platform troubleshooting.

#### Mode 4: Packet Capture

1. After starting simulated platform, all SIP/RTP packets are auto-captured
2. Switch to "Packet Capture" tab, view capture statistics
3. Click "Download pcap" to export libpcap format file (Wireshark compatible)

**Use case**: Post-mortem analysis, remote support, evidence.

> **Zero-dependency capture**: GBDoctor has built-in capture, no libpcap/WinPcap driver needed, doesn't occupy system ports.

#### Mode 5: Network Diagnostics

1. Switch to "Network Diagnostics" tab
2. Enter target IP and port
3. Click "Start Diagnostics"
4. Auto-detects SIP port reachability, RTP port range, NAT type

**Use case**: Network-layer troubleshooting.

### CLI Reference

```bash
gbdoctor desktop              # Desktop app (WebView2 window, no browser)
gbdoctor web [flags]           # Start Web UI (browser mode)
gbdoctor sipsim [flags]        # Simulated upper platform (CLI mode)
gbdoctor simcam [flags]        # Simulated camera (CLI mode)
gbdoctor selftest              # Local loopback self-test
gbdoctor check [flags]         # Full-link checkup on registered device
gbdoctor platform [flags]      # Platform-side checkup
gbdoctor netdiag [flags]       # Network diagnostics
gbdoctor pcap [flags]          # pcap offline analysis
gbdoctor batch [flags]         # Batch checkup
gbdoctor version               # Version
```

Common flags:
```bash
gbdoctor web -port 8080        # Specify web port
gbdoctor web -no-open          # Don't auto-open browser
gbdoctor sipsim -port 5060     # Specify SIP port
gbdoctor sipsim -tcp           # Also listen on TCP
gbdoctor check -device-id 34020000001320000001  # Specify device
```

### Technical Highlights

- **Desktop App Window**: Built on Wails + WebView2, double-click exe opens a native desktop window, no browser needed
- **Pure Go single binary**: Zero CGO dependency, cross-compile anywhere, a few MB
- **go:embed frontend**: HTML/CSS/JS all embedded in binary, no external file dependencies
- **Built-in zero-dependency capture**: No libpcap/WinPcap driver, in-memory capture + libpcap format export
- **Declarative rule engine**: 53+ rules (YAML), decoupled from code, continuously growing
- **Stage-by-stage engine**: Register passes → test catalog; catalog passes → test invite — tells you exactly which stage fails
- **Evidence chain**: Each issue includes raw packet + timestamp + SHA-256 fingerprint

### License

Apache-2.0

### Links

- **Demo**: [demo.gbdoctor.cn](https://demo.gbdoctor.cn)
- **Issues**: Please submit issues on the repository
- **Community**: Join the GB28181 developer community
