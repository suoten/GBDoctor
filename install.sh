#!/bin/bash
# GBDoctor Linux 安装脚本
# 用法: sudo bash install.sh
# 或:   sudo bash install.sh -p 9090  (指定 Web 端口)
#
# 功能:
#   1. 复制二进制到 /usr/local/bin/
#   2. 创建 systemd service（开机自启）
#   3. 创建配置/日志/报告目录
#   4. 配置防火墙规则（如检测到 firewalld/ufw）
#   5. 启动服务

set -e

# ============================================================
# 颜色输出
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ============================================================
# 默认配置
# ============================================================
WEB_PORT=8080
SIP_PORT=5060
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/gbdoctor"
LOG_DIR="/var/log/gbdoctor"
REPORT_DIR="/var/lib/gbdoctor/reports"
SERVICE_FILE="/etc/systemd/system/gbdoctor.service"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ============================================================
# 解析参数
# ============================================================
while getopts "p:s:h" opt; do
    case $opt in
        p) WEB_PORT=$OPTARG ;;
        s) SIP_PORT=$OPTARG ;;
        h) echo "用法: sudo bash install.sh [-p WEB_PORT] [-s SIP_PORT]"; exit 0 ;;
        *) error "未知参数: $opt" ;;
    esac
done

# ============================================================
# 前置检查
# ============================================================
if [ "$(id -u)" -ne 0 ]; then
    error "请使用 root 权限运行: sudo bash install.sh"
fi

if [ ! -f "$SCRIPT_DIR/gbdoctor" ]; then
    error "未找到 gbdoctor 二进制文件，请确保在解压目录中运行此脚本"
fi

# 检查 systemd
if ! command -v systemctl &> /dev/null; then
    warn "未检测到 systemd，将仅复制二进制文件（不创建系统服务）"
    SYSTEMD_AVAILABLE=false
else
    SYSTEMD_AVAILABLE=true
fi

# ============================================================
# 安装步骤
# ============================================================
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  GBDoctor 安装程序${NC}"
echo -e "${CYAN}  GB/T 28181 接入诊断工具${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# 1. 复制二进制
info "安装二进制文件..."
cp "$SCRIPT_DIR/gbdoctor" "$INSTALL_DIR/gbdoctor"
chmod +x "$INSTALL_DIR/gbdoctor"
echo "  -> $INSTALL_DIR/gbdoctor"

# 2. 创建目录
info "创建目录..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"
echo "  -> $CONFIG_DIR"
echo "  -> $LOG_DIR"
echo "  -> $REPORT_DIR"

# 3. 创建配置文件
info "生成配置文件..."
cat > "$CONFIG_DIR/gbdoctor.env" << EOF
# GBDoctor 配置文件
# 修改后需重启服务: sudo systemctl restart gbdoctor

# Web UI 端口
GBDOCTOR_WEB_PORT=$WEB_PORT

# SIP 端口
GBDOCTOR_SIP_PORT=$SIP_PORT

# 是否自动打开浏览器（服务器环境设为 false）
GBDOCTOR_OPEN_BROWSER=false

# 日志目录
GBDOCTOR_LOG_DIR=$LOG_DIR

# 报告目录
GBDOCTOR_REPORT_DIR=$REPORT_DIR
EOF
echo "  -> $CONFIG_DIR/gbdoctor.env"

# 4. 创建 systemd service
if [ "$SYSTEMD_AVAILABLE" = true ]; then
    info "创建 systemd 服务..."
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=GBDoctor - GB/T 28181 Access Diagnostic Tool
Documentation=https://demo.gbdoctor.cn
After=network.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/gbdoctor/gbdoctor.env
ExecStart=/usr/local/bin/gbdoctor web -port ${GBDOCTOR_WEB_PORT} -no-open
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/gbdoctor/gbdoctor.log
StandardError=append:/var/log/gbdoctor/gbdoctor.log
LimitNOFILE=65536

# 安全限制
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/log/gbdoctor /var/lib/gbdoctor

[Install]
WantedBy=multi-user.target
EOF
    echo "  -> $SERVICE_FILE"

    # 5. 启动服务
    info "启动服务..."
    systemctl daemon-reload
    systemctl enable gbdoctor
    systemctl restart gbdoctor

    # 等待服务启动
    sleep 2
    if systemctl is-active --quiet gbdoctor; then
        info "服务已启动并设置开机自启"
    else
        warn "服务启动可能失败，请检查日志: journalctl -u gbdoctor -f"
    fi
fi

# 6. 配置防火墙
info "配置防火墙..."
if command -v firewall-cmd &> /dev/null; then
    # firewalld (CentOS/RHEL)
    firewall-cmd --permanent --add-port=$WEB_PORT/tcp 2>/dev/null && \
    firewall-cmd --permanent --add-port=$SIP_PORT/udp 2>/dev/null && \
    firewall-cmd --reload 2>/dev/null
    echo "  -> firewalld: 已放行 $WEB_PORT/tcp, $SIP_PORT/udp"
elif command -v ufw &> /dev/null; then
    # ufw (Ubuntu/Debian)
    ufw allow $WEB_PORT/tcp 2>/dev/null
    ufw allow $SIP_PORT/udp 2>/dev/null
    echo "  -> ufw: 已放行 $WEB_PORT/tcp, $SIP_PORT/udp"
else
    warn "未检测到防火墙工具（firewalld/ufw），请手动放行端口 $WEB_PORT/tcp 和 $SIP_PORT/udp"
fi

# ============================================================
# 获取本机 IP
# ============================================================
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(ip addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
fi
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="127.0.0.1"
fi

# ============================================================
# 输出结果
# ============================================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  GBDoctor 安装完成!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  访问地址:  http://$LOCAL_IP:$WEB_PORT"
echo "  SIP 端口:  $SIP_PORT/udp"
echo "  日志文件:  $LOG_DIR/gbdoctor.log"
echo "  报告目录:  $REPORT_DIR"
echo ""
if [ "$SYSTEMD_AVAILABLE" = true ]; then
    echo "  服务管理:"
    echo "    sudo systemctl start gbdoctor     # 启动"
    echo "    sudo systemctl stop gbdoctor       # 停止"
    echo "    sudo systemctl restart gbdoctor    # 重启"
    echo "    sudo systemctl status gbdoctor     # 状态"
    echo "    sudo systemctl disable gbdoctor    # 取消开机自启"
    echo "    journalctl -u gbdoctor -f          # 实时日志"
fi
echo ""
echo "  摄像头配置 SIP 服务器地址: $LOCAL_IP  端口: $SIP_PORT"
echo ""
echo "  卸载: sudo bash uninstall.sh"
echo ""
