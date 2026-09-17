#!/bin/bash
# GBDoctor Linux 卸载脚本
# 用法: sudo bash uninstall.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    error "请使用 root 权限运行: sudo bash uninstall.sh"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  GBDoctor 卸载程序${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# 停止并禁用服务
if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet gbdoctor 2>/dev/null; then
        info "停止 gbdoctor 服务..."
        systemctl stop gbdoctor
    fi
    if systemctl is-enabled --quiet gbdoctor 2>/dev/null; then
        info "取消开机自启..."
        systemctl disable gbdoctor
    fi
fi

# 删除文件
info "删除二进制文件..."
rm -f /usr/local/bin/gbdoctor

info "删除 systemd service 文件..."
rm -f /etc/systemd/system/gbdoctor.service
if command -v systemctl &> /dev/null; then
    systemctl daemon-reload 2>/dev/null || true
fi

info "删除配置目录..."
rm -rf /etc/gbdoctor

info "删除日志目录..."
rm -rf /var/log/gbdoctor

info "删除报告目录..."
rm -rf /var/lib/gbdoctor

echo ""
echo -e "${GREEN}GBDoctor 已完全卸载${NC}"
echo ""
