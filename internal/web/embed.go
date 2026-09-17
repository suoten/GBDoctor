// Package web 实现 GBDoctor 的 Web UI 层。
//
// 架构：
//   - HTTP 服务器提供 REST API + WebSocket 实时推送
//   - 前端静态资源通过 go:embed 内嵌进二进制
//   - 启动后自动打开浏览器，实现「双击即用」体验
//
// API 端点：
//   GET  /api/status           — 服务器状态（版本、规则数、已注册设备）
//   POST /api/sipsim/start     — 启动模拟上级平台
//   POST /api/sipsim/stop      — 停止模拟上级平台
//   GET  /api/sessions         — 已注册设备列表
//   POST /api/check            — 对已注册设备执行全链路体检
//   POST /api/selftest         — 本机回环自检
//   POST /api/platform         — 平台侧体检（模拟摄像头注册到真实平台）
//   POST /api/pcap             — pcap 离线分析
//   POST /api/netdiag          — 网络诊断
//   GET  /api/report/:id       — 获取体检报告 HTML
//   GET  /api/reports          — 历史报告列表
//   WS   /ws                   — WebSocket 实时推送（体检进度、日志）
package web

import "embed"

//go:embed web/*
var staticFiles embed.FS
