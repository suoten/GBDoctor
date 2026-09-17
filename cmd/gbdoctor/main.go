// gbdoctor 主程序 CLI。
//
// 子命令：
//
//	gbdoctor sipsim     启动模拟上级平台（等待真机注册）
//	gbdoctor simcam     启动模拟摄像头（注册到目标平台并保活）
//	gbdoctor selftest   本机回环自检（sipsim ↔ simcam 全链路）
//	gbdoctor check      对已注册设备执行全链路体检
//	gbdoctor netdiag    网络诊断（端口/NAT/防火墙）
//	gbdoctor batch      批量体检（V1.2）
//	gbdoctor version    版本号
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gbdoctor/internal/diag"
	"gbdoctor/internal/netdiag"
	"gbdoctor/internal/report"
	"gbdoctor/internal/sip"
)

// version 为包级变量而非常量：make-release.ps1 通过
// go build -ldflags "-X main.version=..." 注入发布版本号，
// -X 只对变量生效，写成 const 会导致发布版版本号永远是默认值。
var version = "1.2.0"

func main() {
	if len(os.Args) < 2 {
		// 无参数双击运行 → 启动桌面应用（WebView2 窗口，无需浏览器）
		cmdDesktop()
		return
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("gbdoctor %s\n", version)
	case "sipsim":
		cmdSipsim(os.Args[2:])
	case "simcam":
		cmdSimcam(os.Args[2:])
	case "selftest":
		cmdSelftest()
	case "check":
		cmdCheck(os.Args[2:])
	case "netdiag":
		cmdNetdiag(os.Args[2:])
	case "batch":
		cmdBatch(os.Args[2:])
	case "pcap":
		cmdPcap(os.Args[2:])
	case "platform":
		cmdPlatform(os.Args[2:])
	case "web":
		cmdWeb(os.Args[2:])
	case "desktop", "gui":
		cmdDesktop()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `GBDoctor —— GB/T 28181 接入诊断医生 `+version+`

用法:
  gbdoctor sipsim   [flags]   模拟上级平台（等待设备注册）
  gbdoctor simcam   [flags]   模拟摄像头（注册到真实平台）
  gbdoctor selftest            本机回环全链路自检
  gbdoctor check    [flags]   对已注册设备执行全链路体检
  gbdoctor netdiag  [flags]   网络诊断（端口/NAT/防火墙）
  gbdoctor batch    [flags]   批量体检（专业版）
  gbdoctor pcap     [flags]   pcap 离线分析
  gbdoctor platform [flags]   平台侧体检（模拟摄像头注册到真实平台）
  gbdoctor desktop              桌面应用（WebView2 窗口，无需浏览器）
  gbdoctor web      [flags]   启动 Web UI（浏览器操作界面）
  gbdoctor version             版本号
`)
}

// cmdSipsim 启动模拟上级平台。
func cmdSipsim(args []string) {
	fs := flag.NewFlagSet("sipsim", flag.ExitOnError)
	host := fs.String("host", "0.0.0.0", "监听地址")
	port := fs.Int("port", 5060, "SIP 端口")
	serverID := fs.String("server-id", "34020000002000000001", "SIP 服务器编码（20 位）")
	password := fs.String("password", "12345678", "鉴权密码")
	algorithm := fs.String("algorithm", "MD5", "挑战算法: MD5 | SHA-256 | SM3")
	useTCP := fs.Bool("tcp", false, "同时监听 TCP")
	_ = fs.Parse(args)

	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host: *host, Port: *port,
		ServerID: *serverID, Password: *password,
		ChallengeAlg: *algorithm, ListenTCP: *useTCP,
	})
	if err := role.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 启动失败: %v（端口被占用？）\n", err)
		os.Exit(1)
	}
	defer role.Cleanup()

	role.OnRegister(func(f sip.RegisterFact) {
		switch f.Kind {
		case "challenge":
			fmt.Printf("[%s] → 401 质询 %s (Via=%s, 来源=%s)\n",
				ts(), f.DeviceID, f.ViaAddr, f.ReceivedAddr)
		case "registered":
			fmt.Printf("[%s] ✅ 注册成功 %s (算法=%s, Expires=%d)\n",
				ts(), f.DeviceID, f.Algorithm, f.Expires)
			if f.NATMismatch {
				fmt.Printf("[%s] ⚠️ NAT 地址不匹配 (Via=%s, 来源=%s)\n", ts(), f.ViaAddr, f.ReceivedAddr)
			}
		case "auth_fail":
			fmt.Printf("[%s] ❌ 鉴权失败 %s (类别=%s)\n", ts(), f.DeviceID, f.FailureKind)
		case "deregister":
			fmt.Printf("[%s] ⚪ 注销 %s\n", ts(), f.DeviceID)
		}
	})
	role.OnKeepalive(func(f sip.KeepaliveFact) {
		fmt.Printf("[%s] ✅ 心跳 %s (SN=%s)\n", ts(), f.DeviceID, sip.XMLTagValue(f.XML, "SN"))
	})
	role.OnCatalog(func(f sip.CatalogFact) {
		fmt.Printf("[%s] ✅ 目录应答 %s (通道数=%d)\n", ts(), f.DeviceID, len(f.Items))
		for _, item := range f.Items {
			fmt.Printf("    通道: %s 名称: %s 状态: %s\n", item.DeviceID, item.Name, item.Status)
		}
	})
	role.OnDeviceInfo(func(f sip.DeviceInfoFact) {
		fmt.Printf("[%s] ✅ 设备信息 %s (厂商=%s 型号=%s 固件=%s)\n",
			ts(), f.DeviceID, f.Manufacturer, f.Model, f.Firmware)
	})

	fmt.Printf("GBDoctor 模拟上级平台 %s\n", version)
	fmt.Printf("  监听: %s:%d (UDP%s)  服务器编码: %s  挑战算法: %s\n",
		*host, role.LocalPort(), tcpLabel(*useTCP), *serverID, strings.ToUpper(*algorithm))
	fmt.Println("等待设备注册… Ctrl+C 退出")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n退出")
}

func ts() string { return time.Now().Format("15:04:05") }

func tcpLabel(b bool) string {
	if b {
		return " + TCP"
	}
	return ""
}

// cmdCheck 对已注册设备执行全链路体检。
func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	host := fs.String("host", "0.0.0.0", "监听地址")
	port := fs.Int("port", 5060, "SIP 端口")
	serverID := fs.String("server-id", "34020000002000000001", "SIP 服务器编码")
	password := fs.String("password", "12345678", "鉴权密码")
	deviceID := fs.String("device-id", "", "目标设备编码（必填）")
	output := fs.String("o", "report.html", "报告输出文件")
	skipCatalog := fs.Bool("skip-catalog", false, "跳过目录检测")
	skipInvite := fs.Bool("skip-invite", false, "跳过点播检测")
	skipDeviceInfo := fs.Bool("skip-deviceinfo", false, "跳过设备信息检测")
	skipPTZ := fs.Bool("skip-ptz", false, "跳过云台控制检测")
	skipAlarm := fs.Bool("skip-alarm", false, "跳过报警订阅检测")
	skipRecord := fs.Bool("skip-record", false, "跳过录像检索检测")
	_ = fs.Parse(args)

	if *deviceID == "" {
		fmt.Fprintln(os.Stderr, "❌ 请用 -device-id 指定目标设备编码")
		os.Exit(2)
	}

	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host: *host, Port: *port,
		ServerID: *serverID, Password: *password,
	})
	if err := role.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 启动失败: %v\n", err)
		os.Exit(1)
	}
	defer role.Cleanup()

	fmt.Printf("GBDoctor 体检 %s\n", version)
	fmt.Printf("  等待设备 %s 注册…\n", *deviceID)

	// 等待设备注册
	registered := make(chan sip.RegisterFact, 1)
	role.OnRegister(func(f sip.RegisterFact) {
		if f.Kind == "registered" && f.DeviceID == *deviceID {
			select {
			case registered <- f:
			default:
			}
		}
	})

	select {
	case <-registered:
		fmt.Printf("[%s] ✅ 设备已注册，开始体检\n", ts())
	case <-time.After(60 * time.Second):
		fmt.Fprintf(os.Stderr, "❌ 等待设备注册超时（60s）\n")
		os.Exit(1)
	}

	// 执行体检
	engine, err := diag.NewDefaultEngine(role, diag.CheckConfig{
		DeviceID:       *deviceID,
		SkipCatalog:    *skipCatalog,
		SkipInvite:     *skipInvite,
		SkipDeviceInfo: *skipDeviceInfo,
		SkipPTZ:        *skipPTZ,
		SkipAlarm:      *skipAlarm,
		SkipRecord:     *skipRecord,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 引擎初始化失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("正在执行全链路体检…")
	r := engine.Run()

	// 输出结果
	fmt.Println(strings.Repeat("-", 46))
	for _, stage := range r.Stages {
		status := "✅"
		if stage.Skipped {
			status = "○"
		} else if !stage.Passed {
			status = "❌"
		}
		fmt.Printf("%s 环节 %s: %s\n", status, stage.Stage, strings.Join(stage.Facts, "; "))
		for _, iss := range stage.Issues {
			fmt.Printf("  [%s] %s\n", diag.SeverityLabel(iss.Severity), iss.Title)
		}
	}
	fmt.Println(strings.Repeat("-", 46))
	fmt.Printf("体检得分: %d/100 %s\n", r.Score, diag.ScoreLabel(r.Score))
	fmt.Printf("证据: %d 条, 规则: %d 条, 问题: %d 个\n", r.EvidenceCount, r.RuleCount, len(r.AllIssues))

	// 生成报告
	if err := report.GenerateHTMLFile(r, *output); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 报告生成失败: %v\n", err)
	} else {
		fmt.Printf("✅ 报告已生成: %s\n", *output)
	}
}

// cmdNetdiag 网络诊断。
func cmdNetdiag(args []string) {
	fs := flag.NewFlagSet("netdiag", flag.ExitOnError)
	target := fs.String("target", "", "目标 IP（必填）")
	_ = fs.Parse(args)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "❌ 请用 -target 指定目标 IP")
		os.Exit(2)
	}

	fmt.Printf("GBDoctor 网络诊断 %s\n", version)
	fmt.Printf("  目标: %s\n", *target)
	fmt.Println(strings.Repeat("-", 46))

	result := netdiag.RunNetworkDiagnosis(*target, 5060)
	for _, c := range result.Conclusions {
		fmt.Println("  " + c)
	}
	fmt.Println(strings.Repeat("-", 46))
	if len(result.Deviations) > 0 {
		fmt.Printf("发现 %d 个网络问题\n", len(result.Deviations))
	} else {
		fmt.Println("✅ 网络诊断通过")
	}
}

// cmdBatch 批量体检。
func cmdBatch(args []string) {
	fs := flag.NewFlagSet("batch", flag.ExitOnError)
	host := fs.String("host", "0.0.0.0", "监听地址")
	port := fs.Int("port", 5060, "SIP 端口")
	serverID := fs.String("server-id", "34020000002000000001", "SIP 服务器编码")
	password := fs.String("password", "12345678", "鉴权密码")
	deviceList := fs.String("devices", "", "设备列表文件（每行一个设备编码）")
	output := fs.String("o", "batch-report.html", "批量报告输出文件")
	_ = fs.Parse(args)

	if *deviceList == "" {
		fmt.Fprintln(os.Stderr, "❌ 请用 -devices 指定设备列表文件")
		os.Exit(2)
	}

	// 读取设备列表
	data, err := os.ReadFile(*deviceList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 读取设备列表失败: %v\n", err)
		os.Exit(1)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var devices []batchDeviceConfig
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		devices = append(devices, batchDeviceConfig{
			DeviceID:  line,
			Password:  *password,
			Transport: "udp",
		})
	}

	fmt.Printf("GBDoctor 批量体检 %s\n", version)
	fmt.Printf("  设备数: %d\n", len(devices))
	fmt.Println(strings.Repeat("-", 46))

	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host: *host, Port: *port,
		ServerID: *serverID, Password: *password,
	})
	if err := role.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 启动失败: %v\n", err)
		os.Exit(1)
	}
	defer role.Cleanup()

	// 执行批量体检
	re, err := diag.NewDefaultEngine(role, diag.CheckConfig{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 规则引擎初始化失败: %v\n", err)
		os.Exit(1)
	}
	ruleEngine := re.RuleEngine()

	results := make([]*diag.ReportData, 0, len(devices))
	passed, failed := 0, 0
	for _, dev := range devices {
		engine := diag.NewEngine(role, ruleEngine, diag.CheckConfig{
			DeviceID:  dev.DeviceID,
			Password:  dev.Password,
			Transport: dev.Transport,
		})
		r := engine.Run()
		results = append(results, r)
		status := "✅"
		if r.Passed {
			passed++
		} else {
			failed++
			status = "❌"
		}
		fmt.Printf("%s %s: 得分 %d/100, 问题 %d 个\n", status, dev.DeviceID, r.Score, len(r.AllIssues))
	}

	fmt.Println(strings.Repeat("-", 46))
	fmt.Printf("总计: %d 台, 通过: %d, 不通过: %d\n", len(devices), passed, failed)

	// 生成批量报告
	batchData := &report.BatchReportData{
		BatchID:     fmt.Sprintf("BATCH-%s", time.Now().Format("20060102-150405")),
		StartTime:   time.Now(),
		DeviceCount: len(devices),
		PassedCount: passed,
		FailedCount: failed,
		Reports:     results,
	}
	if err := report.GenerateBatchReportFile(batchData, *output); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 批量报告生成失败: %v\n", err)
	} else {
		fmt.Printf("✅ 批量报告已生成: %s\n", *output)
	}
}

// batchDeviceConfig 内部设备配置。
type batchDeviceConfig struct {
	DeviceID  string
	Password  string
	Transport string
}

// _ 为确保 diag 包被引用的占位
var _ = diag.FormatDuration

// cmdPcap pcap 离线分析。
func cmdPcap(args []string) {
	fs := flag.NewFlagSet("pcap", flag.ExitOnError)
	pcapFile := fs.String("f", "", "pcap 文件路径（必填）")
	output := fs.String("o", "pcap-report.txt", "分析报告输出文件")
	_ = fs.Parse(args)

	if *pcapFile == "" {
		fmt.Fprintln(os.Stderr, "❌ 请用 -f 指定 pcap 文件路径")
		os.Exit(2)
	}

	data, err := os.ReadFile(*pcapFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 读取文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("GBDoctor pcap 分析 %s\n", version)
	fmt.Printf("  文件: %s (%d 字节)\n", *pcapFile, len(data))

	packets, err := sip.ParsePcapFile(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ pcap 解析失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  解析报文: %d 个\n", len(packets))

	result := sip.AnalyzePcap(packets, *pcapFile)
	fmt.Println(strings.Repeat("-", 46))
	for _, fact := range result.Facts {
		fmt.Printf("  %s\n", fact)
	}
	if len(result.Issues) > 0 {
		fmt.Println(strings.Repeat("-", 46))
		fmt.Printf("发现问题 %d 个:\n", len(result.Issues))
		for _, iss := range result.Issues {
			fmt.Printf("  [%s] %s\n", iss.Severity, iss.Title)
		}
	}

	// 写入报告
	var report strings.Builder
	report.WriteString(fmt.Sprintf("GBDoctor pcap 分析报告\n"))
	report.WriteString(fmt.Sprintf("文件: %s\n", *pcapFile))
	report.WriteString(fmt.Sprintf("分析时间: %s\n", ts()))
	for _, fact := range result.Facts {
		report.WriteString(fact + "\n")
	}
	for _, iss := range result.Issues {
		report.WriteString(fmt.Sprintf("\n[%s] %s\n  %s\n", iss.Severity, iss.Title, iss.Explain))
	}
	if err := os.WriteFile(*output, []byte(report.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 报告写入失败: %v\n", err)
	} else {
		fmt.Printf("✅ 报告已生成: %s\n", *output)
	}
}

// cmdPlatform 平台侧体检（模拟摄像头注册到真实上级平台）。
func cmdPlatform(args []string) {
	fs := flag.NewFlagSet("platform", flag.ExitOnError)
	serverAddr := fs.String("server", "", "上级平台地址 host:port（必填）")
	serverID := fs.String("server-id", "34020000002000000001", "上级平台编码")
	deviceID := fs.String("device-id", "34020000001320000001", "模拟设备编码")
	password := fs.String("password", "12345678", "鉴权密码")
	transport := fs.String("transport", "udp", "传输协议: udp/tcp")
	timeout := fs.Duration("timeout", 15*time.Second, "检测超时")
	_ = fs.Parse(args)

	if *serverAddr == "" {
		fmt.Fprintln(os.Stderr, "❌ 请用 -server 指定上级平台地址")
		os.Exit(2)
	}

	fmt.Printf("GBDoctor 平台侧体检 %s\n", version)
	fmt.Printf("  目标平台: %s\n", *serverAddr)
	fmt.Printf("  设备编码: %s\n", *deviceID)

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: *serverAddr,
		ServerID:   *serverID,
		DeviceID:   *deviceID,
		Password:   *password,
		Transport:  *transport,
		Timeout:    5 * time.Second,
	})
	defer cam.Close()

	result := sip.CheckPlatform(cam, *serverID, *timeout)

	fmt.Println(strings.Repeat("-", 46))
	fmt.Printf("注册: %v (算法=%s)\n", result.RegisterOK, result.RegisterAlg)
	fmt.Printf("心跳: %v\n", result.KeepaliveOK)
	fmt.Printf("目录查询: %v\n", result.CatalogQueryOK)
	fmt.Printf("设备信息: %v\n", result.DeviceInfoOK)
	fmt.Printf("点播: %v\n", result.InviteOK)

	for _, fact := range result.Facts {
		fmt.Printf("  %s\n", fact)
	}

	if len(result.Issues) > 0 {
		fmt.Println(strings.Repeat("-", 46))
		fmt.Printf("发现问题 %d 个:\n", len(result.Issues))
		for _, iss := range result.Issues {
			fmt.Printf("  [%s] %s\n", iss.Severity, iss.Title)
		}
	}
}
