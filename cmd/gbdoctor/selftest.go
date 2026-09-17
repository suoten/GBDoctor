package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gbdoctor/internal/sip"
)

// cmdSimcam 启动模拟摄像头。
func cmdSimcam(args []string) {
	fs := flag.NewFlagSet("simcam", flag.ExitOnError)
	to := fs.String("to", "127.0.0.1:5060", "平台地址 host:port")
	serverID := fs.String("server-id", "34020000002000000001", "平台编码")
	deviceID := fs.String("device-id", "34020000001320000001", "设备编码")
	password := fs.String("password", "12345678", "鉴权密码")
	transport := fs.String("transport", "udp", "传输协议: udp | tcp")
	interval := fs.Int("keepalive", 60, "心跳周期（秒）")
	_ = fs.Parse(args)

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: *to, ServerID: *serverID,
		DeviceID: *deviceID, Password: *password,
		Transport: *transport, Timeout: 5 * time.Second,
	})
	defer cam.Close()

	fmt.Printf("GBDoctor 模拟摄像头 %s\n", version)
	fmt.Printf("  目标: %s (编码 %s)  设备: %s  传输: %s\n", *to, *serverID, *deviceID, *transport)

	resp, alg, err := cam.Register()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 注册失败: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "❌ 注册被拒绝: %d %s\n", resp.StatusCode, resp.ReasonPhrase)
		os.Exit(1)
	}
	fmt.Printf("[%s] ✅ 注册成功 (鉴权算法=%s)\n", ts(), alg)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()
	sn := 0
	for {
		select {
		case <-sig:
			fmt.Println("\n退出")
			return
		case <-ticker.C:
			sn++
			if resp, err := cam.Keepalive(sn); err != nil {
				fmt.Printf("[%s] ❌ 心跳失败: %v\n", ts(), err)
			} else {
				fmt.Printf("[%s] ✅ 心跳 %d → %d\n", ts(), sn, resp.StatusCode)
			}
		}
	}
}

// cmdSelftest 本机回环自检：模拟平台 ↔ 模拟摄像头全链路。
func cmdSelftest() {
	fmt.Printf("GBDoctor 自检 %s\n", version)
	fmt.Println(strings.Repeat("-", 46))

	role := sip.NewDeviceSideRole(sip.RoleConfig{
		Host: "127.0.0.1", Port: 0,
		ServerID: "34020000002000000001", Password: "selftest",
	})
	if err := role.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 模拟平台启动失败: %v\n", err)
		os.Exit(1)
	}
	defer role.Cleanup()

	registered := make(chan sip.RegisterFact, 4)
	keepalive := make(chan sip.KeepaliveFact, 4)
	role.OnRegister(func(f sip.RegisterFact) { registered <- f })
	role.OnKeepalive(func(f sip.KeepaliveFact) { keepalive <- f })

	port := role.LocalPort()
	fmt.Printf("✅ 模拟平台已启动 127.0.0.1:%d\n", port)

	cam := sip.NewCameraSideRole(sip.CameraConfig{
		ServerAddr: "127.0.0.1:" + strconv.Itoa(port),
		ServerID:   "34020000002000000001",
		DeviceID:   "34020000001320000001",
		Password:   "selftest",
		Timeout:    3 * time.Second,
	})
	defer cam.Close()

	fail := false
	resp, alg, err := cam.Register()
	if err != nil || resp.StatusCode != 200 {
		fmt.Printf("❌ 注册环节: err=%v code=%d\n", err, resp.StatusCode)
		fail = true
	} else {
		fmt.Printf("✅ 注册环节: 401 质询 → 鉴权 → 200 OK（算法 %s）\n", alg)
	}
	if resp2, err := cam.Keepalive(1); err != nil || resp2.StatusCode != 200 {
		fmt.Printf("❌ 保活环节: err=%v\n", err)
		fail = true
	} else {
		fmt.Printf("✅ 保活环节: MESSAGE Keepalive → 200 OK\n")
	}

	// 排空 challenge 事实，确认 registered 事实已产出
	deadline := time.After(2 * time.Second)
sawRegistered:
	for {
		select {
		case f := <-registered:
			if f.Kind == "registered" {
				break sawRegistered
			}
		case <-deadline:
			fmt.Println("❌ 事实链: 未收到 registered 事实")
			fail = true
			break sawRegistered
		}
	}
	select {
	case f := <-keepalive:
		fmt.Printf("✅ 事实链: registered + keepalive 事实均已产出（设备 %s）\n", f.DeviceID)
	default:
		fmt.Println("❌ 事实链: 未收到 keepalive 事实")
		fail = true
	}

	evCount := role.Evidence().Count()
	if evCount == 0 {
		fmt.Println("❌ 证据链: 无证据记录")
		fail = true
	} else {
		fmt.Printf("✅ 证据链: %d 条证据（原文 + SHA-256 指纹 + 鉴权头脱敏）\n", evCount)
	}

	fmt.Println(strings.Repeat("-", 46))
	if fail {
		fmt.Println("自检结果：❌ 未通过")
		os.Exit(1)
	}
	fmt.Println("自检结果：✅ 通过（M1 全链路就绪，可用 sipsim 接入真机验收）")
}
