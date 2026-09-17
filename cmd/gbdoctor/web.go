package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gbdoctor/internal/web"
)

// cmdWeb 启动 Web UI 服务器。
// gbdoctor web [flags]
// -port  HTTP 端口（默认 8080）
// -open  是否自动打开浏览器（默认 true）
func cmdWeb(args []string) {
	port := 8080
	openBrowser := true

	// 简单 flag 解析
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-port" || args[i] == "--port":
			if i+1 < len(args) {
				if p, err := strconv.Atoi(args[i+1]); err == nil {
					port = p
				}
				i++
			}
		case args[i] == "-no-open" || args[i] == "--no-open":
			openBrowser = false
		case args[i] == "-help" || args[i] == "--help" || args[i] == "-h":
			fmt.Println(`gbdoctor web [flags]

启动 Web UI 服务器（含诊断 API + 实时 WebSocket 推送）。

Flags:
  -port int    HTTP 端口（默认 8080）
  -no-open     不自动打开浏览器`)
			return
		}
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// 检查端口是否被占用
	if ln, err := net.Listen("tcp", addr); err != nil {
		// 端口被占用，尝试下一个
		logf("端口 %d 被占用，尝试下一个端口...", port)
		found := false
		for p := port + 1; p <= port+10; p++ {
			addr = fmt.Sprintf("127.0.0.1:%d", p)
			if ln2, err2 := net.Listen("tcp", addr); err2 == nil {
				ln2.Close()
				port = p
				addr = fmt.Sprintf("127.0.0.1:%d", port)
				found = true
				break
			}
		}
		if !found {
			msg := fmt.Sprintf("无法绑定端口 %d-%d，可能被其他程序占用。\n请关闭占用端口的程序后重试，\n或使用命令行指定端口: gbdoctor web -port 9000", port, port+10)
			logf("错误: %s", msg)
			alertBox(msg)
			os.Exit(1)
		}
	} else {
		ln.Close()
	}

	server := web.NewServer(version)
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	logf("GBDoctor Web UI %s", version)
	logf("地址: %s", url)
	logf("按 Ctrl+C 退出")
	logf("%s", strings.Repeat("-", 46))

	if openBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond) // 等服务器就绪
			openURL(url)
		}()
	}

	if err := server.Start(addr); err != nil {
		msg := fmt.Sprintf("Web 服务器启动失败: %v", err)
		logf("错误: %s", msg)
		alertBox(msg)
		os.Exit(1)
	}
}

// openURL 跨平台打开浏览器。
func openURL(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // linux 等
		cmd = "xdg-open"
		args = []string{url}
	}

	exec.Command(cmd, args...).Start()
}

// logf 输出日志到 stderr（CLI 模式）和日志文件（GUI 模式）。
func logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, msg)

	// 在 Windows GUI 模式下（无控制台），同时写到日志文件
	if runtime.GOOS == "windows" {
		exePath, _ := os.Executable()
		logPath := filepath.Join(filepath.Dir(exePath), "gbdoctor.log")
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			fmt.Fprintln(f, msg)
			f.Close()
		}
	}
}

// alertBox 在 Windows 上弹出原生消息框，其他平台输出到 stderr。
func alertBox(msg string) {
	if runtime.GOOS == "windows" {
		// 用 PowerShell 弹出消息框，不依赖任何外部库
		escaped := strings.ReplaceAll(msg, `'`, `''`)
		escaped = strings.ReplaceAll(escaped, "\n", "`n")
		psScript := fmt.Sprintf("Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('%s', 'GBDoctor', 'OK', 'Error')", escaped)
		exec.Command("powershell", "-NoProfile", "-Command", psScript).Run()
	} else {
		fmt.Fprintf(os.Stderr, "错误: %s\n", msg)
	}
}
