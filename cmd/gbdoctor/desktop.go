package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gbdoctor/internal/web"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

// App 是 Wails 桌面应用入口。
// 它在后台启动 HTTP 服务器（保持 REST API + WebSocket 不变），
// 然后在 WebView2 窗口中通过 AssetServer 代理加载该页面。
type App struct {
	ctx    context.Context
	server *web.Server
	port   int
}

// NewApp 创建桌面应用实例。
func NewApp(ver string) *App {
	return &App{
		server: web.NewServer(ver),
	}
}

// Startup 在 Wails 启动时被调用。
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	fmt.Println("[desktop] Wails Startup called")
}

// findFreePort 找一个可用端口，start=0 表示随机分配。
func findFreePort(start int) int {
	if start == 0 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0
		}
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	}
	for p := start; p <= start+20; p++ {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		if ln, err := net.Listen("tcp", addr); err == nil {
			ln.Close()
			return p
		}
	}
	return 0
}

// proxyHandler 将 Wails AssetServer 请求代理到内嵌 HTTP 服务器。
type proxyHandler struct {
	app *App
}

// ServeHTTP 代理请求到内嵌 HTTP 服务器。
func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 等待 HTTP 服务器就绪
	for i := 0; i < 100; i++ {
		if h.app.port > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if h.app.port == 0 {
		http.Error(w, "HTTP 服务器未就绪", http.StatusServiceUnavailable)
		return
	}

	target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", h.app.port))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ServeHTTP(w, r)
}

// cmdDesktop 启动 Wails 桌面应用（WebView2 窗口）。
//
// 发布版使用 -H windowsgui 编译（无控制台），任何启动失败都不能
// 只打印到 stderr —— 那样用户双击后什么也看不到，表现为“根本打不开”。
// 因此这里做了三层保障：
//
//  1. 启动前检测 WebView2 Runtime（注册表），缺失时不走 Wails，
//     直接弹窗说明并自动回退浏览器模式；
//  2. 所有启动日志经 logf 写入 exe 同目录 gbdoctor.log，留下现场；
//  3. Wails 启动失败时弹窗报错并回退浏览器模式，进程不静默退出。
func cmdDesktop() {
	app := NewApp(version)

	// 先启动 HTTP 服务器
	app.port = findFreePort(18080)
	if app.port == 0 {
		app.port = findFreePort(0)
	}
	if app.port == 0 {
		logf("[desktop] 错误: 无法找到可用端口")
		alertBox("无法找到可用端口，请检查系统网络配置后重试。")
		return
	}

	addr := fmt.Sprintf("127.0.0.1:%d", app.port)
	webURL := fmt.Sprintf("http://127.0.0.1:%d", app.port)
	logf("[desktop] 启动 HTTP 服务器: %s", addr)
	go func() {
		if err := app.server.Start(addr); err != nil {
			logf("[desktop] HTTP 服务器启动失败: %v", err)
		}
	}()

	// 等待 HTTP 服务器就绪
	for i := 0; i < 100; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			logf("[desktop] HTTP 服务器就绪")
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 保障 1：WebView2 Runtime 缺失时直接回退浏览器模式，不启动 Wails
	if !webView2Available() {
		msg := "未检测到 WebView2 Runtime，桌面窗口无法启动。\n\n" +
			"已自动改用浏览器模式，请在即将弹出的浏览器页面中操作。\n" +
			"界面地址: " + webURL + "\n\n" +
			"如需桌面窗口，请安装 Microsoft Edge WebView2 Runtime\n" +
			"（https://developer.microsoft.com/microsoft-edge/webview2/）"
		logf("[desktop] %s", msg)
		alertBox(msg)
		openURL(webURL)
		waitDesktopExit()
		return
	}

	logf("[desktop] 启动 Wails 窗口...")
	err := wails.Run(&options.App{
		Title:     "GBDoctor - GB/T 28181 接入诊断工具",
		Width:     1280,
		Height:    860,
		MinWidth:  960,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Handler: &proxyHandler{app: app},
		},
		OnStartup: app.Startup,
		Bind:      []interface{}{app},
	})

	// 保障 3：Wails 失败（WebView2 加载异常等）时弹窗报错并回退浏览器
	if err != nil {
		msg := fmt.Sprintf("桌面窗口启动失败: %v\n\n已自动改用浏览器模式，界面地址: %s\n进程将驻留后台（任务管理器中结束 gbdoctor.exe 可退出）。", err, webURL)
		logf("[desktop] %s", msg)
		alertBox(msg)
		openURL(webURL)
		waitDesktopExit()
		return
	}
	logf("[desktop] Wails 已退出")
}

// waitDesktopExit 阻塞直到收到退出信号（浏览器回退模式下保持进程存活）。
func waitDesktopExit() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logf("[desktop] 收到退出信号")
}
