//go:build !windows

package main

// webView2Available 非 Windows 平台无 WebView2 概念，
// 交由 Wails 自行处理，直接返回 true。
func webView2Available() bool {
	return true
}
