//go:build windows

package main

import "golang.org/x/sys/windows/registry"

// webView2Available 检查本机是否安装 WebView2 Runtime。
// 依据 EdgeUpdate\Clients 下 WebView2（固定 GUID）的 pv 版本号判断，
// 覆盖 Evergreen（HKLM/HKCU）与固定版本两种安装方式。
// 仅在 Windows 上编译（x/sys/windows/registry 为 Windows 专有包），
// 非 Windows 平台由 webview2_other.go 提供。
func webView2Available() bool {
	const webview2Key = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
	views := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + webview2Key},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webview2Key},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webview2Key},
	}
	for _, v := range views {
		k, err := registry.OpenKey(v.root, v.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		pv, _, err := k.GetStringValue("pv")
		k.Close()
		if err == nil && pv != "" && pv != "0.0.0.0" {
			return true
		}
	}
	return false
}
