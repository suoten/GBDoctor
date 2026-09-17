# GBDoctor 发布打包脚本
# 用法: powershell -ExecutionPolicy Bypass -File make-release.ps1
# 用法: powershell -ExecutionPolicy Bypass -File make-release.ps1 -Version 1.3.0
# 产出: release/gbdoctor-<version>-<platform>.zip (每个包包含二进制+安装脚本+README)
#
# 流程:
#   1. 交叉编译多平台二进制 (CGO_ENABLED=0 纯 Go，无 C 依赖)
#   2. 打包发布 zip（二进制 + install.sh + README.md）
#   3. 生成 SHA256 校验文件

param(
    [string]$Version = "1.2.0"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  GBDoctor v$Version Release Builder" -ForegroundColor Cyan
Write-Host "  GB/T 28181 接入诊断工具" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# 0. 检查前置条件
# ============================================================
Write-Host "[0/4] Checking prerequisites..." -ForegroundColor Green

$goCmd = Get-Command go -ErrorAction SilentlyContinue
if (-not $goCmd) {
    Write-Host "ERROR: Go is not installed or not in PATH" -ForegroundColor Red
    Write-Host "  Please install Go 1.24+ from https://go.dev/dl/" -ForegroundColor Yellow
    exit 1
}

$goVersion = (go version 2>$null)
Write-Host "  Go: $goVersion" -ForegroundColor DarkGray

# 确保依赖已下载
Write-Host "  Checking Go dependencies..." -ForegroundColor DarkGray
$env:GOPROXY = "https://goproxy.cn,direct"
& go mod tidy 2>&1 | Out-Null
Write-Host "  Dependencies OK" -ForegroundColor DarkGray

# ============================================================
# 1. 编译多平台二进制
#    纯 Go 实现，CGO_ENABLED=0，无需 C 编译器即可交叉编译
# ============================================================
Write-Host "[1/4] Building multi-platform binaries..." -ForegroundColor Green

$distDir = "dist"
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

$buildTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$gitCommit = "unknown"
try {
    $gitCommit = (git rev-parse --short HEAD 2>$null).Trim()
} catch {}

$ldflags = "-s -w -X main.version=$Version -X main.buildTime=$buildTime -X main.gitCommit=$gitCommit"
$binaries = @{}

# --- 重新生成 Windows 版本资源（syso）---
# exe 的图标、版本属性（右键-属性-详细信息）、GUI manifest 都来自
# cmd/gbdoctor/rsrc_windows_amd64.syso，必须随 $Version 重新生成，
# 否则 Explorer 里永远是旧版本号、旧图标。需要 go-winres 工具。
$winres = "$env:USERPROFILE\go\bin\go-winres.exe"
if (-not (Test-Path $winres)) {
    Write-Host "  Installing go-winres (resource compiler)..." -ForegroundColor DarkGray
    & go install github.com/tc-hib/go-winres@latest 2>&1 | Out-Null
    if (-not (Test-Path $winres)) {
        Write-Host "ERROR: go-winres install failed; cannot embed icon/version resources" -ForegroundColor Red
        exit 1
    }
}
$icoFile = "build/windows/icon.ico"
if (-not (Test-Path $icoFile)) {
    Write-Host "ERROR: $icoFile not found (exe icon source)" -ForegroundColor Red
    exit 1
}
Write-Host "  Regenerating version resource (icon + v$Version + GUI manifest)..." -ForegroundColor DarkGray
$verNum = "$Version.0"  # 1.3.0 -> 1.3.0.0（Windows 资源要求四段版本号）
# 注意：--manifest 用 none 而非 gui —— 实测 go-winres 的 gui manifest
# 会导致 Wails 窗口创建后立即静默退出（窗口一闪而过/双击无反应）。
# Wails 自身在运行时设置 DPI 感知，无 manifest 不影响功能。
& $winres simply --arch amd64 --icon $icoFile --manifest none `
    --product-name "GBDoctor" --file-description "GB/T 28181 接入诊断工具" `
    --product-version $verNum --file-version $verNum --original-filename "gbdoctor.exe" `
    --out cmd/gbdoctor/rsrc 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "cmd/gbdoctor/rsrc_windows_amd64.syso")) {
    Write-Host "ERROR: go-winres simply failed" -ForegroundColor Red
    exit 1
}

# --- Windows amd64 (桌面应用：Wails WebView2 + GUI 子系统) ---
# -tags production: Wails v2 需要 production build tag 才能启用 WebView2 前端
# -H windowsgui: 隐藏控制台窗口，双击运行时直接弹出桌面窗口
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
$out = "$distDir/gbdoctor-windows-amd64.exe"
Write-Host "  Building windows/amd64 (Wails desktop + GUI subsystem)..." -ForegroundColor DarkGray
$prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$winLdflags = "$ldflags -H windowsgui"
& go build -tags production -ldflags="$winLdflags" -o $out ./cmd/gbdoctor/ 2>&1 | Out-Null
$buildExit = $LASTEXITCODE; $ErrorActionPreference = $prevEAP
if ($buildExit -ne 0 -or -not (Test-Path $out)) {
    Write-Host "ERROR: Build failed for windows-amd64 (exit $buildExit)" -ForegroundColor Red
    exit 1
}
$binaries["gbdoctor-windows-amd64.exe"] = $out
Write-Host "    -> gbdoctor-windows-amd64.exe ($([math]::Round((Get-Item $out).Length / 1MB, 1)) MB)" -ForegroundColor Yellow

# --- Linux amd64 ---
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"; $env:GOPROXY = "https://goproxy.cn,direct"
$out = "$distDir/gbdoctor-linux-amd64"
Write-Host "  Building linux/amd64..." -ForegroundColor DarkGray
$prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& go build -ldflags="$ldflags" -o $out ./cmd/gbdoctor/ 2>&1 | Out-Null
$buildExit = $LASTEXITCODE; $ErrorActionPreference = $prevEAP
if ($buildExit -ne 0 -or -not (Test-Path $out)) {
    Write-Host "ERROR: Build failed for linux-amd64 (exit $buildExit)" -ForegroundColor Red
    exit 1
}
$binaries["gbdoctor-linux-amd64"] = $out
Write-Host "    -> gbdoctor-linux-amd64 ($([math]::Round((Get-Item $out).Length / 1MB, 1)) MB)" -ForegroundColor Yellow

# --- Linux arm64 ---
$env:GOOS = "linux"; $env:GOARCH = "arm64"; $env:CGO_ENABLED = "0"; $env:GOPROXY = "https://goproxy.cn,direct"
$out = "$distDir/gbdoctor-linux-arm64"
Write-Host "  Building linux/arm64..." -ForegroundColor DarkGray
$prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& go build -ldflags="$ldflags" -o $out ./cmd/gbdoctor/ 2>&1 | Out-Null
$buildExit = $LASTEXITCODE; $ErrorActionPreference = $prevEAP
if ($buildExit -ne 0 -or -not (Test-Path $out)) {
    Write-Host "ERROR: Build failed for linux-arm64 (exit $buildExit)" -ForegroundColor Red
    exit 1
}
$binaries["gbdoctor-linux-arm64"] = $out
Write-Host "    -> gbdoctor-linux-arm64 ($([math]::Round((Get-Item $out).Length / 1MB, 1)) MB)" -ForegroundColor Yellow

# --- macOS amd64 ---
$env:GOOS = "darwin"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"; $env:GOPROXY = "https://goproxy.cn,direct"
$out = "$distDir/gbdoctor-darwin-amd64"
Write-Host "  Building darwin/amd64..." -ForegroundColor DarkGray
$prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& go build -ldflags="$ldflags" -o $out ./cmd/gbdoctor/ 2>&1 | Out-Null
$buildExit = $LASTEXITCODE; $ErrorActionPreference = $prevEAP
if ($buildExit -ne 0 -or -not (Test-Path $out)) {
    Write-Host "WARNING: Build failed for darwin-amd64 (exit $buildExit), skipping..." -ForegroundColor Yellow
} else {
    $binaries["gbdoctor-darwin-amd64"] = $out
    Write-Host "    -> gbdoctor-darwin-amd64 ($([math]::Round((Get-Item $out).Length / 1MB, 1)) MB)" -ForegroundColor Yellow
}

# 清理交叉编译环境变量
$env:GOOS = ""; $env:GOARCH = ""; $env:CGO_ENABLED = ""
Write-Host "  All binaries built OK" -ForegroundColor DarkGray

# ============================================================
# 2. 准备打包文件
# ============================================================
Write-Host "[2/4] Preparing package files..." -ForegroundColor Green

# Linux 公共文件
$linuxFiles = @(
    @{ Src="install.sh";       Dst="install.sh" }
)

# 确保 install.sh 存在
if (-not (Test-Path "install.sh")) {
    Write-Host "  install.sh not found, creating minimal version..." -ForegroundColor DarkGray
    # install.sh 由本脚本旁边的 install.sh 文件提供
}

# ============================================================
# 3. 打包发布 zip
# ============================================================
Write-Host "[3/4] Creating release packages..." -ForegroundColor Green

$releaseDir = "release"
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

# 打包函数
function Package-Zip($tag, $binKey, $winBin, $extraFiles) {
    $ext = if ($winBin) { ".exe" } else { "" }
    $pkgDir = "release/gbdoctor-$tag-pkg"
    # 清理旧打包目录：防止上次运行残留的 gbdoctor.log 等旧文件混进发布包
    if (Test-Path $pkgDir) {
        Remove-Item $pkgDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null

    # 复制二进制
    Copy-Item $binaries[$binKey] "$pkgDir/gbdoctor$ext" -Force

    # 复制 README
    if (Test-Path "README.md") {
        Copy-Item "README.md" "$pkgDir/README.md" -Force
    }

    # 复制额外文件
    if ($extraFiles) {
        foreach ($f in $extraFiles) {
            if (Test-Path $f.Src) {
                Copy-Item $f.Src "$pkgDir/$($f.Dst)" -Force
            }
        }
    }

    # 打 zip 包
    $zipball = "release/gbdoctor-$Version-$tag.zip"
    Write-Host "  Creating $zipball..." -ForegroundColor DarkGray
    Compress-Archive -Path "$pkgDir/*" -DestinationPath $zipball -Force

    $size = [math]::Round((Get-Item $zipball).Length / 1MB, 1)
    Write-Host "    -> $zipball ($size MB)" -ForegroundColor Yellow
}

# 打包 Windows amd64
Package-Zip -tag "windows-amd64" -binKey "gbdoctor-windows-amd64.exe" -winBin $true -extraFiles $null

# 打包 Linux amd64
Package-Zip -tag "linux-amd64" -binKey "gbdoctor-linux-amd64" -winBin $false -extraFiles $linuxFiles

# 打包 Linux arm64
Package-Zip -tag "linux-arm64" -binKey "gbdoctor-linux-arm64" -winBin $false -extraFiles $linuxFiles

# 打包 macOS amd64（如果构建成功）
if ($binaries.ContainsKey("gbdoctor-darwin-amd64")) {
    Package-Zip -tag "darwin-amd64" -binKey "gbdoctor-darwin-amd64" -winBin $false -extraFiles $null
}

# ============================================================
# 4. 生成 SHA256 校验文件
# ============================================================
Write-Host "[4/4] Generating checksums..." -ForegroundColor Green
Push-Location $releaseDir
$hashes = Get-ChildItem -Filter "*.zip" | ForEach-Object {
    $hash = (Get-FileHash $_.Name -Algorithm SHA256).Hash
    "$hash  $($_.Name)"
}
$hashes | Out-File -Encoding ASCII -FilePath "checksums.txt"
Pop-Location

# ============================================================
# 输出结果
# ============================================================
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Release packages created:" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Get-ChildItem $releaseDir -Filter "*.zip" | ForEach-Object {
    $size = if ($_.Length -gt 1MB) { "$([math]::Round($_.Length/1MB,1)) MB" } else { "$([math]::Round($_.Length/1KB,0)) KB" }
    Write-Host "  release/$($_.Name)  ($size)" -ForegroundColor White
}
Write-Host ""
Write-Host "  release/checksums.txt  (SHA256)" -ForegroundColor White
Write-Host ""
Write-Host "Each package contains:" -ForegroundColor Cyan
Write-Host "  gbdoctor                <- binary" -ForegroundColor DarkGray
Write-Host "  install.sh              <- one-click installer (Linux only)" -ForegroundColor DarkGray
Write-Host "  README.md               <- full documentation (bilingual)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Windows deploy:" -ForegroundColor Yellow
Write-Host "  1. Extract gbdoctor-$Version-windows-amd64.zip" -ForegroundColor Yellow
Write-Host "  2. Double-click gbdoctor.exe" -ForegroundColor Yellow
Write-Host "     (桌面模式需要 Microsoft Edge WebView2 Runtime；" -ForegroundColor Yellow
Write-Host "      未安装时程序会弹窗提示并自动改用浏览器模式)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Linux deploy:" -ForegroundColor Yellow
Write-Host "  1. Upload zip to server" -ForegroundColor Yellow
Write-Host "  2. unzip gbdoctor-$Version-linux-amd64.zip" -ForegroundColor Yellow
Write-Host "  3. sudo bash install.sh" -ForegroundColor Yellow
Write-Host ""
