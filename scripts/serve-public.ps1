# serve-public.ps1 - start the AEGIS stack and expose it on a public URL.
#
# Why this exists: `cloudflared tunnel --url ...` creates a *quick tunnel*.
# A quick tunnel is tied to the process that created it: stop the process,
# close the terminal, sleep the laptop, or reboot, and the
# *.trycloudflare.com hostname is released and cannot be recovered. The next
# run gets a brand new random hostname. That is expected behaviour, not a bug
# in AEGIS - so always start the tunnel from here and copy the URL it prints.
#
# Usage (from the repo root):
#   powershell -ExecutionPolicy Bypass -File .\scripts\serve-public.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\serve-public.ps1 -DashboardPort 3000 -ApiPort 8000
#
# Ctrl+C stops the frontend + tunnel started by this script.

param(
    [int]$DashboardPort = 3000,
    [int]$ApiPort = 8000,
    [string]$Cloudflared = "$env:ProgramFiles (x86)\cloudflared\cloudflared.exe"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$FrontendDir = Join-Path $RepoRoot "frontend"
$BackendDir = Join-Path $RepoRoot "backend"
$LogDir = Join-Path $env:TEMP "opencode"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Test-Port([int]$Port) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect("127.0.0.1", $Port)
        $c.Close()
        return $true
    } catch {
        return $false
    }
}

function Wait-Port([int]$Port, [int]$Seconds) {
    for ($i = 0; $i -lt $Seconds; $i++) {
        if (Test-Port $Port) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

Write-Host "== AEGIS public preview ==" -ForegroundColor Cyan

# --- 1. Backend (FastAPI / uvicorn on :8000) ---------------------------------
if (Test-Port $ApiPort) {
    Write-Host "[ok] backend already listening on :$ApiPort" -ForegroundColor Green
} else {
    Write-Host "[..] starting backend on :$ApiPort"
    Start-Process -FilePath "python" `
        -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "$ApiPort" `
        -WorkingDirectory $BackendDir `
        -RedirectStandardOutput (Join-Path $LogDir "aegis-api.log") `
        -RedirectStandardError  (Join-Path $LogDir "aegis-api.err.log") `
        -WindowStyle Hidden
    if (-not (Wait-Port $ApiPort 60)) {
        Write-Host "[!!] backend did not open :$ApiPort - see $LogDir\aegis-api.err.log" -ForegroundColor Red
        exit 1
    }
    Write-Host "[ok] backend up" -ForegroundColor Green
}

# --- 2. Dashboard (Next.js on :3000) ----------------------------------------
# The dev server is used on purpose: it serves the `/api/v1` and `/ws` rewrites
# from next.config.mjs, so the dashboard and the API share one origin and the
# single tunnel below reaches both. `next start` needs a clean `next build`
# first and a dev/build artifact mix in .next breaks it
# ("routesManifest.dataRoutes is not iterable").
$frontendProc = $null
if (Test-Port $DashboardPort) {
    Write-Host "[ok] dashboard already listening on :$DashboardPort" -ForegroundColor Green
} else {
    Write-Host "[..] starting dashboard on :$DashboardPort (next dev)"
    $frontendProc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c", "npm run dev -- -p $DashboardPort > ""$(Join-Path $LogDir 'aegis-web.log')"" 2>&1" `
        -WorkingDirectory $FrontendDir `
        -WindowStyle Hidden -PassThru
    if (-not (Wait-Port $DashboardPort 120)) {
        Write-Host "[!!] dashboard did not open :$DashboardPort - see $LogDir\aegis-web.log" -ForegroundColor Red
        exit 1
    }
    Write-Host "[ok] dashboard up" -ForegroundColor Green
}

# --- 3. Public tunnel --------------------------------------------------------
if (-not (Test-Path $Cloudflared)) {
    $cmd = Get-Command cloudflared -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host "[!!] cloudflared not found. Install it with: winget install Cloudflare.cloudflared" -ForegroundColor Red
        exit 1
    }
    $Cloudflared = $cmd.Source
}

$tunnelLog = Join-Path $LogDir "aegis-tunnel.log"
if (Test-Path $tunnelLog) { Remove-Item $tunnelLog -Force }

Write-Host "[..] opening quick tunnel to http://localhost:$DashboardPort"
$tunnelProc = Start-Process -FilePath $Cloudflared `
    -ArgumentList "tunnel", "--url", "http://localhost:$DashboardPort", "--no-autoupdate", "--logfile", "$tunnelLog", "--loglevel", "info" `
    -WindowStyle Hidden -PassThru

$publicUrl = $null
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $tunnelLog) {
        $m = Select-String -Path $tunnelLog -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" -AllMatches |
             ForEach-Object { $_.Matches } | Select-Object -First 1
        if ($m) { $publicUrl = $m.Value; break }
    }
}

if (-not $publicUrl) {
    Write-Host "[!!] no tunnel URL yet - check $tunnelLog" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Public URL : $publicUrl" -ForegroundColor Yellow
Write-Host "  Login      : admin@aegis.local  (password = AEGIS_ADMIN_PASSWORD in .env)" -ForegroundColor Yellow
Write-Host ""
Write-Host "This URL lives only while this window and the tunnel process stay alive." -ForegroundColor DarkGray
Write-Host "Re-running the script produces a different hostname." -ForegroundColor DarkGray
Write-Host "For a permanent URL, use a named tunnel on your own domain (see README)." -ForegroundColor DarkGray
Write-Host ""

try {
    while (-not $tunnelProc.HasExited) { Start-Sleep -Seconds 2 }
} finally {
    if ($frontendProc -and -not $frontendProc.HasExited) { Stop-Process -Id $frontendProc.Id -Force -ErrorAction SilentlyContinue }
    if ($tunnelProc -and -not $tunnelProc.HasExited) { Stop-Process -Id $tunnelProc.Id -Force -ErrorAction SilentlyContinue }
}
