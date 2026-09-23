# AEGIS Feed Refresher for Windows / PowerShell
$ErrorActionPreference = "Stop"

$baseDir = if ($env:AEGIS_DATA_DIR) { $env:AEGIS_DATA_DIR } else { "$PSScriptRoot\..\backend\app\data" }
$blockList = "$baseDir\blocklists"
$geoIp = "$baseDir\geoip"

New-Item -ItemType Directory -Force -Path $blockList | Out-Null
New-Item -ItemType Directory -Force -Path $geoIp | Out-Null

Write-Host "[*] Blocklists refresh ho rahi hain..." -ForegroundColor Cyan

Invoke-WebRequest -Uri "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" -OutFile "$blockList\et-compromised.txt" -UseBasicParsing
Invoke-WebRequest -Uri "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" -OutFile "$blockList\feodo.txt" -UseBasicParsing
Invoke-WebRequest -Uri "https://cinsscore.com/list/ci-badguys.txt" -OutFile "$blockList\ci-badguys.txt" -UseBasicParsing

Write-Host "[*] DB-IP Lite refresh ho rahi hai..." -ForegroundColor Cyan
$month = (Get-Date).ToString("yyyy-MM")
$gzUrl = "https://download.db-ip.com/free/dbip-city-lite-$month.csv.gz"
$gzFile = "$geoIp\dbip-city-lite.csv.gz"
$csvFile = "$geoIp\dbip-city-lite.csv"

try {
    Invoke-WebRequest -Uri $gzUrl -OutFile $gzFile -UseBasicParsing
    
    # Decompress gzip
    $inFile = [System.IO.File]::OpenRead($gzFile)
    $outFile = [System.IO.File]::Create($csvFile)
    $gzStream = New-Object System.IO.Compression.GZipStream($inFile, [System.IO.Compression.CompressionMode]::Decompress)
    $gzStream.CopyTo($outFile)
    $gzStream.Close()
    $outFile.Close()
    $inFile.Close()
    Remove-Item -Force $gzFile
} catch {
    Write-Warning "Could not download/decompress DB-IP Lite: $_"
}

Write-Host "[+] Sab feeds refresh ho gayi: $(Get-Date)" -ForegroundColor Green
