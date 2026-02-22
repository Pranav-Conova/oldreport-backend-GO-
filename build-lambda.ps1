# build-lambda.ps1
# Builds the Go binary for AWS Lambda (linux/amd64) and packages it as a zip.
#
# Usage:
#   .\build-lambda.ps1              # builds for linux/amd64 (default)
#   .\build-lambda.ps1 -Arch arm64  # builds for linux/arm64 (Graviton2)
#
# Output: dist\lambda.zip  — upload this to your Lambda function.

param(
    [ValidateSet("amd64", "arm64")]
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

$distDir   = Join-Path $PSScriptRoot "dist"
$bootstrap = Join-Path $distDir "bootstrap"
$zipFile   = Join-Path $distDir "lambda.zip"

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir | Out-Null
}

Write-Host "Building for linux/$Arch ..." -ForegroundColor Cyan

$env:GOOS   = "linux"
$env:GOARCH = $Arch
$env:CGO_ENABLED = "0"   # static binary — required on Lambda

go build -trimpath -ldflags="-s -w" -o $bootstrap .

if ($LASTEXITCODE -ne 0) {
    Write-Error "go build failed"
    exit 1
}

# Remove old zip if it exists
if (Test-Path $zipFile) { Remove-Item $zipFile }

Compress-Archive -Path $bootstrap -DestinationPath $zipFile

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host "  Binary : $bootstrap"
Write-Host "  Package: $zipFile"
Write-Host ""
Write-Host "Deploy with:" -ForegroundColor Yellow
Write-Host "  aws lambda update-function-code --function-name <your-function> --zip-file fileb://dist/lambda.zip"

# Reset env vars so the PowerShell session stays usable for normal builds
Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
