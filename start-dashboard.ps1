$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $settingsPath = Join-Path $PSScriptRoot '.env'
    if (Test-Path -LiteralPath $settingsPath) {
        foreach ($line in Get-Content -LiteralPath $settingsPath -Encoding UTF8) {
            $entry = $line.Trim()
            if (!$entry -or $entry.StartsWith('#')) { continue }
            $parts = $entry.Split('=', 2)
            if ($parts.Length -ne 2 -or $parts[0] -notmatch '^DEVSECOPS_[A-Z0-9_]+$') {
                throw 'Invalid entry in .env'
            }
            $value = $parts[1].Trim()
            if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            [Environment]::SetEnvironmentVariable($parts[0], $value, 'Process')
        }
    }
    & (Join-Path $PSScriptRoot '.venv/Scripts/python.exe') -m uvicorn api.app:app --host 127.0.0.1 --port 8000
    $serverExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $serverExitCode
