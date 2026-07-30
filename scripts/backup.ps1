param([string]$Output = ".\backups\rtools_marketplace.sql")
$directory = Split-Path -Parent $Output
if ($directory) { New-Item -ItemType Directory -Force -Path $directory | Out-Null }
docker exec -e MYSQL_PWD=my888888 rtools-marketplace-mysql mysqldump -uroot --single-transaction --routines --triggers rtools_marketplace | Set-Content -Encoding utf8 -Path $Output
if ($LASTEXITCODE -ne 0) { throw "MySQL backup failed" }
Write-Output "Backup written to $Output"
