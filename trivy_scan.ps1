# Script pour scanner l'IaC avec Trivy
#  TP4 Question 4
$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Blue
Write-Host "  Trivy IaC Security Scanning - TP4" -ForegroundColor Blue
Write-Host "========================================" -ForegroundColor Blue
Write-Host ""

# Créer le répertoire pour les rapports
$REPORT_DIR = "trivy-reports"
if (-not (Test-Path $REPORT_DIR)) {
    New-Item -ItemType Directory -Path $REPORT_DIR | Out-Null
}

Write-Host "Repertoire des rapports: $REPORT_DIR" -ForegroundColor Blue
Write-Host ""

# Scanner tous les fichiers yml/yaml
Write-Host "Recherche des fichiers IaC..." -ForegroundColor Yellow
$IacFiles = @()
$IacFiles += Get-ChildItem -Path . -Filter *.yml -File | Select-Object -ExpandProperty Name
$IacFiles += Get-ChildItem -Path . -Filter *.yaml -File | Select-Object -ExpandProperty Name

if ($IacFiles.Count -eq 0) {
    Write-Host "Aucun fichier .yml ou .yaml trouve!" -ForegroundColor Red
    exit
}

Write-Host "Fichiers IaC a scanner:" -ForegroundColor Yellow
foreach ($file in $IacFiles) {
    Write-Host "   $file" -ForegroundColor Green
}
Write-Host ""

# Question 4.1 - Scan
Write-Host "========================================" -ForegroundColor Blue
Write-Host "  4.1 - Scan des vulnerabilites" -ForegroundColor Blue
Write-Host "========================================" -ForegroundColor Blue
Write-Host ""

foreach ($file in $IacFiles) {
    Write-Host "Scanning: $file" -ForegroundColor Yellow
    Write-Host ""
    trivy config $file --severity MEDIUM,HIGH,CRITICAL --format table
    
    $baseName = $file -replace '\.(yml|yaml)$', ''
    $outputFile = "$REPORT_DIR\$baseName-scan-report.json"
    trivy config $file --severity MEDIUM,HIGH,CRITICAL --format json --output $outputFile
    Write-Host "Rapport sauvegarde: $outputFile" -ForegroundColor Green
    Write-Host ""
}

Write-Host "Scan complet du repertoire..." -ForegroundColor Yellow
trivy config . --severity MEDIUM,HIGH,CRITICAL --format json --output "$REPORT_DIR\full-scan-report.json"
Write-Host "Scan complet sauvegarde: $REPORT_DIR\full-scan-report.json" -ForegroundColor Green
Write-Host ""

# Question 4.2 - Extraction avec jq
Write-Host "========================================" -ForegroundColor Blue
Write-Host "  4.2 - Extraction des CVEs (jq)" -ForegroundColor Blue
Write-Host "========================================" -ForegroundColor Blue
Write-Host ""

# Créer le filtre jq (UTF-8 sans BOM)
$jqFilter = @'
[
  .Results[]? | 
  select(.Misconfigurations != null) | 
  .Misconfigurations[] | 
  select(.Severity == "HIGH") | 
  {
    ID: .ID,
    Title: .Title,
    Description: .Description,
    Severity: .Severity,
    CVSSv3: "N/A",
    References: .References,
    Resource: .CauseMetadata.Resource,
    Provider: .CauseMetadata.Provider
  }
]
'@

# Écrire sans BOM
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
[System.IO.File]::WriteAllText("$PWD\filter.jq", $jqFilter, $Utf8NoBomEncoding)

# Exécuter jq
jq -f filter.jq "$REPORT_DIR\full-scan-report.json" > "$REPORT_DIR\cve.json"

Write-Host "Fichier cve.json cree!" -ForegroundColor Green
Write-Host ""

# Afficher le contenu
Write-Host "Contenu de cve.json:" -ForegroundColor Blue
$cveContent = Get-Content "$REPORT_DIR\cve.json" -Raw
if ($cveContent -and $cveContent.Trim() -ne "[]") {
    Write-Host $cveContent
    Write-Host ""
    # Remove BOM
(Get-Content "$REPORT_DIR\cve.json") | Set-Content "$REPORT_DIR\cve.json" -Encoding utf8

# Count CVEs
        $count = jq -r '. | length' "$REPORT_DIR\cve.json"
        if (-not $count) { $count = 0 }


    Write-Host "Total HIGH Severity: $count" -ForegroundColor Red
} else {
    Write-Host "Aucune vulnerabilite HIGH trouvee" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Distribution des severites:" -ForegroundColor Blue

# Créer le filtre stats
$statsFilter = '[.Results[]?.Misconfigurations[]?.Severity] | group_by(.) | map({severity: .[0], count: length}) | .[] | "\(.severity): \(.count)"'
[System.IO.File]::WriteAllText("$PWD\stats.jq", $statsFilter, $Utf8NoBomEncoding)

$stats = jq -r -f stats.jq "$REPORT_DIR\full-scan-report.json"
if ($stats) {
    $stats | ForEach-Object { Write-Host "  $_" }
}

# Nettoyer
Remove-Item "filter.jq", "stats.jq" -ErrorAction SilentlyContinue

# Rapport final
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Scan termine avec succes!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Fichiers generes dans ${REPORT_DIR}:" -ForegroundColor Cyan
Get-ChildItem -Path $REPORT_DIR | ForEach-Object {
    $size = if ($_.Length -lt 1KB) { "{0:N2} B" -f $_.Length }
            elseif ($_.Length -lt 1MB) { "{0:N2} KB" -f ($_.Length / 1KB) }
            else { "{0:N2} MB" -f ($_.Length / 1MB) }
    Write-Host "  - $($_.Name) ($size)" -ForegroundColor White
}
Write-Host ""