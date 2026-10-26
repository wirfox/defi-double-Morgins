<#
  Déchiffre les sauvegardes Défi Double récupérées sur OneDrive, depuis un PC Windows.
  Sert surtout si le Raspberry Pi est perdu : il suffit de rclone (rclone.org/downloads)
  et des deux mots de passe du chiffrement (mot de passe + salt, dans Proton Pass).
  Aucune configuration rclone n'est créée ni enregistrée.

  Utilisation, dans PowerShell (Bypass : Windows bloque par défaut les scripts téléchargés) :
    powershell -ExecutionPolicy Bypass -File .\dechiffrer-sauvegarde.ps1 -Source C:\Users\Moi\Downloads\chiffre

  -Source : un DOSSIER de fichiers téléchargés depuis OneDrive, ou UN SEUL fichier.
            Ne renomme pas les fichiers : leur nom illisible est chiffré lui aussi.
  -Sortie : où écrire les fichiers déchiffrés (par défaut : un dossier « dechiffre-… »
            à côté de la source, ou dans le dossier temporaire de Windows si la source
            est dans OneDrive). Les .json.gz sont aussi décompressés en .json.
  -Rclone : chemin de rclone.exe, s'il n'est pas trouvé tout seul.

  Les mots de passe sont demandés masqués : ils ne s'affichent pas et ne restent pas
  dans l'historique de PowerShell.
#>
param(
  [Parameter(Mandatory = $true)][string]$Source,
  [string]$Sortie,
  [string]$Rclone
)
$ErrorActionPreference = 'Stop'

$tempDir = $null
function Stop-WithError([string]$message) {
  if ($script:tempDir) { Remove-Item -LiteralPath $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Host "`nDéchiffrement ANNULÉ : $message" -ForegroundColor Red
  exit 1
}

# ---------- rclone ----------
function Find-Rclone {
  if ($Rclone) {
    if (Test-Path -LiteralPath $Rclone -PathType Leaf) { return (Resolve-Path -LiteralPath $Rclone).Path }
    Stop-WithError "rclone introuvable à l'emplacement donné : $Rclone"
  }
  foreach ($dir in @($PSScriptRoot, (Get-Location).Path)) {
    foreach ($name in @('rclone.exe', 'rclone')) {
      $p = Join-Path $dir $name
      if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }
  }
  $cmd = Get-Command rclone -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  if ($env:USERPROFILE -and (Test-Path -LiteralPath (Join-Path $env:USERPROFILE 'Downloads'))) {
    $downloads = Join-Path $env:USERPROFILE 'Downloads'
    $found = Get-ChildItem -LiteralPath $downloads -Filter 'rclone.exe' -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
  }
  Stop-WithError "rclone introuvable. Télécharge-le sur rclone.org/downloads, ou indique son chemin avec -Rclone."
}

# ---------- mots de passe ----------
function Read-Secret([string]$label) {
  $secure = Read-Host -Prompt $label -AsSecureString
  $plain = [System.Net.NetworkCredential]::new('', $secure).Password
  if (-not $plain) { Stop-WithError "$label vide : le collage n'a pas marché. Colle avec un clic droit, puis Entrée." }
  return $plain
}

# rclone attend les mots de passe « obscurcis ». On les lui passe par l'entrée standard
# (rclone obscure -) plutôt qu'en argument : les guillemets ou symboles d'un mot de passe
# ne peuvent alors pas casser la commande.
function Get-Obscured([string]$rc, [string]$plain) {
  $ErrorActionPreference = 'Continue'  # Windows PowerShell 5.1 : sinon un message de rclone sur stderr arrête tout
  $out = $plain | & $rc obscure - 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $out) { Stop-WithError "rclone n'a pas pu préparer le mot de passe." }
  return ([string]($out | Select-Object -Last 1)).Trim()
}

# ---------- décompression des .json.gz ----------
function Expand-Gzip([string]$gzPath) {
  $jsonPath = $gzPath.Substring(0, $gzPath.Length - 3)
  $in = [System.IO.File]::OpenRead($gzPath)
  try {
    $gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
    $out = [System.IO.File]::Create($jsonPath)
    try { $gz.CopyTo($out) } finally { $out.Dispose(); $gz.Dispose() }
  } finally { $in.Dispose() }
  return $jsonPath
}

# ---------- programme ----------
$rc = Find-Rclone
$OutputEncoding = New-Object System.Text.UTF8Encoding $false

if (-not (Test-Path -LiteralPath $Source)) { Stop-WithError "« $Source » n'existe pas." }
$sourceItem = Get-Item -LiteralPath $Source
if ($sourceItem.PSIsContainer) {
  $cryptDir = $sourceItem.FullName
  $parent = $sourceItem.Parent.FullName
} else {
  # Un seul fichier : on le copie dans un dossier temporaire, rclone travaille sur des dossiers.
  $script:tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('dd-dechiffre-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tempDir | Out-Null
  Copy-Item -LiteralPath $sourceItem.FullName -Destination $tempDir
  $cryptDir = $tempDir
  $parent = $sourceItem.DirectoryName
}
if (-not (Get-ChildItem -LiteralPath $cryptDir -File -Recurse)) { Stop-WithError "aucun fichier dans « $cryptDir »." }
if (-not $Sortie) {
  # Jamais à l'intérieur de OneDrive : la copie déchiffrée (avec les données des
  # PIN) repartirait sinon dans le cloud, en clair.
  $base = $parent
  foreach ($od in @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial)) {
    if ($od -and ($parent + '\').StartsWith($od.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
      $base = [System.IO.Path]::GetTempPath()
      Write-Host "La source est dans OneDrive : les fichiers déchiffrés iront dans le dossier temporaire de Windows." -ForegroundColor Yellow
      break
    }
  }
  $Sortie = Join-Path $base ('dechiffre-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

Write-Host "rclone : $rc"
Write-Host "Fichiers chiffrés : $cryptDir`n"
$p1 = Read-Secret 'Mot de passe'
$p2 = Read-Secret 'Salt'
$o1 = Get-Obscured $rc $p1
$o2 = Get-Obscured $rc $p2
Remove-Variable p1, p2

$sortieExisted = Test-Path -LiteralPath $Sortie
New-Item -ItemType Directory -Path $Sortie -Force | Out-Null
$before = @(Get-ChildItem -LiteralPath $Sortie -File -Recurse | ForEach-Object { $_.FullName })

try {
  # Remote crypt temporaire, rien n'est enregistré. Le chemin est entre ' ' car il contient « C: ».
  # Les mots de passe passent par des variables d'environnement, propres à ce
  # processus, plutôt que sur la ligne de commande (visible dans la liste des processus).
  $remote = ":crypt,remote='" + ($cryptDir -replace "'", "''") + "':"
  $env:RCLONE_CRYPT_PASSWORD = $o1
  $env:RCLONE_CRYPT_PASSWORD2 = $o2
  $ErrorActionPreference = 'Continue'
  $log = & $rc copy $remote $Sortie 2>&1
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
} finally {
  Remove-Item Env:RCLONE_CRYPT_PASSWORD, Env:RCLONE_CRYPT_PASSWORD2 -ErrorAction SilentlyContinue
  Remove-Variable o1, o2, remote -ErrorAction SilentlyContinue
  if ($tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
}

$new = @(Get-ChildItem -LiteralPath $Sortie -File -Recurse | Where-Object { $before -notcontains $_.FullName })
if ($new.Count -eq 0) {
  if (-not $sortieExisted -and -not (Get-ChildItem -LiteralPath $Sortie -Force)) { Remove-Item -LiteralPath $Sortie -Force }
  if ($code -ne 0) { $log | Select-Object -Last 5 | ForEach-Object { Write-Host $_ } }
  if ($before.Count -gt 0 -and $code -eq 0) {
    Stop-WithError "aucun NOUVEAU fichier dans « $Sortie » : soit ils y sont déjà (déchiffrés lors d'un essai précédent), soit le mot de passe ou le salt est faux. Relance avec un dossier de sortie vide pour en être sûr."
  }
  Stop-WithError "aucun fichier n'a pu être déchiffré. Causes possibles : mot de passe ou salt faux, ou fichier renommé après le téléchargement (il doit garder son nom illisible)."
}
if ($code -ne 0) {
  # Une partie seulement a été déchiffrée : on le dit, et on rappelle que ces
  # fichiers-là contiennent déjà des données sensibles.
  $log | Select-Object -Last 5 | ForEach-Object { Write-Host $_ }
  Write-Host "`nATTENTION : déchiffrement INCOMPLET (rclone a signalé une erreur). Seuls les fichiers ci-dessous ont été déchiffrés." -ForegroundColor Yellow
}

Write-Host "`nDéchiffrés dans : $Sortie" -ForegroundColor Green
foreach ($f in $new) {
  Write-Host ("  " + $f.FullName.Substring($Sortie.Length).TrimStart('\', '/'))
  if ($f.Name -like 'defi-double-*.json.gz') {
    $json = Expand-Gzip $f.FullName
    try {
      $b = Get-Content -LiteralPath $json -Raw -Encoding UTF8 | ConvertFrom-Json
      $counts = ($b.counts.PSObject.Properties | ForEach-Object { "$($_.Name) $($_.Value)" }) -join ', '
      try { $when = ([datetime]$b.exportedAt).ToLocalTime().ToString('dd.MM.yyyy HH:mm') } catch { $when = $b.exportedAt }
      Write-Host "    -> $(Split-Path $json -Leaf) : sauvegarde du $when, $counts"
    } catch {
      Write-Host "    -> $(Split-Path $json -Leaf) (pas une sauvegarde Défi Double lisible)"
    }
  }
}
Write-Host "`nCes fichiers contiennent les données des PIN : supprime le dossier quand tu n'en as plus besoin." -ForegroundColor Yellow
