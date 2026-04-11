# Uses the OpenSSL bundled with Git for Windows; falls back to whatever is on PATH.
$ErrorActionPreference = "Stop"

$certDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $certDir

try {
    # Prefer Git for Windows OpenSSL so we get a known-good openssl.cnf alongside it.
    $gitOpenSsl = "C:\Program Files\Git\usr\bin\openssl.exe"
    if (Test-Path $gitOpenSsl) {
        $openssl = $gitOpenSsl
        $env:OPENSSL_CONF = "C:\Program Files\Git\usr\ssl\openssl.cnf"
        Write-Host "Using Git for Windows OpenSSL: $openssl"
    } else {
        $openssl = "openssl"
        Write-Host "Using OpenSSL from PATH"
    }

    $days    = 365
    $rsaBits = 2048

    Write-Host "==> Generating Certificate Authority"
    & $openssl req -x509 -newkey "rsa:$rsaBits" -nodes `
        -keyout ca.key -out ca.crt -days $days `
        -subj "/CN=FROST-TSA-CA/O=FROST Timestamp Authority"

    function New-ServiceCert {
        param([string]$Name, [string]$SAN)

        Write-Host "==> Generating certificate for: $Name (SANs: $SAN)"

        @"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=$SAN
"@ | Set-Content -Encoding ASCII "$Name.ext"

        & $openssl req -newkey "rsa:$rsaBits" -nodes `
            -keyout "$Name.key" -out "$Name.csr" `
            -subj "/CN=$Name/O=FROST Timestamp Authority"

        & $openssl x509 -req -in "$Name.csr" `
            -CA ca.crt -CAkey ca.key -CAcreateserial `
            -out "$Name.crt" -days $days `
            -extfile "$Name.ext"

        Remove-Item -Force "$Name.csr", "$Name.ext" -ErrorAction SilentlyContinue
    }

    New-ServiceCert "gateway"    "DNS:gateway,DNS:localhost,IP:127.0.0.1"
    New-ServiceCert "aggregator" "DNS:aggregator,DNS:localhost,IP:127.0.0.1"
    New-ServiceCert "signer"     "DNS:signer,DNS:*.signer,DNS:localhost,IP:127.0.0.1"

    Remove-Item -Force ca.srl -ErrorAction SilentlyContinue

    Write-Host "`n==> Certificates generated in $certDir"
    Get-ChildItem "*.crt", "*.key" | Format-Table Name, LastWriteTime
}
finally {
    Pop-Location
}
