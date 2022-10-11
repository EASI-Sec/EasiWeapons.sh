## Usage
EasiWeapons.sh heavily relies on Python virtual environments and uses pipx, poetry and pipenv to orchestra venvs.

In order to launch the bleeding-edge version of a tool installed with pipx and not the version that is already shipped with Kali, you should modify the PATH variable:

Modify PATH for a normal user with any method you want (.bashrc / .profile / .zshrc / etc.): export PATH="$HOME/.local/bin:$PATH".
Modify PATH for the superuser by modifying secure_path within sudoers (sudo visudo):
sudoers.png

Now you can download EasiWeapons.sh and run it from your home directory (pip may prompt for unlocking the keyring during the process). When it's done, you can check the results in ~/tools and ~/www:

```
~$ curl -sL https://raw.githubusercontent.com/EASI-Sec/EasiWeapons.sh/main/EasiWeapons.sh | bash -s -- -idtw
~$ ls -la ~/tools ~/www
```

⚠️ Warning: the 1st command above will delete existing ~/tools and ~/www directories.

It's recommended to run EasiWeapons.sh on a clean installation of Kali Linux.

Rerun the Installations
To execute EasiWeapons.sh with full set of arguments again after it has already been ran once, remove the existent virtual environments first and then run the script:

```
~$ rm -rf ~/.local/pipx/ ~/.virtualenvs/
~$ ./EasiWeapons.sh -idtw
```

### Help Menu

usage: EasiWeapons.sh [-h] [-i] [-d] [-t] [w]

optional arguments:
  -h                    show this help message and exit
  -i                    initialize filesystem (re-create ./tools and ./www directories)
  -d                    resolve dependencies
  -t                    download and install tools on Kali Linux
  -w                    download scripts and binaries for transferring onto the victim host

## Available Tools

### tools

 BloodHound.py
 BloodHound
 CVE-2020-1472 (checker)
 CrackMapExec
 Ebowla
 Empire
 LDAPPER
 PrivExchange
 Responder
 TrustVisualizer
 Windows-Exploit-Suggester
 aclpwn.py
 adidnsdump
 aquatone
 bettercap
 chisel
 crowbar
 cve-2019-1040-scanner
 dementor.py
 dsniff
 enum4linux-ng
 evil-winrm
 gateway-finder-imp
 gitjacker
 gobuster
 htbenum
 impacket
 kerbrute
 krbrelayx
 ldapdomaindump
 mitm6
 Nim via choosenim
 Nim-Scripts
 nullinux
 odat
 pypykatz
 pywerview
 rbcd-attack
 rbcd_permissions
 rdp-tunnel
 updog
 xc

### www

 Bypass-AMSI.ps1
 Bypass-UAC.ps1
 Discover-PSMSExchangeServers
 Discover-PSMSSQLServers
 DomainPasswordSpray.ps1
 Intercept-NG
 Inveigh.ps1
 InveighZero · Pre-Compiled · PowerSharpPack.ps1
 Invoke-ACLPwn.ps1
 Invoke-Kerberoast.ps1 (Empire)
 Invoke-Mimikatz.ps1 (Empire)
 Invoke-Portscan.ps1 (PowerSploit)
 Invoke-RunasCs.ps1
 Invoke-SMBClient.ps1
 Invoke-SMBEnum.ps1
 Invoke-SMBExec.ps1
 Invoke-WMIExec.ps1
 jaws-enum.ps1
 Out-EncryptedScript.ps1 (PowerSploit)
 PowerUp.ps1 (PowerSploit)
 PowerUpSQL.ps1
 PowerView2.ps1 (PowerSploit)
 PowerView3.ps1 (PowerSploit) (New-GPOImmediateTask)
 PowerView3.ps1 (PowerSploit)
 PowerView4.ps1 (ZeroDayLab)
 Powermad.ps1
 PrivescCheck.ps1
 PrintSpoofer · Invoke-BadPotato.ps1 (PowerSharpPack)
 ProcDump (Sysinternals)
 RoguePotato
 Rubeus · Pre-Compiled · Invoke-Rubeus.ps1 (Empire) · Invoke-Rubeus.ps1 (PowerSharpPack)
 Seatbelt · Pre-Compiled · Invoke-Seatbelt.ps1 (PowerSharpPack)
 SessionGopher.ps1
 Set-GpoStatus.ps1
 SharpGPOAbuse · Pre-Compiled · Invoke-SharpGPOAbuse.ps1 (PowerSharpPack)
 SharpHound.exe
 SharpHound.ps1
 Sherlock.ps1
 SpoolSample · Pre-Compiled · Invoke-Spoolsample.ps1 (PowerSharpPack)
 Watson · Pre-Compiled · Invoke-SharpWatson.ps1 (PowerSharpPack)
 WinPwn
 chisel
 htbenum.sh
 linux-exploit-suggester
 mimikatz
 netcat for Windows
 plink
 powercat.ps1
 pspy
 rdp2tcp.exe
 winPEAS.exe
