## Usage
EasiWeapons.sh heavily relies on Python virtual environments and uses pipx, poetry and pipenv to orchestra venvs.

In order to launch the bleeding-edge version of a tool installed with pipx and not the version that is already shipped with Kali, you should modify the PATH variable:

Modify PATH for a normal user with any method you want (.bashrc / .profile / .zshrc / etc.): 

```
export PATH="$HOME/.local/bin:$PATH"
```

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

- [x] Amsi-Bypass-Powershell
- [x] BloodHound
- [x] BloodHound.py
- [x] Certipy
- [x] CS-BC-SECURITY-Malleable-C2-Profiles
- [x] CS-Invoke-CredentialPhisher
- [x] CS-RdpThief
- [x] CS-Situational-Awareness-BOF
- [x] CS-minimal-defender-bypass
- [x] CS-nanodump
- [x] CS-threatexpress-malleable-c2
- [x] CVE-2019-1040-scanner
- [x] CVE-2020-1472-checker
- [x] CVE-2021-1675-tools
- [x] Covenant
- [x] CrackMapExec
- [x] Creds
- [x] DLLsForHackers
- [x] DonPAPI
- [x] DivideAndScan
- [x] Ebowla
- [x] Empire
- [x] LDAPPER
- [x] LDAPmonitor
- [x] LdapRelayScan
- [x] LightMe
- [x] MS17-010
- [x] MANSPIDER
- [x] MeterPwrShell
- [x] Nim
- [x] NimlineWhispers
- [x] Obsidian
- [x] OffensiveNim
- [x] PCredz
- [x] PEzor
- [x] PKINITtools
- [x] PetitPotam
- [x] PetitPotam-Ext
- [x] PrivExchange
- [x] Responder
- [x] RustScan
- [x] SCShell
- [x] ScareCrow
- [x] ShadowCoerce
- [x] SharpGen
- [x] SharpShooter
- [x] ShellPop
- [x] WebclientServiceScanner
- [x] TrustVisualizer
- [x] Windows-Exploit-Suggester
- [x] ack3
- [x] aclpwn.py
- [x] adidnsdump
- [x] aquatone
- [x] arsenal
- [x] bettercap
- [x] bloodhound-import
- [x] bloodhound-quickwin
- [x] certi
- [x] chisel-server
- [x] crowbar
- [x] dementor.py
- [x] dsniff
- [x] eavesarp
- [x] enum4linux-ng
- [x] feroxbuster
- [x] ffuf
- [x] gMSADumper
- [x] gateway-finder-imp
- [x] gitjacker
- [x] go-windapsearch
- [x] gobuster
- [x] hashcat-utils
- [x] impacket
- [x] ipmitool
- [x] kerbrute
- [x] krbrelayx
- [x] ldapdomaindump
- [x] ldapsearch-ad
- [x] ligolo-ng-proxy
- [x] lsassy
- [x] masscan
- [x] mitm6
- [x] mscache
- [x] nac_bypass
- [x] nextnet
- [x] nishang
- [x] noPac
- [x] ntlm-scanner
- [x] ntlmv1-multi
- [x] nullinux
- [x] odat
- [x] paperify
- [x] payloadGenerator
- [x] pyGPOAbuse
- [x] pyKerbrute
- [x] pypykatz
- [x] pywerview
- [x] pywhisker
- [x] rbcd-attack
- [x] rbcd_permissions
- [x] rdp-tunnel-tools
- [x] rtfm
- [x] sRDI
- [x] sgn
- [x] smartbrute
- [x] snmpwn
- [x] spraykatz
- [x] ssb
- [x] sshuttle
- [x] targetedKerberoast
- [x] traitor
- [x] updog
- [x] webpage2html
- [x] wesng
- [x] windapsearch
- [x] wmiexec-RegOut
- [x] xc

### www

- [x] Bypass-AMSI.ps1
- [x] Bypass-UAC.ps1
- [x] Discover-PSMSExchangeServers
- [x] Discover-PSMSSQLServers
- [x] DomainPasswordSpray.ps1
- [x] Intercept-NG
- [x] Inveigh.ps1
- [x] InveighZero · Pre-Compiled · PowerSharpPack.ps1
- [x] Invoke-ACLPwn.ps1
- [x] Invoke-Kerberoast.ps1 (Empire)
- [x] Invoke-Mimikatz.ps1 (Empire)
- [x] Invoke-Portscan.ps1 (PowerSploit)
- [x] Invoke-RunasCs.ps1
- [x] Invoke-SMBClient.ps1
- [x] Invoke-SMBEnum.ps1
- [x] Invoke-SMBExec.ps1
- [x] Invoke-WMIExec.ps1
- [x] jaws-enum.ps1
- [x] Out-EncryptedScript.ps1 (PowerSploit)
- [x] PowerUp.ps1 (PowerSploit)
- [x] PowerUpSQL.ps1
- [x] PowerView2.ps1 (PowerSploit)
- [x] PowerView3.ps1 (PowerSploit) (New-GPOImmediateTask)
- [x] PowerView3.ps1 (PowerSploit)
- [x] PowerView4.ps1 (ZeroDayLab)
- [x] Powermad.ps1
- [x] PrivescCheck.ps1
- [x] PrintSpoofer · Invoke-BadPotato.ps1 (PowerSharpPack)
- [x] ProcDump (Sysinternals)
- [x] RoguePotato
- [x] Rubeus · Pre-Compiled · Invoke-Rubeus.ps1 (Empire) · Invoke-Rubeus.ps1 (PowerSharpPack)
- [x] Seatbelt · Pre-Compiled · Invoke-Seatbelt.ps1 (PowerSharpPack)
- [x] SessionGopher.ps1
- [x] Set-GpoStatus.ps1
- [x] SharpGPOAbuse · Pre-Compiled · Invoke-SharpGPOAbuse.ps1 (PowerSharpPack)
- [x] SharpHound.exe
- [x] SharpHound.ps1
- [x] Sherlock.ps1
- [x] SpoolSample · Pre-Compiled · Invoke-Spoolsample.ps1 (PowerSharpPack)
- [x] Watson · Pre-Compiled · Invoke-SharpWatson.ps1 (PowerSharpPack)
- [x] WinPwn
- [x] chisel
- [x] htbenum.sh
- [x] linux-exploit-suggester
- [x] mimikatz
- [x] netcat for Windows
- [x] plink
- [x] powercat.ps1
- [x] pspy
- [x] rdp2tcp.exe
- [x] winPEAS.exe
