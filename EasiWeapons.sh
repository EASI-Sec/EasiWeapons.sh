#!/usr/bin/env bash

nocolor="\033[0m"
green="\033[0;32m"
yellow="\033[0;33m"
red="\033[0;31m"
red_bold="\033[1;31m"
blue="\033[0;34m"
light_gray="\033[0;37m"
dark_gray="\033[1;30m"
magenta_bold="\033[1;35m"

SITE="https://github.com/Easi-Sec/EasiWeapons.sh"
VERSION="0.1.4"

echo -e "${red_bold}    ______           _ _       __                                         __  ${nocolor}"
echo -e "${red_bold}   / ____/___ ______(_) |     / /__  ____ _____  ____  ____  _____  _____/ /_ ${nocolor}"
echo -e "${red_bold}  / __/ / __ `/ ___/ /| | /| / / _ \/ __ `/ __ \/ __ \/ __ \/ ___/ / ___/ __ \ ${nocolor}"
echo -e "${red_bold} / /___/ /_/ (__  ) / | |/ |/ /  __/ /_/ / /_/ / /_/ / / / (__  ) (__  ) / / /${nocolor}"
echo -e "${red_bold}/_____/\__,_/____/_/  |__/|__/\___/\__,_/ .___/\____/_/ /_/____(_)____/_/ /_/ ${nocolor}"
echo -e "${red_bold}                                       /_/                                    ${nocolor}"
echo    "                           		\"The more, the merrier\""

# -----------------------------------------------------------------------------
# ----------------------------------- Init ------------------------------------
# -----------------------------------------------------------------------------

filesystem() {
	rm -rf tools www
	mkdir -p tools/CobaltStrike/{Scripts,Profiles} www
}

# -----------------------------------------------------------------------------
# --------------------------------- Messages ----------------------------------
# -----------------------------------------------------------------------------

info() {
	echo -e "${blue}[*] $1${nocolor}"
}

success() {
	echo -e "${green}[+] $1${nocolor}"
}

warning() {
	echo -e "${yellow}[!] $1${nocolor}"
}

fail() {
	echo -e "${red}[-] $1${nocolor}"
}

progress() {
	echo -e "${magenta_bold}[WPNZKL] Installing $1${nocolor}"
}

# -----------------------------------------------------------------------------
# ---------------------------------- Helpers ----------------------------------
# -----------------------------------------------------------------------------

_pushd() {
	pushd $1 2>&1 > /dev/null
}

_popd() {
	popd 2>&1 > /dev/null
}

installDebPackage() {
	pkg_name=$1
	if ! /usr/bin/dpkg-query -f '${Status}' -W $pkg_name 2>&1 | /bin/grep "ok installed" > /dev/null; then
		warning "$pkg_name not found, installing with apt"
		sudo apt install $pkg_name -y
	fi
	success "Installed deb package: $pkg_name"
}

installPipPackage() {
	V=$1
	pkg_name=$2
	if ! which $pkg_name > /dev/null 2>&1; then
		warning "$pkg_name not found, installing with pip$V"
		sudo "python${V}" -m pip install -U $pkg_name
	fi
	success "Installed pip$V package: $pkg_name"
}

installSnapPackage() {
	pkg_name=$1
	if ! /usr/bin/snap info $pkg_name 2>&1 | /bin/grep "installed" > /dev/null; then
		warning "$pkg_name not found, installing with snap"
		sudo snap install $pkg_name --dangerous
	fi
	success "Installed snap package: $pkg_name"
}

cloneRepository() {
	url=$1
	repo_name=${url##*/}
	repo_name=${repo_name%.*}

	if [ -z "$2" ]; then
		dname=$repo_name
	else
		dname=$2
	fi

	if git clone --recurse-submodules -q $url $dname; then
		success "Cloned repository: $repo_name"
	else
		fail "Failed to clone repository: $repo_name"
	fi
}

downloadRawFile() {
	url=$1
	filename=$2
	if curl -sL $url > $filename; then
		success "Downloaded raw file: $filename"
	else
		fail "Failed to download raw file: $filename"
	fi
}

downloadRelease() {
	full_repo_name=$1
	release_name=$2
	filename=$3
	if curl -sL "https://api.github.com/repos/$full_repo_name/releases/latest" | jq -r '.assets[].browser_download_url' | grep $release_name | wget -O $filename -qi -; then
		success "Downloaded release: $filename"
	else
		fail "Failed to download release: $filename"
	fi
}

# -----------------------------------------------------------------------------
# ------------------------------- Dependencies --------------------------------
# -----------------------------------------------------------------------------

_jq() {
	installDebPackage jq
}

_python2-pip() {
	curl -s https://bootstrap.pypa.io/pip/2.7/get-pip.py | sudo python2
	sudo python2 -m pip install -U setuptools
}

_python2-dev() {
	installDebPackage python-dev
}

_python3-pip() {
	installDebPackage python3-pip
}

_python3-venv() {
	installDebPackage python3-venv
}

_setuptools() {
	installPipPackage 2 setuptools
	installPipPackage 3 setuptools
}

_impacket() {
	installPipPackage 2 impacket
	installPipPackage 3 impacket
}

_poetry() {
	installPipPackage 3 poetry
}

_pipx() {
	installPipPackage 3 pipx
	pipx ensurepath
}

_neo4j() {
	installDebPackage neo4j
}

_snap() {
	installDebPackage snapd
	sudo service snapd start
	sudo apparmor_parser -r /etc/apparmor.d/*snap-confine*
	sudo apparmor_parser -r /var/lib/snapd/apparmor/profiles/snap*
	export PATH="$PATH:/snap/bin"
}

_dotnet() {
	# For Covenant
	curl -sSL https://dot.net/v1/dotnet-install.sh | sudo bash /dev/stdin -Channel 3.1
	# For SharpGen
	curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin -Channel 2.1
}

dependencies() {
	_jq
	_python2-pip
	_python2-dev
	_python3-pip
	_python3-venv
	_setuptools
	_impacket
	_poetry
	_pipx
	_neo4j
	_snap
	_dotnet
}

# -----------------------------------------------------------------------------
# ----------------------------------- tools -----------------------------------
# -----------------------------------------------------------------------------

Amsi-Bypass-Powershell() {
	_pushd tools
	progress "Amsi-Bypass-Powershell"
	cloneRepository "https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell.git"
	_popd
}

BloodHound() {
	_pushd tools
	progress "BloodHound"
	downloadRelease "BloodHoundAD/BloodHound" BloodHound-linux-x64 BloodHound.zip
	unzip -q BloodHound.zip
	mv BloodHound-linux-x64 BloodHound
	rm BloodHound.zip
	cd BloodHound
	sudo chown root:root chrome-sandbox
	sudo chmod 4755 chrome-sandbox
	chmod +x BloodHound
	sudo mkdir /usr/share/neo4j/logs/
	mkdir -p ~/.config/bloodhound

	downloadRawFile "https://github.com/ShutdownRepo/Exegol/raw/master/sources/bloodhound/customqueries.json" /tmp/customqueries1.json
	downloadRawFile "https://github.com/CompassSecurity/BloodHoundQueries/raw/master/customqueries.json" /tmp/customqueries2.json
	downloadRawFile "https://github.com/ZephrFish/Bloodhound-CustomQueries/raw/main/customqueries.json" /tmp/customqueries3.json
	downloadRawFile "https://github.com/ly4k/Certipy/raw/main/customqueries.json" /tmp/customqueries4.json

	python3 - << 'EOT'
import json
from pathlib import Path
merged = {'queries': []}
for jf in sorted((Path('/tmp')).glob('customqueries*.json')):
	with open(jf, 'r') as f:
		merged['queries'] += json.load(f)['queries']
with open(Path.home() / '.config' / 'bloodhound' / 'customqueries.json', 'w') as f:
	json.dump(merged, f, indent=4)
EOT
	rm /tmp/customqueries*.json

	downloadRawFile "https://github.com/ShutdownRepo/Exegol/raw/master/sources/bloodhound/config.json" ~/.config/bloodhound/config.json
	sed -i 's/"password": "exegol4thewin"/"password": "WeaponizeK4li!"/g' ~/.config/bloodhound/config.json

	_popd
}

BloodHound.py() {
	progress "BloodHound.py"
	pipx install -f "git+https://github.com/fox-it/BloodHound.py.git"
}

CS-BC-SECURITY-Malleable-C2-Profiles() {
	_pushd tools
	progress "CS-BC-SECURITY-Malleable-C2-Profiles"
	cd CobaltStrike/Profiles
	cloneRepository "https://github.com/BC-SECURITY/Malleable-C2-Profiles.git"
	_popd
}

CS-Invoke-CredentialPhisher() {
	_pushd tools
	progress "CS-Invoke-CredentialPhisher"
	cd CobaltStrike/Scripts
	cloneRepository "https://github.com/fox-it/Invoke-CredentialPhisher.git"
	_popd
}

CS-RdpThief() {
	_pushd tools
	progress "CS-RdpThief"
	cd CobaltStrike/Scripts
	cloneRepository "https://github.com/0x09AL/RdpThief.git"
	_popd
}

CS-Situational-Awareness-BOF() {
	_pushd tools
	progress "CS-Situational-Awareness-BOF"
	cd CobaltStrike/Scripts
	cloneRepository "https://github.com/trustedsec/CS-Situational-Awareness-BOF.git"
	cd CS-Situational-Awareness-BOF
	./make_all.sh
	_popd
}

CS-minimal-defender-bypass() {
	_pushd tools
	progress "CS-Minimal-Cobalt-Strike-Profile"
	cd CobaltStrike/Profiles
	downloadRawFile "https://gist.github.com/tothi/8abd2de8f4948af57aa2d027f9e59efe/raw/c5bce7ff65feacbf48741c39bb694a54575efa19/minimal-defender-bypass.profile" minimal-defender-bypass.profile
	_popd
}

CS-nanodump() {
	_pushd tools
	progress "CS-nanodump"
	cd CobaltStrike/Scripts
	cloneRepository "https://github.com/helpsystems/nanodump.git"
	_popd
}

CS-threatexpress-malleable-c2() {
	_pushd tools
	progress "CS-threatexpress-malleable-c2"
	cd CobaltStrike/Profiles
	cloneRepository "https://github.com/threatexpress/malleable-c2.git"
	_popd
}

CVE-2019-1040-scanner() {
	_pushd tools
	progress "CVE-2019-1040-scanner"
	mkdir CVE-2019-1040-scanner
	cd CVE-2019-1040-scanner
	downloadRawFile "https://github.com/fox-it/cve-2019-1040-scanner/raw/master/scan.py" CVE-2019-1040-scanner.py
	chmod +x CVE-2019-1040-scanner.py
	_popd
}

CVE-2020-1472-checker() {
	_pushd tools
	progress "CVE-2020-1472-checker"
	cloneRepository "https://github.com/SecuraBV/CVE-2020-1472.git"
	mv CVE-2020-1472 CVE-2020-1472-checker
	cd CVE-2020-1472-checker
	python3 -m pip install -U -r requirements.txt
	chmod +x zerologon_tester.py
	_popd
}

CVE-2021-1675-tools() {
	_pushd tools
	progress "CVE-2021-1675"
	mkdir CVE-2021-1675
	cd CVE-2021-1675
	cloneRepository "https://github.com/cube0x0/impacket.git"
	downloadRawFile "https://github.com/cube0x0/CVE-2021-1675/raw/main/CVE-2021-1675.py" CVE-2021-1675-MS-RPRN.py
	downloadRawFile "https://github.com/cube0x0/CVE-2021-1675/raw/main/SharpPrintNightmare/CVE-2021-1675.py" CVE-2021-1675-MS-PAR.py
	_popd
}

Certipy() {
	progress "Certipy"
	pipx install -f "git+https://github.com/ly4k/Certipy.git"
}

Covenant() {
	_pushd tools
	cloneRepository "https://github.com/cobbr/Covenant.git"
	#cd Covenant/Covenant
	#sudo /root/.dotnet/dotnet run
	_popd
}

CrackMapExec() {
	progress "CrackMapExec"
	pipx install -f "git+https://github.com/byt3bl33d3r/CrackMapExec.git"
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/conf/cme.conf" ~/.cme/cme.conf
}

Creds() {
	_pushd tools
	progress "Creds"
	cloneRepository "https://github.com/S3cur3Th1sSh1t/Creds.git"
	_popd
}

DLLsForHackers() {
	_pushd tools
	progress "DLLsForHackers"
	cloneRepository "https://github.com/Mr-Un1k0d3r/DLLsForHackers.git"
	_popd
}

DonPAPI() {
	_pushd tools
	progress "DonPAPI"
	cloneRepository "https://github.com/login-securite/DonPAPI.git"
	cd DonPAPI
	python3 -m pip install -U -r requirements.txt
	_popd
}

DivideAndScan() {
	progress "DivideAndScan"
	pipx install -f "git+https://github.com/snovvcrash/DivideAndScan.git"
}

Ebowla() {
	_pushd tools
	progress "Ebowla"
	cloneRepository "https://github.com/Genetic-Malware/Ebowla.git"
	cd Ebowla
	rm -rf .git
	installDebPackage golang
	installDebPackage mingw-w64
	installDebPackage wine
	python2 -m pip install -U configobj pyparsing pycrypto
	_popd
}

Empire() {
	_pushd tools
	progress "Empire"
	cloneRepository "https://github.com/BC-SECURITY/Empire.git"
	cd Empire
	sudo STAGING_KEY=`echo 'WeaponizeK4li!' | md5sum | cut -d' ' -f1` ./setup/install.sh
	sudo poetry install
	echo $'#!/usr/bin/env bash\nsudo poetry run python empire.py ${@}' > ps-empire.sh
	chmod +x ps-empire.sh
	_popd
}

ItWasAllADream() {
	_pushd tools
	progress "ItWasAllADream"
	cloneRepository "https://github.com/byt3bl33d3r/ItWasAllADream.git"
	cd ItWasAllADream
	poetry install
	_popd
}

LDAPPER() {
	_pushd tools
	progress "LDAPPER"
	cloneRepository "https://github.com/shellster/LDAPPER.git"
	cd LDAPPER
	python3 -m pip install -U -r requirements.txt
	_popd
}

LDAPmonitor() {
	_pushd tools
	progress "LDAPmonitor"
	cloneRepository "https://github.com/p0dalirius/LDAPmonitor.git"
	cd LDAPmonitor/python
	python3 -m pip install -U -r requirements.txt
	sudo ln -sn `readlink -f pyLDAPmonitor.py` /usr/bin/LDAPmonitor.py
	_popd
}

LdapRelayScan() {
	_pushd tools
	progress "LdapRelayScan"
	cloneRepository "https://github.com/zyn3rgy/LdapRelayScan.git"
	_popd
}

LightMe() {
	_pushd tools
	progress "LightMe"
	cloneRepository "https://github.com/WazeHell/LightMe.git"
	_popd
}

MANSPIDER() {
	progress "MANSPIDER"
	installDebPackage antiword
	pipx install man-spider
}

MS17-010() {
	_pushd tools
	progress "MS17-010"
	cloneRepository "https://github.com/helviojunior/MS17-010.git"
	_popd
}

MeterPwrShell() {
	_pushd tools
	progress "MeterPwrShell"
	mkdir MeterPwrShell
	cd MeterPwrShell
	downloadRawFile "https://github.com/GetRektBoy724/MeterPwrShell/releases/download/v2.0.0/MeterPwrShell2Kalix64" MeterPwrShell2Kalix64
	chmod +x MeterPwrShell2Kalix64
	_popd
}

Neo-reGeorg() {
	_pushd tools
	progress "Neo-reGeorg"
	cloneRepository "https://github.com/L-codes/Neo-reGeorg.git"
	python2 -m pip install -U requests
	_popd
}

Nim() {
	progress "Nim"
	installDebPackage mingw-w64
	installDebPackage nim
	nimble install winim nimcrypto zippy -y
	#curl https://nim-lang.org/choosenim/init.sh -sSf | CHOOSENIM_NO_ANALYTICS=1 sh
}

NimlineWhispers() {
	_pushd tools
	progress "NimlineWhispers"
	cloneRepository "https://github.com/snovvcrash/NimlineWhispers.git"
	_popd
}

Obsidian() {
	progress "Obsidian"
	downloadRelease "obsidianmd/obsidian-releases" obsidian.*amd64.snap /tmp/obsidian.snap
	installSnapPackage /tmp/obsidian.snap
	rm /tmp/obsidian.snap
	cp /var/lib/snapd/desktop/applications/obsidian_obsidian.desktop ~/Desktop/obsidian_obsidian.desktop
}

OffensiveNim() {
	_pushd tools
	progress "OffensiveNim"
	cloneRepository "https://github.com/byt3bl33d3r/OffensiveNim.git"
	_popd
}

PCredz() {
	_pushd tools
	progress "PCredz"
	cloneRepository "https://github.com/lgandx/PCredz.git"
	python3 -m pip install -U Cython
	python3 -m pip install -U python-libpcap
	_popd
}

PEzor() {
	_pushd tools
	progress "PEzor"
	cloneRepository "https://github.com/phra/PEzor.git"
	cd PEzor
	sudo bash install.sh
	#sudo cat /root/.bashrc | grep PEzor
	_popd
}

PKINITtools() {
	_pushd tools
	progress "PKINITtools"
	cloneRepository "https://github.com/dirkjanm/PKINITtools.git"
	python3 -m pip install -U minikerberos
	cd PKINITtools
	chmod +x getnthash.py gets4uticket.py gettgtpkinit.py
	sudo ln -sv `readlink -f getnthash.py` /usr/local/bin/getnthash.py
	sudo ln -sv `readlink -f gets4uticket.py` /usr/local/bin/gets4uticket.py
	sudo ln -sv `readlink -f gettgtpkinit.py` /usr/local/bin/gettgtpkinit.py
	_popd
}

PetitPotam() {
	_pushd tools
	progress "PetitPotam"
	cloneRepository "https://github.com/topotam/PetitPotam.git"
	_popd
}

PetitPotam-Ext() {
	_pushd tools
	progress "PetitPotam-Ext"
	cloneRepository "https://github.com/ly4k/PetitPotam.git" PetitPotam-Ext
	_popd
}

PoshC2() {
	progress "PoshC2"
	curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/dev/Install.sh | sudo bash -s -- -p /opt/PoshC2 -b dev
}

PrivExchange() {
	_pushd tools
	progress "PrivExchange"
	cloneRepository "https://github.com/dirkjanm/PrivExchange.git"
	_popd
}

Responder() {
	_pushd tools
	progress "Responder"
	cloneRepository "https://github.com/lgandx/Responder.git"
	cd Responder
	sed -i 's/Challenge = Random/Challenge = 1122334455667788/g' Responder.conf
	_popd
}

RustScan() {
	_pushd tools
	progress "RustScan"
	mkdir RustScan
	cd RustScan
	downloadRelease "RustScan/RustScan" rustscan.*amd64.deb rustscan.deb
	sudo dpkg -i rustscan.deb
	sudo wget https://gist.github.com/snovvcrash/8b85b900bd928493cd1ae33b2df318d8/raw/fe8628396616c4bf7a3e25f2c9d1acc2f36af0c0/rustscan-ports-top1000.toml -O /root/.rustscan.toml
	_popd
}

SCShell() {
	_pushd tools
	progress "SCShell"
	cloneRepository "https://github.com/Mr-Un1k0d3r/SCShell.git"
	_popd
}

ScareCrow() {
	_pushd tools
	progress "ScareCrow"
	mkdir ScareCrow
	cd ScareCrow
	downloadRelease "optiv/ScareCrow" ScareCrow.*linux_amd64 ScareCrow
	chmod +x ScareCrow
	_popd
}

ShadowCoerce() {
	_pushd tools
	progress "ShadowCoerce"
	cloneRepository "https://github.com/ShutdownRepo/ShadowCoerce.git"
	_popd
}

SharpGen() {
	_pushd tools
	progress "SharpGen"
	cloneRepository "https://github.com/cobbr/SharpGen.git"
	_popd
}

SharpShooter() {
	_pushd tools
	progress "SharpShooter"
	cloneRepository "https://github.com/mdsecactivebreach/SharpShooter.git"
	cd SharpShooter
	python2 -m pip install -U -r requirements.txt
	_popd
}

ShellPop() {
	_pushd tools
	progress "ShellPop"
	cloneRepository "https://github.com/0x00-0x00/ShellPop.git"
	cd ShellPop
	python2 -m pip install -U -r requirements.txt
	sudo python2 setup.py install
	_popd
}

TrustVisualizer() {
	_pushd tools
	progress "TrustVisualizer"
	cloneRepository "https://github.com/snovvcrash/TrustVisualizer.git"
	cd TrustVisualizer
	python2 -m pip install -U -r requirements.txt
	_popd
}

WebclientServiceScanner() {
	progress "WebclientServiceScanner"
	pipx install -f "git+https://github.com/Hackndo/WebclientServiceScanner.git"
}

Windows-Exploit-Suggester() {
	_pushd tools
	progress "Windows-Exploit-Suggester"
	cloneRepository "https://github.com/a1ext/Windows-Exploit-Suggester.git"
	cd Windows-Exploit-Suggester
	python3 -m pip install -U -r requirements.txt
	_popd
}

ack3() {
	_pushd tools
	progress "ack3"
	cloneRepository "https://github.com/beyondgrep/ack3.git"
	cd ack3
	echo yes | sudo perl -MCPAN -e 'install File::Next'
	perl Makefile.PL
	make
	make test
	sudo make install
	_popd
}

aclpwn.py() {
	progress "aclpwn.py"
	pipx install -f "git+https://github.com/fox-it/aclpwn.py.git"
}

adidnsdump() {
	progress "adidnsdump"
	pipx install -f "git+https://github.com/dirkjanm/adidnsdump.git"
}

aquatone() {
	_pushd tools
	progress "aquatone"
	mkdir aquatone
	cd aquatone
	downloadRelease "michenriksen/aquatone" aquatone_linux_amd64.*.zip aquatone.zip
	unzip -q aquatone.zip
	rm LICENSE.txt aquatone.zip
	chmod +x aquatone
	_popd
}

arsenal() {
	_pushd tools
	progress "arsenal"
	cloneRepository "https://github.com/Orange-Cyberdefense/arsenal.git"
	cd arsenal
	python3 -m pip install -U -r requirements.txt
	sudo ln -sn `readlink -f run` /usr/bin/a
	_popd
}

bettercap() {
	_pushd tools
	progress "bettercap"
	installDebPackage libpcap-dev
	installDebPackage libusb-1.0-0-dev
	installDebPackage libnetfilter-queue-dev
	mkdir bettercap
	cd bettercap
	downloadRelease "bettercap/bettercap" bettercap_linux_amd64.*.zip bettercap.zip
	unzip -q bettercap.zip
	rm bettercap*.sha256 bettercap.zip
	sudo ./bettercap -eval "caplets.update; ui.update; q"
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bettercap/arpspoof.cap"
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bettercap/wsus.cap"
	_popd
}

bloodhound-import() {
	progress "bloodhound-import"
	pipx install -f 'git+https://github.com/fox-it/bloodhound-import.git'
}

bloodhound-quickwin() {
	_pushd tools
	progress "bloodhound-quickwin"
	cloneRepository "https://github.com/kaluche/bloodhound-quickwin.git"
	cd bloodhound-quickwin
	python3 -m pip install -U -r requirements.txt
	_popd
}

certi() {
	progress "certi"
	pipx install -f "git+https://github.com/zer1t0/certi.git"
}

chisel-server() {
	_pushd tools
	progress "chisel"
	mkdir chisel
	cd chisel
	downloadRelease "jpillora/chisel" chisel.*linux_amd64.gz chisel.gz
	gunzip chisel.gz
	chmod +x chisel
	sudo ln -sv `readlink -f chisel` /usr/local/bin/chisel
	_popd
}

crowbar() {
	progress "crowbar"
	pipx install -f "git+https://github.com/galkan/crowbar.git"
}

dementor.py() {
	_pushd tools
	progress "dementor.py"
	mkdir dementor
	cd dementor
	downloadRawFile "https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc/raw/7c7f09ea46eff4ede636f69c00c6dfef0541cd14/dementor.py" dementor.py
	chmod +x dementor.py
	_popd
}

dsniff() {
	progress "dsniff"
	#sudo sysctl -w net.ipv4.ip_forward=1
	sudo sh -c 'echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf'
	installDebPackage dsniff
}

eavesarp() {
	_pushd tools
	progress "eavesarp"
	cloneRepository "https://github.com/arch4ngel/eavesarp.git"
	cd eavesarp
	sudo python3 -m pip install -U -r requirements.txt
	_popd
}

enum4linux-ng() {
	progress "enum4linux-ng"
	pipx install -f "git+https://github.com/cddmp/enum4linux-ng.git"
}

feroxbuster() {
	_pushd tools
	progress "feroxbuster"
	mkdir feroxbuster
	cd feroxbuster
	downloadRelease "epi052/feroxbuster" x86_64-linux-feroxbuster.zip feroxbuster.zip
	unzip -q feroxbuster.zip
	rm feroxbuster.zip
	chmod +x feroxbuster
	sudo ln -sv `readlink -f feroxbuster` /usr/local/bin/feroxbuster
	_popd
}

ffuf() {
	progress "ffuf"
	installDebPackage ffuf
}

gMSADumper() {
	_pushd tools
	progress "gMSADumper"
	cloneRepository "https://github.com/micahvandeusen/gMSADumper.git"
	_popd
}

gateway-finder-imp() {
	_pushd tools
	progress "gateway-finder-imp"
	cloneRepository "https://github.com/whitel1st/gateway-finder-imp.git"
	cd gateway-finder-imp
	python3 -m pip install -U -r requirements.txt
	_popd
}

gitjacker() {
	_pushd tools
	progress "gitjacker"
	mkdir gitjacker
	cd gitjacker
	downloadRelease "liamg/gitjacker" gitjacker-linux-amd64 gitjacker
	chmod +x gitjacker
	_popd
}

go-windapsearch() {
	_pushd tools
	progress "go-windapsearch"
	mkdir go-windapsearch
	cd go-windapsearch
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/windapsearch" windapsearch
	chmod +x windapsearch
	sudo ln -sv `readlink -f windapsearch` /usr/local/bin/windapsearch
	_popd
}

gobuster() {
	progress "gobuster"
	installDebPackage gobuster
}

hashcat-utils() {
	_pushd tools
	progress "hashcat-utils"
	cloneRepository "https://github.com/hashcat/hashcat-utils.git"
	cd hashcat-utils/src
	make
	_popd
}

impacket() {
	progress "impacket"
	pipx install -f "git+https://github.com/SecureAuthCorp/impacket.git"
	_pushd tools
	progress "impacket-src"
	cloneRepository "https://github.com/SecureAuthCorp/impacket.git"
	progress "impacket-snovvcrash"
	cloneRepository "https://github.com/snovvcrash/impacket.git" impacket-snovvcrash
	_popd
}

ipmitool() {
	progress "ipmitool"
	installDebPackage ipmitool
}

kerbrute() {
	_pushd tools
	progress "kerbrute"
	mkdir kerbrute
	cd kerbrute
	downloadRelease "ropnop/kerbrute" kerbrute_linux_amd64 kerbrute
	chmod +x kerbrute
	sudo ln -sv `readlink -f kerbrute` /usr/local/bin/kerbrute
	_popd
}

krbrelayx() {
	_pushd tools
	progress "krbrelayx"
	cloneRepository "https://github.com/dirkjanm/krbrelayx.git"
	cd krbrelayx
	chmod +x addspn.py dnstool.py printerbug.py
	sudo ln -sv `readlink -f addspn.py` /usr/local/bin/addspn.py
	sudo ln -sv `readlink -f dnstool.py` /usr/local/bin/dnstool.py
	sudo ln -sv `readlink -f printerbug.py` /usr/local/bin/printerbug.py
	_popd
}

ldapdomaindump() {
	_pushd tools
	progress "ldapdomaindump"
	cloneRepository "https://github.com/dirkjanm/ldapdomaindump.git"
	cd ldapdomaindump
	python2 -m pip install -U ldap3 dnspython
	sudo python2 setup.py install
	_popd
}

ldapsearch-ad() {
	_pushd tools
	progress "ldapsearch-ad"
	cloneRepository "https://github.com/yaap7/ldapsearch-ad.git"
	cd ldapsearch-ad
	python3 -m pip install -U -r requirements.txt
	_popd
}

ligolo-ng-proxy() {
	_pushd tools
	progress "ligolo-ng"
	mkdir ligolo-ng
	cd ligolo-ng
	downloadRelease "tnpitsecurity/ligolo-ng" ligolo-ng_proxy.*Linux_64bit.tar.gz ligolo-proxy.tar.gz
	tar -xzf ligolo-proxy.tar.gz
	rm LICENSE ligolo-proxy.tar.gz
	_popd
}

lsassy() {
	progress "lsassy"
	pipx install -f "git+https://github.com/Hackndo/lsassy.git"
}

masscan() {
	_pushd tools
	progress "masscan"
	cloneRepository "https://github.com/robertdavidgraham/masscan.git"
	cd masscan
	make
	sudo make install
	_popd
}

mitm6() {
	progress "mitm6"
	pipx install -f "git+https://github.com/fox-it/mitm6.git"
}

mscache() {
	_pushd tools
	progress "mscache"
	cloneRepository "https://github.com/QAX-A-Team/mscache.git"
	python2 -m pip install -U passlib
	_popd
}

nac_bypass() {
	_pushd tools
	progress "nac_bypass"
	cloneRepository "https://github.com/snovvcrash/nac_bypass.git"
	installDebPackage bridge-utils
	installDebPackage arptables
	installDebPackage ebtables
	sudo sh -c 'echo "br_netfilter" >> /etc/modules'
	_popd
}

nextnet() {
	_pushd tools
	progress "nextnet"
	mkdir nextnet
	cd nextnet
	downloadRelease "hdm/nextnet" nextnet.*linux_amd64.tar.gz nextnet.tar.gz
	tar -xzf nextnet.tar.gz
	rm LICENSE nextnet.tar.gz
	_popd
}

nishang() {
	_pushd tools
	progress "nishang"
	cloneRepository "https://github.com/samratashok/nishang.git"
	_popd
}

noPac() {
	_pushd tools
	progress "noPac"
	cloneRepository "https://github.com/Ridter/noPac.git"
	_popd
}

ntlm-scanner() {
	_pushd tools
	progress "ntlm-scanner"
	cloneRepository "https://github.com/preempt/ntlm-scanner.git"
	_popd
}

ntlmv1-multi() {
	_pushd tools
	progress "ntlmv1-multi"
	cloneRepository "https://github.com/evilmog/ntlmv1-multi.git"
	_popd
}

nullinux() {
	_pushd tools
	progress "nullinux"
	cloneRepository "https://github.com/m8r0wn/nullinux.git"
	cd nullinux
	sudo bash setup.sh
	_popd
}

odat() {
	_pushd tools
	progress "odat"
	mkdir odat
	cd odat
	downloadRelease "quentinhardy/odat" odat-linux.*.tar.gz odat.tar.gz
	tar -xzf odat.tar.gz
	rm odat.tar.gz
	mv odat-* odat-dir
	mv odat-dir/* .
	rm -rf odat-dir
	_popd
}

paperify() {
	_pushd tools
	progress "paperify"
	cloneRepository "https://github.com/alisinabh/paperify.git"
	installDebPackage qrencode
	installDebPackage imagemagick
	cd paperify
	sudo ln -sv `readlink -f paperify.sh` /usr/local/bin/paperify
	_popd
}

payloadGenerator() {
	_pushd tools
	progress "payloadGenerator"
	cloneRepository "https://github.com/smokeme/payloadGenerator.git"
	_popd
}

pyGPOAbuse() {
	_pushd tools
	progress "pyGPOAbuse"
	cloneRepository "https://github.com/Hackndo/pyGPOAbuse.git"
	cd pyGPOAbuse
	python3 -m pip install -U -r requirements.txt
	python3 -m pip install -U aiosmb
	_popd
}

pyKerbrute() {
	_pushd tools
	progress "pyKerbrute"
	cloneRepository "https://github.com/3gstudent/pyKerbrute.git"
	_popd
}

pypykatz() {
	progress "pypykatz"
	pipx install -f "git+https://github.com/skelsec/pypykatz.git"
}

pywerview() {
	_pushd tools
	progress "pywerview"
	cloneRepository "https://github.com/the-useless-one/pywerview.git"
	cd pywerview
	python2 -m pip install -U -r requirements.txt
	_popd
}

pywhisker() {
	_pushd tools
	progress "pywhisker"
	cloneRepository "https://github.com/ShutdownRepo/pywhisker.git"
	cd pywhisker
	python3 -m pip install -U -r requirements.txt
	_popd
}

rbcd-attack() {
	_pushd tools
	progress "rbcd-attack"
	cloneRepository "https://github.com/tothi/rbcd-attack.git"
	_popd
}

rbcd_permissions() {
	_pushd tools
	progress "rbcd_permissions"
	cloneRepository "https://github.com/NinjaStyle82/rbcd_permissions.git"
	_popd
}

rdp-tunnel-tools() {
	_pushd tools
	progress "rdp-tunnel-tools"
	cloneRepository "https://github.com/NotMedic/rdp-tunnel.git"
	_popd
}

rtfm() {
	_pushd tools
	progress "rtfm"
	cloneRepository "https://github.com/leostat/rtfm.git"
	cd rtfm
	./rtfm -u 2>/dev/null
	echo 'function rtfm() { ~/tools/rtfm/rtfm.py "$@" 2>/dev/null }' >> ~/.zshrc
	_popd
}

sRDI() {
	_pushd tools
	progress "sRDI"
	cloneRepository "https://github.com/monoxgas/sRDI.git"
	_popd
}

sgn() {
	_pushd tools
	progress "sgn"
	mkdir sgn
	cd sgn
	downloadRelease "EgeBalci/sgn" sgn_linux_amd64.*.zip sgn.zip
	unzip -q sgn.zip
	mv sgn_*/sgn .
	rm -rf sgn.zip sgn_*
	sudo ln -sn `readlink -f sgn` /usr/bin/sgn
	_popd
}

smartbrute() {
	progress "smartbrute"
	pipx install -f "git+https://github.com/ShutdownRepo/smartbrute.git"
}

snmpwn() {
	_pushd tools
	progress "snmpwn"
	cloneRepository "https://github.com/hatlord/snmpwn.git"
	cd snmpwn
	bundle install --path ~/.gem
	_popd
}

spraykatz() {
	_pushd tools
	progress "spraykatz"
	cloneRepository "https://github.com/aas-n/spraykatz.git"
	cd spraykatz
	python3 -m pip install -U -r requirements.txt
	_popd
}

ssb() {
	_pushd tools
	progress "ssb"
	mkdir ssb
	cd ssb
	downloadRelease "kitabisa/ssb" ssb.*amd64.tar.gz ssb.tar.gz
	tar -xzf ssb.tar.gz
	rm LICENSE.md ssb.tar.gz
	_popd
}

sshuttle() {
	progress "sshuttle"
	installDebPackage sshpass
	installDebPackage sshuttle
}

targetedKerberoast() {
	_pushd tools
	progress "targetedKerberoast"
	cloneRepository "https://github.com/ShutdownRepo/targetedKerberoast.git"
	cd targetedKerberoast
	python3 -m pip install -U -r requirements.txt
	_popd
}

ticket_converter() {
	_pushd tools
	progress "ticket_converter"
	cloneRepository "https://github.com/eloypgz/ticket_converter.git"
	cd ticket_converter
	python2 -m pip install -U -r requirements.txt
	_popd
}

traitor() {
	_pushd tools
	progress "traitor"
	mkdir traitor
	cd traitor
	downloadRelease "liamg/traitor" traitor.*amd64 traitor
	chmod +x traitor
	_popd
}

updog() {
	progress "updog"
	pipx install -f "git+https://github.com/sc0tfree/updog.git"
}

webpage2html() {
	_pushd tools
	progress "webpage2html"
	cloneRepository "https://github.com/snovvcrash/webpage2html.git"
	cd webpage2html
	python2 -m pip install -U -r requirements.txt
	_popd
}

wesng() {
	_pushd tools
	progress "wesng"
	cloneRepository "https://github.com/bitsadmin/wesng.git"
	cd wesng
	python3 wes.py --update
	_popd
}

windapsearch() {
	_pushd tools
	progress "windapsearch"
	installDebPackage libsasl2-dev
	installDebPackage libldap2-dev
	installDebPackage libssl-dev
	cloneRepository "https://github.com/ropnop/windapsearch.git"
	cd windapsearch
	python3 -m pip install -U -r requirements.txt
	_popd
}

wmiexec-RegOut() {
	_pushd tools
	progress "wmiexec-RegOut"
	cloneRepository "https://github.com/XiaoliChan/wmiexec-RegOut.git"
	_popd
}

xc() {
	_pushd tools
	progress "xc"
	cloneRepository "https://github.com/xct/xc.git"
	cd xc
	GO111MODULE=off go get golang.org/x/sys/...
	GO111MODULE=off go get golang.org/x/text/encoding/unicode
	GO111MODULE=off go get github.com/hashicorp/yamux
	installDebPackage rlwrap
	installDebPackage upx
	python3 build.py
	chmod -x xc xc.exe
	cp xc xc.exe ../../www
	_popd
}

tools() {
	Amsi-Bypass-Powershell
	BloodHound
	BloodHound.py
	Certipy
	CS-BC-SECURITY-Malleable-C2-Profiles
	CS-Invoke-CredentialPhisher
	CS-RdpThief
	CS-Situational-Awareness-BOF
	CS-minimal-defender-bypass
	CS-nanodump
	CS-threatexpress-malleable-c2
	CVE-2019-1040-scanner
	CVE-2020-1472-checker
	CVE-2021-1675-tools
	Covenant
	CrackMapExec
	Creds
	DLLsForHackers
	DonPAPI
	DivideAndScan
	Ebowla
	Empire
	ItWasAllADream
	LDAPPER
	LDAPmonitor
	LdapRelayScan
	LightMe
	MS17-010
	MANSPIDER
	MeterPwrShell
	Nim
	NimlineWhispers
	Obsidian
	OffensiveNim
	PCredz
	PEzor
	PKINITtools
	PetitPotam
	PetitPotam-Ext
	#PoshC2
	PrivExchange
	Responder
	RustScan
	SCShell
	ScareCrow
	ShadowCoerce
	SharpGen
	SharpShooter
	ShellPop
	WebclientServiceScanner
	TrustVisualizer
	Windows-Exploit-Suggester
	#ack3
	aclpwn.py
	adidnsdump
	aquatone
	arsenal
	bettercap
	bloodhound-import
	bloodhound-quickwin
	certi
	chisel-server
	crowbar
	dementor.py
	dsniff
	eavesarp
	enum4linux-ng
	feroxbuster
	ffuf
	gMSADumper
	gateway-finder-imp
	gitjacker
	go-windapsearch
	gobuster
	hashcat-utils
	impacket
	ipmitool
	kerbrute
	krbrelayx
	ldapdomaindump
	ldapsearch-ad
	ligolo-ng-proxy
	lsassy
	masscan
	mitm6
	mscache
	nac_bypass
	nextnet
	nishang
	noPac
	ntlm-scanner
	ntlmv1-multi
	nullinux
	odat
	paperify
	payloadGenerator
	pyGPOAbuse
	pyKerbrute
	pypykatz
	pywerview
	pywhisker
	rbcd-attack
	rbcd_permissions
	rdp-tunnel-tools
	rtfm
	sRDI
	sgn
	smartbrute
	snmpwn
	spraykatz
	ssb
	sshuttle
	targetedKerberoast
	ticket_converter
	traitor
	updog
	webpage2html
	wesng
	windapsearch
	wmiexec-RegOut
	xc
}

# -----------------------------------------------------------------------------
# ------------------------------------ www ------------------------------------
# -----------------------------------------------------------------------------

ADCSPwn() {
	_pushd www
	downloadRelease "bats3c/ADCSPwn" ADCSPwn.exe adcspwn.exe
	_popd
}

ADRecon() {
	_pushd www
	downloadRawFile "https://github.com/adrecon/ADRecon/raw/master/ADRecon.ps1" adrecon.ps1
	_popd
}

ADSearch() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/ADSearch.exe" adsearch.exe
	_popd
}

ASREPRoast() {
	_pushd www
	downloadRawFile "https://github.com/HarmJ0y/ASREPRoast/raw/master/ASREPRoast.ps1" asreproast.ps1
	_popd
}

AccessChk() {
	_pushd www
	downloadRawFile "https://xor.cat/assets/other/Accesschk.zip" accesschk-accepteula.zip
	unzip -q accesschk-accepteula.zip
	mv accesschk.exe accesschk-accepteula.exe
	rm Eula.txt accesschk-accepteula.zip
	downloadRawFile "https://download.sysinternals.com/files/AccessChk.zip" accesschk.zip
	unzip -q accesschk.zip
	rm Eula.txt accesschk64a.exe accesschk.zip
	_popd
}

CVE-2021-1675-www() {
	_pushd www
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/SharpPrintNightmare.exe" sharpprintnightmare.exe
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/Invoke-SharpPrintNightmare.ps1" invoke-sharpprintnightmare.ps1
	_popd
}

Certify() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_Any/Certify.exe" certify.exe
	_popd
}

DefenderStop() {
	_pushd www
	downloadRelease "dosxuz/DefenderStop" DefenderStop_x64.exe defenderstop.exe
	_popd
}

Discover-PSMSExchangeServers() {
	_pushd www
	downloadRawFile "https://github.com/PyroTek3/PowerShell-AD-Recon/raw/master/Discover-PSMSExchangeServers" discover-psmsexchangeservers.ps1
	_popd
}

Discover-PSMSSQLServers() {
	_pushd www
	downloadRawFile "https://github.com/PyroTek3/PowerShell-AD-Recon/raw/master/Discover-PSMSSQLServers" discover-psmssqlservers.ps1
	_popd
}

DomainPasswordSpray() {
	_pushd www
	downloadRawFile "https://github.com/dafthack/DomainPasswordSpray/raw/master/DomainPasswordSpray.ps1" domainpasswordspray.ps1
	_popd
}

Grouper2() {
	_pushd www
	downloadRelease "l0ss/Grouper2" Grouper2.exe grouper2.exe
	_popd
}

HandleKatz() {
	_pushd www
	downloadRawFile "https://gist.github.com/S3cur3Th1sSh1t/9f328fc411ff103c0800294c523503e2/raw/fbebe3fa2e6ba7d617e450c7368e3ef8bf7b0e9a/Invoke-HandleKatzInject.ps1" invoke-handlekatzinject.ps1
	_popd
}

HiveNightmare() {
	_pushd www
	downloadRelease "GossiTheDog/HiveNightmare" HiveNightmare.exe hivenightmare.exe
	downloadRawFile "https://github.com/FireFart/hivenightmare/raw/main/release/hive.exe" hive.exe
	cloneRepository "https://github.com/HuskyHacks/ShadowSteal.git"
	cd ShadowSteal
	nimble install zippy argparse winim -y
	make
	mv bin/ShadowSteal.exe ../shadowsteal.exe
	chmod -x ../shadowsteal.exe
	cd ..
	rm -rf ShadowSteal
	_popd
}

Intercepter-NG() {
	_pushd www
	downloadRawFile "http://sniff.su/Intercepter-NG.v1.0+.zip" intercepter-ng.zip
	_popd
}

Inveigh() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Inveigh/raw/master/Inveigh-Relay.ps1" inveigh-relay.ps1
	downloadRawFile "https://github.com/Kevin-Robertson/Inveigh/raw/master/Inveigh.ps1" inveigh.ps1
	_popd
}

InveighZero() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_Any/Inveigh.exe" inveighzero.exe
	_popd
}

Invoke-ACLPwn() {
	_pushd www
	downloadRawFile "https://github.com/fox-it/Invoke-ACLPwn/raw/master/Invoke-ACLPwn.ps1" invoke-aclpwn.ps1
	_popd
}

Invoke-ImpersonateUser-PTH() {
	_pushd www
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/NamedPipePTH/raw/main/Invoke-ImpersonateUser-PTH.ps1" invoke-impersonateuser-pth.ps1
	_popd
}

Invoke-Portscan() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/Invoke-Portscan.ps1" invoke-portscan.ps1
	_popd
}

Invoke-RunasCs() {
	_pushd www
	downloadRawFile "https://github.com/antonioCoco/RunasCs/raw/master/Invoke-RunasCs.ps1" invoke-runascs.ps1
	_popd
}

Invoke-SMBClient() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBClient.ps1" invoke-smbclient.ps1
	_popd
}

Invoke-SMBEnum() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBEnum.ps1" invoke-smbenum.ps1
	_popd
}

Invoke-SMBExec() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBExec.ps1" invoke-smbexec.ps1
	_popd
}

Invoke-WMIExec() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-WMIExec.ps1" invoke-wmiexec.ps1
	_popd
}

Invoke-noPac() {
	_pushd www
	downloadRawFile "https://gist.github.com/S3cur3Th1sSh1t/0ed2fb0b5ae485b68cbc50e89581baa6/raw/4f0ab724a11c8984c29097250b1a8263e013d183/Invoke-noPac.ps1" invoke-nopac.ps1
	_popd
}

JAWS() {
	_pushd www
	downloadRawFile "https://github.com/411Hall/JAWS/raw/master/jaws-enum.ps1" jaws-enum.ps1
	_popd
}

JuicyPotato() {
	_pushd www
	downloadRelease "ohpe/juicy-potato" JuicyPotato.exe juicypotato64.exe
	downloadRelease "ivanitlearning/Juicy-Potato-x86" Juicy.Potato.x86.exe juicypotato32.exe
	_popd
}

LaZagne() {
	_pushd www
	downloadRelease "AlessandroZ/LaZagne" lazagne.exe lazagne.exe
	_popd
}

Out-EncryptedScript() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/master/ScriptModification/Out-EncryptedScript.ps1" out-encryptedscript.ps1
	_popd
}

PEASS() {
	_pushd www
	downloadRelease " carlospolop/PEASS-ng" linpeas.sh linpeas.sh
	downloadRelease " carlospolop/PEASS-ng" winPEASany.exe winpeas.exe
	downloadRelease " carlospolop/PEASS-ng" winPEAS.bat winpeas.bat
	_popd
}

PSInject() {
	_pushd www
	downloadRawFile "https://github.com/EmpireProject/PSInject/raw/master/Invoke-PSInject.ps1" invoke-psinject.ps1
	_popd
}

PingCastle() {
	_pushd www
	downloadRelease "vletoux/pingcastle" PingCastle.*.zip pingcastle.zip
	_popd
}

PowerShellArmoury() {
	_pushd www
	downloadRawFile "https://github.com/cfalta/PowerShellArmoury/raw/master/New-PSArmoury.ps1" new-psarmoury.ps1
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/extra/PSArmoury.json" psarmoury.json
	_popd
}

PowerUp() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/master/Privesc/PowerUp.ps1" powerup.ps1
	_popd
}

PowerUpSQL() {
	_pushd www
	downloadRawFile "https://github.com/NetSPI/PowerUpSQL/raw/master/PowerUpSQL.ps1" powerupsql.ps1
	_popd
}

PowerView2() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellEmpire/PowerTools/raw/master/PowerView/powerview.ps1" powerview2.ps1
	_popd
}

PowerView3() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1" powerview3.ps1
	_popd
}

PowerView3-GPO() {
	_pushd www
	downloadRawFile "https://github.com/PowerShellMafia/PowerSploit/raw/26a0757612e5654b4f792b012ab8f10f95d391c9/Recon/PowerView.ps1" powerview3-gpo.ps1
	_popd
}

PowerView4() {
	_pushd www
	downloadRawFile "https://github.com/ZeroDayLab/PowerSploit/raw/master/Recon/PowerView.ps1" powerview4.ps1
	_popd
}

PowerSharpPack() {
	_pushd www
	cloneRepository "https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git"
	_popd
}

Powermad() {
	_pushd www
	downloadRawFile "https://github.com/Kevin-Robertson/Powermad/raw/master/Powermad.ps1" powermad.ps1
	_popd
}

PrintSpoofer() {
	_pushd www
	downloadRelease "itm4n/PrintSpoofer" PrintSpoofer64.exe printspoofer64.exe
	_popd
}

PrivescCheck() {
	_pushd www
	downloadRawFile "https://github.com/itm4n/PrivescCheck/raw/master/PrivescCheck.ps1" privesccheck.ps1
	_popd
}

PSTools() {
	_pushd www
	downloadRawFile "https://download.sysinternals.com/files/PSTools.zip" pstools.zip
	unzip -q pstools.zip
	rm Eula.txt Pstools.chm psversion.txt pstools.zip
	_popd
}

ProcDump() {
	_pushd www
	downloadRawFile "https://download.sysinternals.com/files/Procdump.zip" procdump.zip
	unzip -q procdump.zip
	rm Eula.txt procdump64a.exe procdump.zip
	_popd
}

RemotePotato0() {
	_pushd www
	downloadRelease "antonioCoco/RemotePotato0" RemotePotato0.zip remotepotato0.zip
	unzip -q remotepotato0.zip
	rm remotepotato0.zip
	_popd
}

RoguePotato() {
	_pushd www
	downloadRelease "antonioCoco/RoguePotato" RoguePotato.zip roguepotato.zip
	unzip -q roguepotato.zip
	rm roguepotato.zip
	_popd
}

Rubeus() {
	_pushd www
	downloadRawFile "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" rubeus.exe
	_popd
}

SandboxDefender() {
	_pushd www
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/SandboxDefender.exe" sandboxdefender.exe
	_popd
}

Seatbelt() {
	_pushd www
	downloadRawFile "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe" seatbelt.exe
	_popd
}

SessionGopher() {
	_pushd www
	downloadRawFile "https://github.com/Arvanaghi/SessionGopher/raw/master/SessionGopher.ps1" sessiongopher.ps1
	_popd
}

SharpChrome() {
	_pushd www
	downloadRawFile "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpChrome.exe" sharpchrome.exe
	_popd
}

SharpDPAPI() {
	_pushd www
	downloadRawFile "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpDPAPI.exe" sharpdpapi.exe
	_popd
}

SharpGPOAbuse() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_Any/SharpGPOAbuse.exe" sharpgpoabuse.exe
	_popd
}

SharpHandler() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_Any/SharpHandler.exe" sharphandler.exe
	_popd
}

SharpHound() {
	_pushd www
	downloadRawFile "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe" sharphound.exe
	downloadRawFile "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.ps1" sharphound.ps1
	_popd
}

SharpImpersonation() {
	_pushd www
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/SharpImpersonation.exe" sharpimpersonation.exe
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/Invoke-SharpImpersonation.ps1" invoke-sharpimpersonation.ps1
	_popd
}

SharpLAPS() {
	_pushd www
	downloadRelease "swisskyrepo/SharpLAPS" SharpLAPS.exe sharplaps.exe
	_popd
}

SharpNamedPipePTH() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_Any/SharpNamedPipePTH.exe" sharpnamedpipepth.exe
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/Invoke-SharpNamedPipePTH.ps1" invoke-sharpnamedpipepth.ps1
	_popd
}

SharpRDP() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.5_Any/SharpRDP.exe" sharprdp.exe
	_popd
}

SharpRdpThief() {
	_pushd www
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/SharpRdpThief.exe" sharprdpthief.exe
	_popd
}

SharpRelay() {
	_pushd www
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/SharpRelay.exe" sharprelay.exe
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/WinDivert64.sys" windivert64.sys
	_popd
}

SharpSecDump() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_Any/SharpSecDump.exe" sharpsecdump.exe
	_popd
}

SharpSystemTriggers() {
	_pushd www
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/SharpDcomTrigger.exe" sharpdcomtrigger.exe
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/SharpEfsTrigger.exe" sharpefstrigger.exe
	downloadRawFile "https://github.com/penetrarnya-tm/WeaponizeKali.sh/raw/main/bin/SharpSpoolTrigger.exe" sharpspooltrigger.exe
	_popd
}

SharpView() {
	_pushd www
	downloadRawFile "https://github.com/tevora-threat/SharpView/raw/master/Compiled/SharpView.exe" sharpview.exe
	_popd
}

Sherlock() {
	_pushd www
	downloadRawFile "https://github.com/rasta-mouse/Sherlock/raw/master/Sherlock.ps1" sherlock.ps1
	_popd
}

Snaffler() {
	_pushd www
	downloadRelease "SnaffCon/Snaffler" Snaffler.exe snaffler.exe
	_popd
}

SpoolSample() {
	_pushd www
	downloadRawFile "https://github.com/BlackDiverX/WinTools/raw/master/SpoolSample-Printerbug/SpoolSample.exe" spoolsample.exe
	_popd
}

StandIn() {
	_pushd www
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_Any/StandIn.exe" standin.exe
	_popd
}

WerTrigger() {
	_pushd www
	downloadRawFile "https://github.com/sailay1996/WerTrigger/archive/refs/heads/master.zip" wertrigger.zip
	_popd
}

WinPwn() {
	_pushd www
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/WinPwn.ps1" winpwn.ps1
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/ObfusWinPwn.ps1" obfuswinpwn.ps1
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/Obfus_SecurePS_WinPwn.ps1" obfus-secureps-winpwn.ps1
	downloadRawFile "https://github.com/S3cur3Th1sSh1t/WinPwn/raw/master/Offline_WinPwn.ps1" offline-winpwn.ps1
	_popd
}

arpfox() {
	_pushd www
	downloadRelease "malfunkt/arpfox" arpfox_linux_amd64.gz arpfox.gz
	gunzip arpfox.gz
	_popd
}

chisel-clients() {
	_pushd www
	mkdir tmp1
	cd tmp1
	downloadRelease "jpillora/chisel" chisel.*linux_amd64.gz chisel.gz
	gunzip chisel.gz
	mv chisel ../chisel
	cd ..
	mkdir tmp2
	cd tmp2
	downloadRelease "jpillora/chisel" chisel.*windows_amd64.gz chisel.exe.gz
	gunzip chisel.exe.gz
	mv chisel.exe ../chisel.exe
	cd ..
	rm -rf tmp1 tmp2
	downloadRawFile "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_Any/SharpChisel.exe" sharpchisel.exe
	_popd
}

ligolo-ng-agents() {
	_pushd www
	mkdir tmp1
	cd tmp1
	downloadRelease "tnpitsecurity/ligolo-ng" ligolo-ng_agent.*Linux_64bit.tar.gz ligolo-agent.tar.gz
	tar -xzf ligolo-agent.tar.gz
	mv agent ../ligolo-agent
	cd ..
	mkdir tmp2
	cd tmp2
	downloadRelease "tnpitsecurity/ligolo-ng" ligolo-ng_agent.*Windows_64bit.zip ligolo-agent.exe.zip
	unzip -q ligolo-agent.exe.zip
	mv agent.exe ../ligolo-agent.exe
	cd ..
	chmod -x ligolo-agent ligolo-agent.exe
	rm -rf tmp1 tmp2
	_popd
}

linux-exploit-suggester() {
	_pushd www
	downloadRawFile "https://github.com/mzet-/linux-exploit-suggester/raw/master/linux-exploit-suggester.sh" les.sh
	_popd
}

linux-smart-enumeration() {
	_pushd www
	downloadRawFile "https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh" lse.sh
	_popd
}

mimikatz() {
	_pushd www
	downloadRelease "gentilkiwi/mimikatz" mimikatz_trunk.zip mimikatz.zip
	_popd
}

netcat-win() {
	_pushd www
	downloadRawFile "https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip" nc.zip
	unzip -q nc.zip
	rm doexec.c generic.h getopt.c getopt.h hobbit.txt license.txt Makefile netcat.c readme.txt nc.zip
	_popd
}

plink() {
	_pushd www
	downloadRawFile "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" plink.exe
	_popd
}

powercat() {
	_pushd www
	downloadRawFile "https://github.com/besimorhino/powercat/raw/master/powercat.ps1" powercat.ps1
	_popd
}

pspy() {
	_pushd www
	downloadRelease "DominicBreuker/pspy" pspy64 pspy
	_popd
}

pypykatz-exe() {
	_pushd www
	downloadRelease "skelsec/pypykatz" pypykatz.exe pypykatz.exe
	_popd
}

rdp-tunnel-www() {
	_pushd www
	downloadRawFile "https://github.com/NotMedic/rdp-tunnel/raw/master/rdp2tcp.exe" rdp2tcp.exe
	_popd
}

static-binaries() {
	_pushd www
	cloneRepository "https://github.com/andrew-d/static-binaries.git"
	_popd
}

suid3num.py() {
	_pushd www
	downloadRawFile "https://github.com/Anon-Exploiter/SUID3NUM/raw/master/suid3num.py" suid3num.py
	_popd
}

www() {
	ADCSPwn
	ADRecon
	ADSearch
	ASREPRoast
	AccessChk
	CVE-2021-1675-www
	Certify
	DefenderStop
	Discover-PSMSExchangeServers
	Discover-PSMSSQLServers
	DomainPasswordSpray
	#Grouper2
	HandleKatz
	#HiveNightmare
	Intercepter-NG
	Inveigh
	InveighZero
	Invoke-ACLPwn
	Invoke-ImpersonateUser-PTH
	Invoke-Portscan
	Invoke-RunasCs
	Invoke-SMBClient
	Invoke-SMBEnum
	Invoke-SMBExec
	Invoke-WMIExec
	Invoke-noPac
	JAWS
	JuicyPotato
	LaZagne
	Out-EncryptedScript
	PEASS
	PSInject
	PingCastle
	PowerShellArmoury
	PowerUp
	PowerUpSQL
	PowerView2
	PowerView3
	PowerView3-GPO
	PowerView4
	PowerSharpPack
	Powermad
	PrintSpoofer
	PrivescCheck
	PSTools
	ProcDump
	RemotePotato0
	RoguePotato
	Rubeus
	SandboxDefender
	Seatbelt
	SessionGopher
	SharpChrome
	SharpDPAPI
	SharpGPOAbuse
	SharpHandler
	SharpHound
	SharpImpersonation
	SharpLAPS
	SharpNamedPipePTH
	SharpRDP
	SharpRdpThief
	SharpRelay
	SharpSecDump
	SharpView
	Sherlock
	Snaffler
	SpoolSample
	StandIn
	WerTrigger
	WinPwn
	arpfox
	chisel-clients
	ligolo-ng-agents
	linux-exploit-suggester
	mimikatz
	netcat-win
	plink
	powercat
	pspy
	pypykatz-exe
	rdp-tunnel-www
	static-binaries
	suid3num.py
}

# -----------------------------------------------------------------------------
# ----------------------------------- Help ------------------------------------
# -----------------------------------------------------------------------------

help() {
	echo "usage: EasiWeapons.sh [-h] [-i] [-d] [-t] [w]"
	echo
	echo "optional arguments:"
	echo "  -h                    show this help message and exit"
	echo "  -i                    initialize filesystem (re-create ./tools and ./www directories)"
	echo "  -d                    resolve dependencies"
	echo "  -t                    download and install tools on Kali Linux"
	echo "  -w                    download scripts and binaries for transferring onto the victim host"
	echo "  -hidtw                basic install"
}

# -----------------------------------------------------------------------------
# ----------------------------------- Main ------------------------------------
# -----------------------------------------------------------------------------

while getopts "hidtw" opt; do
	case "$opt" in
	h)
		call_help=1
		;;
	i)
		init_filesystem=1
		;;
	d)
		resolve_dependencies=1
		;;
	t)
		call_tools=1
		;;
	w)
		call_www=1
		;;
	esac
done

if [[ "$call_help" ]]; then
	help
	exit
fi

if [[ "$init_filesystem" ]]; then
	filesystem
fi

if [[ "$resolve_dependencies" ]]; then
	echo -e "${red}################################### dependencies ####################################"
	dependencies
fi

if [[ "$call_tools" ]]; then
	sudo apt update
	echo -e "${red}####################################### tools #######################################"
	tools
fi

if [[ "$call_www" ]]; then
	echo -e "${red}######################################## www ########################################"
	www
fi