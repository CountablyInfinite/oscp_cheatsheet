# OSCP Cheatsheet

The following collection is a wild (but structured) selection of commands, snippets, links, exploits, tools, lists and techniques I personally tested and used on my journey to becoming an OSCP. I will extend and update it from time to time, so let's see where this is going. 

## Disclaimer
This cheatsheet is definitely not "complete". I am sure i forgot to write down hundreds of essential commands, use most of them in the wrong way with unnessecary flags and you'll  probably soon ask yourself how i've even made it through the exam. Feel free to issue a PR if you want to help to improve the list.
**Use for educational pruposes only!**

***

# Reconnaissance

## Autorecon
https://github.com/Tib3rius/AutoRecon

```bash
autorecon -vv 192.168.0.1
```

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

## Enum4Linux

### Scan Hos
```bash
enum4linux 192.168.0.1
```
### Scan Host, Suppress Errors
```bash
enum4linux 192.168.0.1 | grep -Ev '^(Use of)' > enum4linux.out 
```



