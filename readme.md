# OSCP Cheatsheet

The following collection is a wild (but structured) selection of commands, snippets, exploits, tools, lists and techniques I personally tested and used on my journey to becoming an OSCP. I will extend and update it from time to time, let's see where this is going.

# Reconnaissance

## Nmap

### Initial fast TCP scan

```shell
nmap -v -sS -sV -Pn --top-ports 1000 -oA first_10.10.10.181 10.10.10.181
```