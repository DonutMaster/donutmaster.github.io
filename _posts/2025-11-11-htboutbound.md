---
title: Outbound Writeup
date: 2025-11-11
categories: [HackTheBox Challenges, HTB Easy]
tags: [htb, challenge, easy]
description: HackTheBox Outbound Easy Challenge Writeup
---

> Challenge description:
> 
> As is common in real life pentests, you will start the Outbound box with credentials for the following account:
> 
> tyler / LhKL1o9Nm3X2
{: .prompt-info }

<br>

---

## Adding IP to /etc/hosts

To add the machine IP into your /etc/hosts, we can use this command:
```terminal
sudo echo '10.10.11.77 outbound.htb' >> /etc/hosts
```

## Rustscan

Let's use Rustscan/Nmap to check the ports on the Outbound machine.

```terminal
┌──(kali㉿kali)-[~/Desktop/HTB/Outbound]
└─$ rustscan -a outbound.htb -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
Open 10.10.11.77:22
Open 10.10.11.77:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 10.10.11.77
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-11 05:45 EST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
Initiating Ping Scan at 05:45
Scanning 10.10.11.77 [4 ports]
Completed Ping Scan at 05:45, 0.09s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 05:45
Scanning outbound.htb (10.10.11.77) [2 ports]
Discovered open port 80/tcp on 10.10.11.77
Discovered open port 22/tcp on 10.10.11.77
Completed SYN Stealth Scan at 05:45, 0.09s elapsed (2 total ports)
Initiating Service scan at 05:45
Scanning 2 services on outbound.htb (10.10.11.77)
Completed Service scan at 05:45, 6.15s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against outbound.htb (10.10.11.77)
Initiating Traceroute at 05:45
Completed Traceroute at 05:45, 0.07s elapsed
Initiating Parallel DNS resolution of 1 host. at 05:45
Completed Parallel DNS resolution of 1 host. at 05:45, 0.16s elapsed
DNS resolution of 1 IPs took 0.16s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
NSE: Script scanning 10.10.11.77.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 2.05s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.29s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
Nmap scan report for outbound.htb (10.10.11.77)
Host is up, received echo-reply ttl 63 (0.069s latency).
Scanned at 2025-11-11 05:45:17 EST for 10s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=11/11%OT=22%CT=%CU=30946%PV=Y%DS=2%DC=T%G=N%TM=691313C
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST1
OS:1NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Uptime guess: 19.440 days (since Wed Oct 22 20:11:35 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   69.35 ms 10.10.14.1
2   69.43 ms outbound.htb (10.10.11.77)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:45
Completed NSE at 05:45, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.85 seconds
           Raw packets sent: 38 (2.458KB) | Rcvd: 28 (1.886KB)
```

> # <center> 🔒 Post is Locked 🔒 </center>
> <br>
> "Outbound" is currently an active machine on HackTheBox. Once retired, this blog post will be published for public access, as per [HackTheBox's policy](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines?ref=benheater.com) on publishing content from their platform.
{: .prompt-info }