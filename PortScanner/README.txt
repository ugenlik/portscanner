Author: 
Umut Can Genlik

Description:
Code connects and search for open ports. Unix specific ports and Windows specific ports are held in global array lists. Connection function simply tries to connect well-known ports and if timeout occurs it sends the port number to array list and compare either if it is a Unix or Windows port. After searching all the ports according to numbers of open TCP and UDP ports program determines OS of target machine. If number of Windows ports greater it guesses target OS is Windows otherwise it is Unix or undetermined. If port 80 is open on host it sends "GET HTTP" to server and reads the header.


Vulnerabilities:
	According to Header from port 80 a hacker can see what version of OS server runs. Hacker can attack known vulnerabilities of that OS. Practical solution would be updating server OS to latest version and close GET method.
	
	Bounce Scan: A port scanner can exploit this to scan TCP ports from a proxy ftp server. Thus you could connect to an FTP server behind a firewall, and then scan ports that are more likely to be blocked (e.g., port 139). If the ftp server allows reading from and writing to a directory (such as /incoming), you can send arbitrary data to ports that you do find open.
	
	SYN scan:his technique is also called half-open scanning, because a TCP connection is not completed. A SYN packet is sent (as if we are going to open a connection), and the target host responds with a SYN+ACK, this indicates the port is listening, and an RST indicates a non- listener. The server process is never informed by the TCP layer because the connection did not complete.
	FIN scan:
	The typical TCP scan attempts to open connections (at least part way). Another technique sends erroneous packets at a port, expecting that open listening ports will send back different error messages than closed ports. The scanner sends a FIN packet, which should close a connection that is open. Closed ports reply to a FIN packet with a RST. Open ports, on the other hand, ignore the packet in question. This is required TCP behavior
	
	Fingerprinting an OS:The last scanning method is called Fingerprinting. Fingerprinting is the technique of interpreting the responses of a system in order to figure out what it is. Unusual combination’s of data are sent to the system in order to trigger these responses. Systems respond the same with correct data, but they rarely respond the same way for wrong data.




Outputs: 
1.
Starting scan on 128.226.119.104
Number of open TCP ports: 4
Number of open UDP ports: 0
Number of open Windows-specific TCP ports: 2
Number of open Unix-specific TCP ports: 0
Target is probably running Windows
A web server appears to be running on target machine. I am going to try to get the "Server" header.
Server: Apache/2.2.16 (Win32)

2.
Starting scan on 128.226.119.62...
Number of open TCP ports: 3
Number of open UDP ports: 0
Number of open Windows-specific TCP ports: 3
Number of open Unix-specific TCP ports: 0
Target is probably running Windows
A web server appears to be running on target machine. I am going to try to get the "Server" header.
Cannot connect to web server.

3.
Starting scan on 128.226.74.189...
Number of open TCP ports: 2
Number of open UDP ports: 0
Number of open Windows-specific TCP ports: 0
Number of open Unix-specific TCP ports: 1
Target is probably running Unix
A web server appears to be running on target machine. I am going to try to get the "Server" header.
Server: Apache/2.2.14 (Ubuntu)


4.
Starting scan on 128.226.119.186...
Number of open TCP ports: 0
Number of open UDP ports: 0
Number of open Windows-specific TCP ports: 0
Number of open Unix-specific TCP ports: 0
Cannot determine the target OS based on open ports.
A web server appears to be running on target machine. I am going to try to get the "Server" header.
Cannot connect to web server.



5.
Starting scan on 128.226.119.63...
Number of open TCP ports: 2
Number of open UDP ports: 0
Number of open Windows-specific TCP ports: 0
Number of open Unix-specific TCP ports: 1
Target is probably running Unix
A web server appears to be running on target machine. I am going to try to get the "Server" header.
Server: Apache/2.2.6 (Fedora)

