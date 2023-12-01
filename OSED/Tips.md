- Dumpbin via dev shell for symbols and headers etc.
### Pattern create:
```bash
msf-pattern_create -l x
msf-pattern_offset -l x -q bytes
```

Might have endianness reversed
#### String Instructions
https://medium.com/@ophirharpaz/a-summary-of-x86-string-instructions-87566a28c20c
#### Catching Shell
```bash
ncat -lvp 4444
```
### Show PID in title bars
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer
DWORD32 ShowPidInTitle = 1
```
### Process Hacker
Add relative start time column and sort by it to speed up finding new process
### Reset Routing
``` bash
route -p add 192.168.xxx.0 mask 255.255.255.0 192.168.45.1 metric 1 
```
### OpenVPN from Kali
Very simple but for the sake of recording it
```bash
tar xvfj archive.tar.bz2
sudo openvpn vpn.ovpn
```
### RDP
```bash
xfreerdp /u:user /p:pass /v:1.2.3.4 /dynamic-resolution 
```
### Web Server Buffer Space
If attacking a web server, try:
``` python
...
requestBuffer += b"\r\n"
requestBuffer += secondStage()
requestBuffer += b"\r\n\r\n"
```
As a possible means to having another buffer to work with.

Alternatively try straight up:
``` python
...
requestBuffer += b"...\r\n\r\n"
requestBuffer += secondStage()
```