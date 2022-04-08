## snortchallenges1.md
unfinished 2022/04

### Task2
1. `detect all TCP port 80`
   * alert tcp any 80 <> any any (msg: "TCP Port 80";sid:1000001;rev:1;)
   * alert tcp any any <> any 80 (msg: "TCP Port 80";sid:1000002;rev:1;)
   * -> 328
2. `destination address of packet 63`
   * write alerts file w\ '-A fast', grep file line numbers 'cat -n' and grep for line '63'
   * -> 145.254.160.237
3. `ACK number of packet 64?`
   * work around from above no longer works as we more info using '-A full'
   * ACK numbers tend to get reused, so I just tried a few
   * 0x38AFFFF3
4. `SEQ number of packet 62?`
   * 0x38AFFFF3
5. `TTL of packet 65`
   * 128
6. `soure IP of packet 65`
   * 145.254.160.237
7. `soure port of packet 65`
   * 3372

### Task3
1. `detect all TCP port 21`
   * alert tcp any 21 <> any any (msg: "TCP Port 21";sid:1000001;rev:1;)
   * alert tcp any any <> any 21 (msg: "TCP Port 21";sid:1000002;rev:1;)
   * 614
2. `ftp service name`
   * didnt find a nice filter, so 'sudo snort -X -v -r ftp-png-gif.pcap > fulldump'
   * cat fulldump \| grep 220
   * microsoft ftp service
3. `number of failed ftp logins`
   * alert tcp any any <> any any (msg: "Failed login FTP"; content:"530 "; sid:1000004;rev:1;)
   * 41
4. `number of successful ftp logins`
   * alert tcp any any <> any any (msg: "Login FTP"; content:"230 User"; sid:1000005;rev:1;)
   * 1
5. `number of failed logins with valid user`
   * alert tcp any any <> any any (msg: "User ok, need pass"; content:"331 Password"; sid:1000006;rev:1;)
   * 42
6. `number of failed logins with user Administrator`
   * alert tcp any any <> any any (msg: "User Admin, need pass"; content:"331 Password required for Administrator"; sid:1000007;rev:1;)
   * 7

### Task 4
