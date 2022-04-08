## snortchallenges1.md
finished 2022/04

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

