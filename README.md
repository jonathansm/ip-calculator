# ip-calculator
IP Calculator will calculate all relevant information for an IP. You can input a single IP or pipe IPs in from anything

```
Variables:
-c Display subnetmask and CIDR table
-x Display the results in XML format
-j Display the results in JSON format
-h Display the help
```
```
Examples:
./ip-calculator 192.168.0.10/24
./ip-calculator 192.168.0.10 255.255.255.0
cat ips.txt | ./ip-calculator
cat ips.txt | ./ip-calculator -j
```

```
Output examples:

./ip-calculator 192.168.0.10/24

------------------  IP Address Info  ------------------
| IP Address                             192.168.0.10 |
| Subnet Mask                           255.255.255.0 |
| CIDR                                             24 |
| Network Address                         192.168.0.0 |
| Broadcast Address                     192.168.0.255 |
| Range                   192.168.0.1 - 192.168.0.254 |
| Number of hosts                                 254 |
-------------------------------------------------------

./ip-calculator 192.168.0.10/24 -j
[
{
 "ip":"192.168.0.10",
 "subnetmask":"255.255.255.0",
 "cidr":"24",
 "networkaddress":"192.168.0.0",
 "broadcastaddress":"192.168.0.255",
 "range":"192.168.0.1 - 192.168.0.254",
 "hosts":"254"
}
]
```

The current compiled executable was compiled on MacOS 10.12.5 with gcc `Apple LLVM version 8.1.0 (clang-802.0.42)`