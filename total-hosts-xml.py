import sys
import untangle

try:
    if not sys.stdin.isatty():
        data = untangle.parse(sys.stdin)
    else:
        data = untangle.parse(sys.argv[1])
except:
    print("File failed to load.")
    quit()

totalIPs = 0
totalHosts = 0

for ip in data.root.ip:
    totalHosts += int(ip.hosts.cdata)
    totalIPs += 1

print("Total Subnets ",totalIPs)
print("Total IPs ", "{:,}".format(totalHosts))
