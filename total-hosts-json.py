import sys
import json

try:
    if not sys.stdin.isatty():
        data = json.load(sys.stdin)
    else:
        with open(sys.argv[1]) as data_file:
            data = json.load(data_file)
except:
    print("File failed to load.")
    quit()

totalIPs = 0
totalHosts = 0

for ip in data:
    totalHosts += int(ip['hosts'])
    totalIPs += 1

print("Total Subnets ",totalIPs)
print("Total IPs ", "{:,}".format(totalHosts))