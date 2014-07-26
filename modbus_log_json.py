import json
import csv
from collections import Counter
import numpy as np

js = [ {} ]
ctr = 0
for j in range(0,166):
	addr = '../Large-Logs/pcap'+str(j)+'/modbus.log'
	num_lines = sum(1 for line in open(addr))
	i = 0
	print j
	with open(addr, 'r') as csvfile:
		spamreader = csv.reader(csvfile, delimiter='	')
		for row in spamreader:
			i = i + 1
			if row[0][0]!="#" and i<(num_lines):
				js[0][ctr]= { "time" : row[0], "src_ip" : row[2], "dst_ip" : row[4], "src_port" : row[3], "dest_port" : row[5], "func" : row[6] }
				ctr = ctr + 1

file = open("../modbus_data.json", "w")
temp = json.dumps(js, sort_keys=True, indent=1, separators=(',', ': '))
wr = temp[1:-1]
file.write(wr)
file.close()
