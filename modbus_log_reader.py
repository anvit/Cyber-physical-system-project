import json
import csv
from collections import Counter
import numpy as np

# ip = []
src_ip = []
# src_p = []
dst_ip = []
# dst_p = []
func = []
src_dst = []
select_src_ip = []
select_dst_ip = []
# src_host43 = []
# dst_host43 = []
diff_host = []
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
				src_ip.append(row[2])
				# src_p.append(row[3])
				dst_ip.append(row[4])
				# dst_p.append(row[5])
				func.append(row[6])
				ctr = ctr + 1
				if(row[2]=='172.16.2.34'):
					select_src_ip.append(row[4])
				elif(row[4]=='172.16.2.34'):
					select_dst_ip.append(row[2])
				# elif(row[2]=='172.16.2.43'):
				# 	src_host43.append(row[4])
				# elif(row[4]=='172.16.2.43'):
				# 	dst_host43.append(row[2])
				else:
					diff_host.append(row[2]+"*"+row[4])

count_src_freq = Counter(select_src_ip)
count_dst_freq = Counter(select_dst_ip)

print count_dst_freq
dst_freq_file = open('../modbus_dst_freq.txt', 'w')
dst_freq_file.write(str(count_dst_freq))

print count_src_freq
src_freq_file = open('../modbus_src_freq.txt', 'w')
src_freq_file.write(str(count_src_freq))

count_diff_freq = Counter(diff_host)

connect_diff_file = open('../modbus_diff_freq.txt', 'w')
connect_diff_file.write(str(count_diff_freq))