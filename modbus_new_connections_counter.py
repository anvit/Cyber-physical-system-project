import json
import csv
from collections import Counter
import numpy as np

src_ip = []
dst_ip = []
func = []
src_dst = []
select_src_ip = []
select_dst_ip = []
diff_host = []
time = []
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
				time.append(float(row[0]))
				dst_ip.append(row[4])
				func.append(row[6])
				ctr = ctr + 1

# conns_per_sec = []
# conn = 0
# r0 = time[0]
# ip_set_chk = []

# for i in range(0,len(dst_ip)):
# 	print i
# 	if(time[i]>=r0 and time[i]<(r0+1)):
# 		if (dst_ip[i] in ip_set_chk) == False:
# 			ip_set_chk.append(dst_ip[i])
# 			conn = conn + 1
# 	elif(time[i]>=(r0+1)):
# 		r0 = r0 + 1
# 		if (dst_ip[i] in ip_set_chk) == False:
# 			ip_set_chk.append(dst_ip[i])
# 			conn = conn + 1
# 		conns_per_sec.append(conn)
# 		conn = 0

conns_per_min = []
conn = 0
r0 = time[0]
ip_n_set_chk = []
for i in range(0,len(dst_ip)):
	print i
	if(time[i]>=r0 and time[i]<(r0+60)):
		if (dst_ip[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(dst_ip[i])
			conn = conn + 1
		elif (src_ip[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(src_ip[i])
			conn = conn + 1
	elif(time[i]>=(r0+60)):
		r0 = r0 + 60
		if (dst_ip[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(dst_ip[i])
			conn = conn + 1
		elif (src_ip[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(src_ip[i])
			conn = conn + 1
		conns_per_min.append(conn)
		conn = 0


# cps_file = open('../modbus_cps.csv', 'w')
# for i in range(0,len(conns_per_sec)):
# 	cps_file.write(str(i) + "," + str(conns_per_sec[i]) + "\n")
# cps_file.close()

cpm_file = open('../modbus_cpm.csv', 'w')
for i in range(0,len(conns_per_min)):
	cpm_file.write(str(i) + "," + str(conns_per_min[i]) + "\n")
cpm_file.close()