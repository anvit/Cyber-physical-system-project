import json
import csv
from collections import Counter
import numpy as np

src_ip = []
src_p = []
dst_ip = []
dst_p = []
proto = []
ip = []
duration = []
src_dst = []
src_dst_split = []
count_each = []
select_src_ip = []
select_dst_ip = []
diff_host = []
resp_bytes = []
src_host43 = []
dst_host43 = []
ctr = 0
time = []
for j in range(0,166):
	addr = '../Large-Logs/pcap'+str(j)+'/conn.log'
	num_lines = sum(1 for line in open(addr))
	i = 0
	with open(addr, 'r') as csvfile:
		spamreader = csv.reader(csvfile, delimiter='	')
		for row in spamreader:
			i = i + 1
			if row[0][0]!="#" and i<(num_lines):
				src_ip.append(row[2])
				ip.append(row[2])
				ip.append(row[4])
				src_p.append(row[3])
				dst_ip.append(row[4])
				dst_p.append(row[5])
				proto.append(row[6])
				resp_bytes.append(row[10])
				duration.append(row[8])
				src_dst.append(row[2]+":"+row[4])
				time.append(float(row[0]))

conns_per_sec = []
conn = 0
r0 = time[0]
ip_set_chk = []

for i in range(0,len(dst_ip)):
	print i
	if(time[i]>=r0 and time[i]<(r0+1)):
		if (dst_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(dst_ip[i])
			conn = conn + 1
		elif (src_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(src_ip[i])
			conn = conn + 1
	elif(time[i]>=(r0+1)):
		r0 = r0 + 1
		if (dst_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(dst_ip[i])
			conn = conn + 1
		elif (src_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(src_ip[i])
			conn = conn + 1
		conns_per_sec.append(conn)
		conn = 0

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
	elif(time[i]>=(r0+60)):
		r0 = r0 + 60
		if (dst_ip[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(dst_ip[i])
			conn = conn + 1
		conns_per_min.append(conn)
		conn = 0


cps_file = open('../count_cps.csv', 'w')
for i in range(0,len(conns_per_sec)):
	cps_file.write(str(i) + "," + str(conns_per_sec[i]) + "\n")
cps_file.close()

cpm_file = open('../count_cpm.csv', 'w')
for i in range(0,len(conns_per_min)):
	cpm_file.write(str(i) + "," + str(conns_per_min[i]) + "\n")
cpm_file.close()