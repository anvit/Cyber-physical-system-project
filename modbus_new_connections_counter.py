import json
import csv
from collections import Counter
import numpy as np

src_ip = []
dst_ip = []
src_dst = []
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
				src_dst.append(row[2]+"*" + row[4])
				ctr = ctr + 1

conns_per_min = []
conn = 0
r0 = time[0]
ip_n_set_chk = []
for i in range(0,len(src_dst)):
	print i
	if(time[i]>=r0 and time[i]<(r0+60)):
		if (src_dst[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(src_dst[i])
			conn = conn + 1
	elif(time[i]>=(r0+60)):
		r0 = r0 + 60
		if (src_dst[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(src_dst[i])
			conn = conn + 1
		conns_per_min.append(conn)
		conn = 0

cpm_file = open('../modbus_conn_cpm.csv', 'w')
for i in range(0,len(conns_per_min)):
	cpm_file.write(str(i) + "," + str(conns_per_min[i]) + "\n")
cpm_file.close()


conns_ip_per_min = []
conn_ip = 0
r0 = time[0]
ip_set_chk = []
for i in range(0,len(dst_ip)):
	print i
	if(time[i]>=r0 and time[i]<(r0+60)):
		if (dst_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(dst_ip[i])
			conn_ip = conn_ip + 1
		elif (src_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(src_ip[i])
			conn_ip = conn_ip + 1
	elif(time[i]>=(r0+60)):
		r0 = r0 + 60
		if (dst_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(dst_ip[i])
			conn_ip = conn_ip + 1
		elif (src_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(src_ip[i])
			conn_ip = conn_ip + 1
		conns_ip_per_min.append(conn_ip)
		conn_ip = 0

cpm_file = open('../modbus_ip_cpm.csv', 'w')
for i in range(0,len(conns_ip_per_min)):
	cpm_file.write(str(i) + "," + str(conns_ip_per_min[i]) + "\n")
cpm_file.close()