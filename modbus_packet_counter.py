import json
import csv
from collections import Counter
import numpy as np

modbus_uids = [line.strip() for line in open('../modbus_uids.csv')]


ip = []
modbus_ip = []
src_ip = []
dst_ip = []
modbus_src_ip = []
modbus_dst_ip = []
conn_bytes = []
modbus_bytes = []
uid = []
modbus_uid = []
ctr = 0
time = []
modbus_time = []
for j in range(0,166):
	addr = '../Large-Logs/pcap'+str(j)+'/conn.log'
	num_lines = sum(1 for line in open(addr))
	i = 0
	print j
	with open(addr, 'r') as csvfile:
		spamreader = csv.reader(csvfile, delimiter='	')
		for row in spamreader:
			i = i + 1
			if row[0][0]!="#" and i<(num_lines):
				if(row[1] in modbus_uids):
					modbus_time.append(float(row[0]))
					modbus_uid.append(row[1])
					modbus_ip.append(row[2] + "*" + row[4])
					modbus_src_ip.append(row[2])
					modbus_dst_ip.append(row[4])
					modbus_bytes.append(row[10])
				else:
					time.append(float(row[0]))
					ip.append(row[2] + "*" + row[4])
					uid.append(row[1])
					src_ip.append(row[2])
					dst_ip.append(row[4])
					conn_bytes.append(row[10])

modbus_pkts_per_min = []
pkt = 0
r0 = modbus_time[0]
for i in range(0,len(modbus_bytes)):
	print i
	if(modbus_time[i]>=r0 and modbus_time[i]<(r0+60)):
		if(modbus_bytes[i]!='-'):
			pkt = pkt + int(modbus_bytes[i])
	elif(modbus_time[i]>=(r0+60)):
		r0 = r0 + 60
		if(modbus_bytes[i]!='-'):
			pkt = pkt + int(modbus_bytes[i])
		modbus_pkts_per_min.append(pkt)
		pkt = 0

modbus_ppm_file = open('../modbus_ppm.txt', 'w')
for i in range(0,len(modbus_pkts_per_min)):
	modbus_ppm_file.write(str(i) + "," + str(modbus_pkts_per_min[i]) + "\n")
modbus_ppm_file.close()

pkts_per_min = []
pkt = 0
r0 = time[0]
for i in range(0,len(conn_bytes)):
	print i
	if(time[i]>=r0 and time[i]<(r0+60)):
		if(conn_bytes[i]!='-'):
			pkt = pkt + int(conn_bytes[i])
	elif(time[i]>=(r0+60)):
		r0 = r0 + 60
		if(conn_bytes[i]!='-'):
			pkt = pkt + int(conn_bytes[i])
		pkts_per_min.append(pkt)
		pkt = 0

ppm_file = open('../conn_ppm.txt', 'w')
for i in range(0,len(pkts_per_min)):
	ppm_file.write(str(i) + "," + str(pkts_per_min[i]) + "\n")
ppm_file.close()

conns_per_min = []
conn = 0
r0 = time[0]
ip_n_set_chk = []
for i in range(0,len(ip)):
	print i
	if(time[i]>=r0 and time[i]<(r0+60)):
		if (ip[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(ip[i])
			conn = conn + 1
	elif(time[i]>=(r0+60)):
		r0 = r0 + 60
		if (ip[i] in ip_n_set_chk) == False:
			ip_n_set_chk.append(ip[i])
			conn = conn + 1
		conns_per_min.append(conn)
		conn = 0

cpm_file = open('../conn_cpm.csv', 'w')
for i in range(0,len(conns_per_min)):
	cpm_file.write(str(i) + "," + str(conns_per_min[i]) + "\n")
cpm_file.close()

modbus_conns_per_min = []
modbus_conn = 0
r0 = modbus_time[0]
modbus_ip_n_set_chk = []
for i in range(0,len(modbus_ip)):
	print i
	if(modbus_time[i]>=r0 and modbus_time[i]<(r0+60)):
		if (modbus_ip[i] in modbus_ip_n_set_chk) == False:
			modbus_ip_n_set_chk.append(modbus_ip[i])
			modbus_conn = modbus_conn + 1
	elif(modbus_time[i]>=(r0+60)):
		r0 = r0 + 60
		if (modbus_ip[i] in modbus_ip_n_set_chk) == False:
			modbus_ip_n_set_chk.append(modbus_ip[i])
			modbus_conn = modbus_conn + 1
		modbus_conns_per_min.append(modbus_conn)
		modbus_conn = 0

modbus_cpm_file = open('../modbus_cpm.csv', 'w')
for i in range(0,len(modbus_conns_per_min)):
	modbus_cpm_file.write(str(i) + "," + str(modbus_conns_per_min[i]) + "\n")
modbus_cpm_file.close()


ip_per_min = []
conn = 0
r0 = time[0]
ip_set_chk = []
for i in range(0,len(src_ip)):
	print i
	if(time[i]>=r0 and time[i]<(r0+60)):
		if (src_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(src_ip[i])
			conn = conn + 1
		elif  (dst_ip[i] in ip_set_chk) == False :
			ip_set_chk.append(dst_ip[i])
			conn = conn + 1
	elif(time[i]>=(r0+60)):
		r0 = r0 + 60
		if (src_ip[i] in ip_set_chk) == False:
			ip_set_chk.append(src_ip[i])
			conn = conn + 1
		elif  (dst_ip[i] in ip_set_chk) == False :
			ip_set_chk.append(dst_ip[i])
			conn = conn + 1
		ip_per_min.append(conn)
		conn = 0

cpm_file = open('../ip_cpm.csv', 'w')
for i in range(0,len(ip_per_min)):
	cpm_file.write(str(i) + "," + str(ip_per_min[i]) + "\n")
cpm_file.close()

modbus_ip_per_min = []
modbus_conn = 0
r0 = modbus_time[0]
modbus_ip_set_chk = []
for i in range(0,len(modbus_src_ip)):
	print i
	if(modbus_time[i]>=r0 and modbus_time[i]<(r0+60)):
		if (modbus_src_ip[i] in modbus_ip_set_chk) == False:
			modbus_ip_set_chk.append(modbus_src_ip[i])
			modbus_conn = modbus_conn + 1
		elif (modbus_dst_ip[i] in modbus_ip_set_chk) == False:
			modbus_ip_set_chk.append(modbus_dst_ip[i])
			modbus_conn = modbus_conn + 1
	elif(modbus_time[i]>=(r0+60)):
		r0 = r0 + 60
		if (modbus_src_ip[i] in modbus_ip_set_chk) == False:
			modbus_ip_set_chk.append(modbus_src_ip[i])
			modbus_conn = modbus_conn + 1
		elif (modbus_dst_ip[i] in modbus_ip_set_chk) == False:
			modbus_ip_set_chk.append(modbus_dst_ip[i])
			modbus_conn = modbus_conn + 1
		modbus_ip_per_min.append(modbus_conn)
		modbus_conn = 0

modbus_cpm_file = open('../modbus_ip_cpm.csv', 'w')
for i in range(0,len(modbus_ip_per_min)):
	modbus_cpm_file.write(str(i) + "," + str(modbus_ip_per_min[i]) + "\n")
modbus_cpm_file.close()