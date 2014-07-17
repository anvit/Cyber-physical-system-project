import csv
import numpy as np

src_ip = []
src_p = []
dst_ip = []
dst_p = []
proto = []
ip = []
duration = []

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
				duration.append(row[8])

ip_set = list(set(ip))
con = np.empty((len(ip_set), len(ip_set)), dtype=object)
for k in range(0,len(ip_set)):
	for j in range(0,len(ip_set)):
		con[k][j] = ''
for i in range(0,len(src_ip)):
	if con[ip_set.index(src_ip[i])][ip_set.index(dst_ip[i])] == '' :
		test = []
		test.append(proto[i])
		con[ip_set.index(src_ip[i])][ip_set.index(dst_ip[i])] = test
	else:	
		test = []
		test = con[ip_set.index(src_ip[i])][ip_set.index(dst_ip[i])]
		test.append(proto[i])
		newtest = list(set(test))
		con[ip_set.index(src_ip[i])][ip_set.index(dst_ip[i])] =  newtest

f = open('../dump.txt', 'w')
for i in range(0,len(ip_set)):
	for j in range(0,len(ip_set)):
		if con[i][j]!= '' :
			f.write('Src IP: ' + ip_set[i] + ', Dst IP: ' + ip_set[j] + ', Protocol: ' + str(con[i][j]) + "\n")