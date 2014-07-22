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
				src_dst.append(row[2]+":"+row[4])
				src_dst_split.append(row[2]+":"+row[4])
				if(row[2]=='172.16.2.34'):
					select_src_ip.append(row[4])
				elif(row[4]=='172.16.2.34'):
					select_dst_ip.append(row[2])
	if j%14 == 0 :
		count_each.append(Counter(src_dst_split))
		del src_dst_split[:]

count_freq = Counter(src_dst)

count_src_freq = Counter(select_src_ip)
count_dst_freq = Counter(select_dst_ip)

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

ip_list_file = open('../ips.txt', 'w')
ip_list_file.write(str(sorted(ip_set)))

connect_freq_file = open('../count_freq.txt', 'w')
connect_freq_file.write(str(count_freq))

src_freq_file = open('../count_src_freq.txt', 'w')
src_freq_file.write(str(count_src_freq))

dst_freq_file = open('../count_dst_freq.txt', 'w')
dst_freq_file.write(str(count_dst_freq))


for i in range(0,len(count_each)):
	connect_freq_file = open('../count_freq_split'+str(i)+'.txt', 'w')
	connect_freq_file.write(str(count_each[i]))

f = open('../dump.txt', 'w')
for i in range(0,len(ip_set)):
	for j in range(0,len(ip_set)):
		if con[i][j]!= '' :
			f.write('Src IP: ' + ip_set[i] + ', Dst IP: ' + ip_set[j] + ', Protocol: ' + str(con[i][j]) + "\n")
