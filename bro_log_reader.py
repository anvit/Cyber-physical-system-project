import json
import csv
from collections import Counter
import numpy as np
import MySQLdb

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
js = [ {} ]
diff_host = []
resp_bytes = []
src_host43 = []
dst_host43 = []
ctr = 0
time = []
# conn = MySQLdb.connect(user="root",passwd="",db="test",unix_socket="/opt/lampp/var/mysql/mysql.sock")
# x = conn.cursor()
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
				# try:
				# 	add_salary = ()
				# 	x.execute("""INSERT INTO connection (time, src_ip, src_p, dest_ip, dest_p, protocol, duration, orig_bytes, resp_bytes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (row[0],row[2],row[3],row[4],row[5],row[6],row[8],row[9],row[10] ))
				# 	conn.commit()
				# except:
				# 	conn.rollback()
				js[0][ctr]= { "time" : row[0], "src_ip" : row[2], "dst_ip" : row[4], "protocol" : row[6], "duration" : row[8], "orig_bytes" : row[9], "resp_bytes" : row[10] }
				ctr = ctr + 1
				src_dst_split.append(row[2]+":"+row[4])
				if(row[2]=='172.16.2.34'):
					select_src_ip.append(row[4])
				elif(row[4]=='172.16.2.34'):
					select_dst_ip.append(row[2])
				elif(row[2]=='172.16.2.43'):
					src_host43.append(row[4])
				elif(row[4]=='172.16.2.43'):
					dst_host43.append(row[2])
				else:
					diff_host.append(row[2]+"*"+row[4])

	if j%14 == 0 :
		count_each.append(Counter(src_dst_split))
		del src_dst_split[:]

# conn.close()

count_freq = Counter(src_dst)
count_diff_freq = Counter(diff_host)

count_src_freq = Counter(select_src_ip)
count_dst_freq = Counter(select_dst_ip)

count_src43_freq = Counter(src_host43)
count_dst43_freq = Counter(dst_host43)

file = open("../data.json", "w")
temp = json.dumps(js, sort_keys=True, indent=1, separators=(',', ': '))
wr = temp[1:-1]
file.write(wr)
file.close()

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

connect_diff_file = open('../count_diff_freq.txt', 'w')
connect_diff_file.write(str(count_diff_freq))

src_freq_file = open('../count_src_freq.txt', 'w')
src_freq_file.write(str(count_src_freq))

dst_freq_file = open('../count_dst_freq.txt', 'w')
dst_freq_file.write(str(count_dst_freq))


src43_freq_file = open('../count_src43_freq.txt', 'w')
src43_freq_file.write(str(count_src43_freq))

dst43_freq_file = open('../count_dst43_freq.txt', 'w')
dst43_freq_file.write(str(count_dst43_freq))


for i in range(0,len(count_each)):
	connect_freq_file = open('../count_freq_split'+str(i)+'.txt', 'w')
	connect_freq_file.write(str(count_each[i]))

f = open('../dump.txt', 'w')
for i in range(0,len(ip_set)):
	for j in range(0,len(ip_set)):
		if con[i][j]!= '' :
			f.write('Src IP: ' + ip_set[i] + ', Dst IP: ' + ip_set[j] + ', Protocol: ' + str(con[i][j]) + "\n")

pkts_per_sec = []
pkt = 0
r0 = time[0]


for i in range(0,len(resp_bytes)):
	print i
	if(time[i]>=r0 and time[i]<(r0+1)):
		if(resp_bytes[i]!='-'):
			pkt = pkt + int(resp_bytes[i])
	elif(time[i]>=(r0+1)):
		r0 = r0 + 1
		if(resp_bytes[i]!='-'):
			pkt = pkt + int(resp_bytes[i])
		pkts_per_sec.append(pkt)
		pkt = 0

pkts_per_min = []
pkt = 0
r0 = time[0]
for i in range(0,len(resp_bytes)):
	print i
	if(time[i]>=r0 and time[i]<(r0+60)):
		if(resp_bytes[i]!='-'):
			pkt = pkt + int(resp_bytes[i])
	elif(time[i]>=(r0+60)):
		r0 = r0 + 60
		if(resp_bytes[i]!='-'):
			pkt = pkt + int(resp_bytes[i])
		pkts_per_min.append(pkt)
		pkt = 0


pps_file = open('../count_pps.txt', 'w')
for i in range(0,len(pkts_per_sec)):
	pps_file.write(str(i) + "," + str(pkts_per_sec[i]) + "\n")
pps_file.close()

ppm_file = open('../count_ppm.txt', 'w')
for i in range(0,len(pkts_per_min)):
	ppm_file.write(str(i) + "," + str(pkts_per_min[i]) + "\n")
ppm_file.close()