import csv

src_ip = []
src_p = []
dst_ip = []
dst_p = []
proto = []

f = open('../dump.txt', 'w')
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
				src_p.append(row[3])
				dst_ip.append(row[4])
				dst_p.append(row[5])
				proto.append(row[6])

f.write(str(src_ip))