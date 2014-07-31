#! /usr/bin/python

#based on modbus_log_json.py 

import json
import csv

# class for each source ip in the modbus file that will count each time it is used and other info
class conn:
	def __init__(self, source_ip, dest_ip, time):
		self.source_ip = source_ip
		self.dest_ip = dest_ip
		self.time = time
		
def find_by_addrs(someArray, source_ip, dest_ip):
	for x in someArray:
		if x.source_ip == source_ip and x.dest_ip == dest_ip:
			return someArray.index(x)
	return -1

conns = []
all_addrs = []
uids = []

for j in range(0,166):
	addr = '/media/227A4A207A49F159/TRA-Data+Logs/Large-Logs/pcap'+str(j)+'/modbus.log'
	num_lines = sum(1 for line in open(addr))
	i = 0
	print j
	with open(addr, 'r') as csvfile:
		spamreader = csv.reader(csvfile, delimiter='	')
		for row in spamreader:
			i += 1
			if row[0][0]!="#" and i<(num_lines):
				source_ip = row[2]
				dest_ip = row[4]
				uid = row[1]
				time = int(float(row[0]))
				index = find_by_addrs(conns, source_ip, dest_ip)

				if index < 0:
					conns.append(conn(source_ip, dest_ip, time))

				if all_addrs.count(source_ip) == 0:
					all_addrs.append(source_ip)
				
				if all_addrs.count(dest_ip) == 0:
					all_addrs.append(dest_ip)

				if uids.count(uid) == 0:
					uids.append(uid)


	print "Num of conns: " + str(len(conns))
	print "Num of addrs: " + str(len(all_addrs))
	print "Num of uids: " + str(len(uids))

modbus_edges = open('./modbus_edges.csv', 'w')
for i in range(0,len(conns)):
	if i == 0:
		modbus_edges.write("Source," +"Target," + "Type," + "Id," + "Time" + "\n")
	modbus_edges.write(conns[i].source_ip +"," + conns[i].dest_ip + ",Directed," + str(i) +"," + str(conns[i].time) + "\n")
modbus_edges.close()

modbus_nodes = open('./modbus_nodes.csv', 'w')
for i in range(0,len(all_addrs)):
	if i == 0:
		modbus_nodes.write("Nodes," +"Id," + "Label" + "\n")
	modbus_nodes.write(all_addrs[i] + "," + all_addrs[i] + "," + all_addrs[i] +"\n")
modbus_nodes.close()

modbus_uids = open('./modbus_uids.csv', 'w')
for i in range(0,len(uids)):
	modbus_uids.write(uids[i] + "\n")
modbus_uids.close()


