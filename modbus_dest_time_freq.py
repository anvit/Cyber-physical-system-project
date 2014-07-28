#! /usr/bin/python

#based on modbus_log_json.py 

import json
import csv
from collections import Counter

# class for each destination ip in the modbus file that will count each interval using secs
class DestIP:
	def __init__(self, addr, first_occurrence):
		self.addr = addr
		self.last_occur = first_occurrence
		self.first_occur = first_occurrence

		self.interval_count = []
		self.interval_count.append([])
		self.interval_count.append([])

	def new_occur(self, occurrence):
		interval = occurrence - self.last_occur
		self.last_occur = occurrence

		if(self.interval_count[0].count(interval) == 0):
			self.interval_count[0].append(interval)
			self.interval_count[1].append(1)
		else:
			self.interval_count[1][self.interval_count[0].index(interval)] += 1

	# debug function
	def print_intervals(self):
		print self.addr
		for x in xrange(0,len(self.interval_count)):
			print self.interval_count[x]

def find_by_addr(someArray, addr):
	for x in someArray:
		if x.addr == addr:
			return someArray.index(x)
	return -1


js = [ {} ]
ip_addrs = []

for j in range(0,1):
	addr = '/media/227A4A207A49F159/TRA-Data+Logs/Large-Logs/pcap'+str(j)+'/modbus.log'
	num_lines = sum(1 for line in open(addr))
	i = 0
	print j
	with open(addr, 'r') as csvfile:
		spamreader = csv.reader(csvfile, delimiter='	')
		for row in spamreader:
			i = i + 1
			if row[0][0]!="#" and i<(num_lines):
				dest_ip = row[4]
				time = row[0]
				index = find_by_addr(ip_addrs, dest_ip)

				if index < 0:
					ip_addrs.append(DestIP(dest_ip, int(float(time))))
				else:
					ip_addrs[index].new_occur(int(float(time)))

count = 0
for x in ip_addrs:
	js[0][count]= { "addr" : x.addr, "first_occur" : x.first_occur,"last_occur" : x.last_occur, "time_freq" : x.interval_count}
	count += 1

file = open("./modbus_data.json", "w")
temp = json.dumps(js, sort_keys=True, indent=1, separators=(',', ': '))
wr = temp[1:-1]
file.write(wr)
file.close()
