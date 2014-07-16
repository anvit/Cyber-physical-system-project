from scapy.all import *
import numpy as np

ip = []
src = []
dst= []


pc = rdpcap("/run/media/anvit/Media/IR-sra/network data/selected.pcap")
for x in range(0, len(pc)):
	ip.append(pc[x].src)
	src.append(pc[x].src)
	ip.append(pc[x].dst)
	dst.append(pc[x].dst)

# for x in range(0, len(pc)):
# 	try:
# 		ip.append(pc[x]["IP"].src)
# 		src.append(pc[x]["IP"].src)
# 		ip.append(pc[x]["IP"].dst)
# 		dst.append(pc[x]["IP"].dst)
# 	except IndexError:
# 		print "Layer IP not found at :"+str(x) 
src_set = list(set(src))
dest_set = list(set(dst))
ip_set = list(set(ip))
print (src_set)
print (len(ip_set))
con = np.zeros((len(pc),len(ip_set),len(ip_set)))

for i in range(0,len(pc)):
	for j in range(0,len(ip_set)):
		for k in range(0,len(ip_set)):
			con[0][ip_set.index(pc[0].src)][ip_set.index(pc[0].dst)] = 1

	print con
# print i
