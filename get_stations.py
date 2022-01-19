from scapy.all import *
import time
import os

iface = 'en0'
bssid = '14:35:8b:1a:e7:f1'
#bssid = '20:25:64:f8:52:c8'

print
print
lines = [['', None], ['', None], ["   {:<18}   {:<18} {:>7}".format("bssid", "station", "count"), None]]
#count = [None, None]

sensitivity = 10

addr = []

os.system("clear")

def handle(pkt):
	try:

		if (pkt.addr1 or pkt.addr2) == bssid:

			if pkt.addr2 and pkt.addr2 != bssid and not pkt.addr2 in addr:
				addr.append(pkt.addr2)

				lines.append(["{:>20} {:>20}".format(bssid, pkt.addr2), 1])


			elif pkt.addr2 in addr:
				lines[addr.index(pkt.addr2)][1] += 1

				for i in range(0, len(lines) - 1):
					if lines[i][1] > sensitivity or lines[i][1] == None:
						print("\033[F\033[K"),

				print("")
				print(lines[2][0])

				for i in range(0, len(lines)):
					if lines[i][1] > sensitivity:
						print(lines[i][0] + "{:>9}".format(lines[i][1]))

	except:
		pass

def main():
	s = sniff(iface = iface,
		monitor = True,
		count = 0,
		prn = handle)

try:
	main()
except KeyboardInterrupt:
	print
	exit()

exit()
