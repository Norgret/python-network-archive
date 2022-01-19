
# arp.py
# ARP structure:
#	DST MAC | SRC MAC
#	type ARP (0x0806000108000604) | op (0x0001)
#	SRC MAC | SRC IP
#	DST MAC | DST IP
#
# My MAC			:	a0:99:9b:09:94:31
# Home router MAC	:


programName = "arp.py"

import os

# IO class (writes to console)
class IOSocket:
	def out(self, string = "", persistant = True):
		if persistant:
			print("\033[2K\r" + "  [" + str(programName) + "]  " + str(string))
		elif not persistant:
			os.system('printf "\033[2K\r' + '  [' + str(programName) + ']  ' + str(string) + '"')
	def err(self, string = "", fatal = False):
		if not fatal:
			self.out("[err]  " + str(string))
		else:
			self.out("[fatal err]  " + str(string))
			exit()

ln = IOSocket()

def usage(err = True):
	os.system('printf \033[2K\r')
	if err:
		ln.err("unrecognized params")
	print("  usage: arptool <type> <dst IPv4> [-Sadhisv] [--decoys]")
	print("   type: query/whois, reply/is-at")
	print("   -S: src IPv4")
	print("   -d: dst MAC")
	print("   -s: src MAC")
	print("   -i: interval (milliseconds)")
	print("   -v: verbosity level (int)")
	print("   --help / -h: display this text")
	print("   --decoy <IPv4, MAC>: use decoy IP or MAC addresses")
	print("      ~ mac<MAC> : denotes MAC address")
	print("      ~ ip<IPv4> : denotes IP4 address")
	print("   examples:")
	print("      > arptool who-has 10.0.0.1-254 -S 10.0.0.2 -d ff:ff:ff:ff:ff:ff -s 22:22:22:22:22:22")
	print("      > arptool is-at 10.0.0.255 -S 10.0.0.1 -d ff:ff:ff:ff:ff:ff -s 33:33:33:33:33:33")
	exit()

# imports stuff
ln.out("Importing libraries...", False)
from scapy.all import * # sendp, srp, Ether, ARP
from threading import Thread
from time import sleep
from re import match, search
ln.out("Done", False)

def main():

	# argument handling
	decoys = [[]]					# stores decoy(s) [IPv4, MAC]
	verbose = True
	random = False
	loop = False
	interval = 0					# interval in ms
	scan_order = 1					# 0: scans starting from first byte (X.x.x.x) <-
									# 1: scans starting from last byte  (x.x.x.X) ->
	arp_type = None					# whois or is-at
	ip_range = [[], [], [], []]		# stores IP destination range - only type

	# tests is user entered -h flag
	if sys.argv[1] == '-h' or sys.argv[1] == '--help':
		usage(err = False)

	# tests if user specified at least 2 arguments (<type> <dest IP>)
	if len(sys.argv) < 3:
		usage(err = True)

	arp_type = sys.argv[1]
#	if arp_type == "whois":
#
#	elif arp_type == "is-at":

	# handles IP address
	ip = sys.argv[2]
	if re.match('^([0-9]{1,3}(\-[0-9]{1,3})?\.){3}[0-9]{1,3}(\-[0-9]{1,3})?$', ip):

#		if re.match('^.+\-.+$', ip):

		if re.match('^.+([0-9]{1,3}\-[0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){3}$', ip):
			min = re.search('([0-9]{1,3})\-([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){3}$', ip).group(1)
			max = re.search('([0-9]{1,3})\-([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){3}$', ip).group(2)
			ip_range[0] = [int(min), int(max)]
		else:
			val = re.search('([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){3}$', ip).group(1)
			ip_range[0] = [int(val)]

		if re.match('^.+([0-9]{1,3}\-[0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){2}$', ip):
			min = re.search('([0-9]{1,3})\-([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){2}$', ip).group(1)
			max = re.search('([0-9]{1,3})\-([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){2}$', ip).group(2)
			ip_range[1] = [int(min), int(max)]
		else:
			val = re.search('([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){2}$', ip).group(1)
			ip_range[1] = [int(val)]

		if re.match('^.+([0-9]{1,3}\-[0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?){1}$', ip):
			min = re.search('([0-9]{1,3})\-([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?)$', ip).group(1)
			max = re.search('([0-9]{1,3})\-([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?)$', ip).group(2)
			ip_range[2] = [int(min), int(max)]
		else:
			val = re.search('([0-9]{1,3})(\.[0-9]{1,3}(\-[0-9]{1,3})?)$', ip).group(1)
			ip_range[2] = [int(val)]

		if re.match('^.+([0-9]{1,3}\-[0-9]{1,3})$', ip):
			min = re.search('([0-9]{1,3})\-([0-9]{1,3})$', ip).group(1)
			max = re.search('([0-9]{1,3})\-([0-9]{1,3})$', ip).group(2)
			ip_range[3] = [int(min), int(max)]
		else:
			val = re.search('([0-9]{1,3})$', ip).group(1)
			ip_range[3] = [int(val)]

#		else:
#			pass

		for i in range(1, len(sys.argv)):
			arg = sys.argv[i]
			if arg == '-v' or arg == '--verbose':
				if sys.argv[i + 1] == '0':
					verbose = False
				elif sys.argv[i + 1] == '1':
					verbose = True
				else:
					ln.err('-v flag accepts boolean value')

	targets = []

	# crafts packet
	class Packet:
		def __init__(self, dst_mac, src_mac, dst_ip, src_ip, iface = 'en0'):
			self.dst_mac = dst_mac
			self.src_mac = src_mac
			self.dst_ip = dst_ip
			self.src_ip = src_ip
			self.iface = iface
		def getPacket(self):
			pkt = Ether(dst = self.dst_mac, src = self.src_mac) / ARP(hwsrc = self.src_mac, psrc = self.src_ip, hwdst = self.dst_mac, pdst = self.dst_ip)
			return pkt
		def send(self, verbose = True):
			pkt = self.getPacket()
			sendp(pkt, iface = self.iface, verbose = False)
			if verbose:
				ln.out("Sent ARP request to " + str(self.dst_ip) + " from " + str(self.src_ip), False)


	# sends packet

#	try:
	pkt = Packet('ff:ff:ff:ff:ff:ff', 'a0:99:9b:09:94:31', '', '192.168.8.182', 'en0')

	# loop through ip_range ranges
	ranges = [None] * 4

	for i in range(0, len(ip_range)):
		if len(ip_range[i]) == 2:
			ranges[i] = range(ip_range[i][0], ip_range[i][1] + 1)
		else:
			ranges[i] = range(ip_range[i][0], ip_range[i][0] + 1)

	for i in ranges[0]:
		for j in ranges[1]:
			for k in ranges[2]:
				for l in ranges[3]:
					if scan_order == 0:
						pkt.dst_ip = '%d.%d.%d.%d' % (l, k, j, i)
					elif scan_order == 1:
						pkt.dst_ip = '%d.%d.%d.%d' % (i, j, k, l)
					pkt.send()
#	except:
#		ln.out("Error")
#		exit()

	ln.out("Done")


if __name__ == "__main__":
	try:
		main()
		exit()
	except KeyboardInterrupt:
		ln.err("Cancelled")
		exit()
