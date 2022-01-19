
programName = "forgeon.py"

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

ln.out("Importing libraries...", False)
from scapy.all import *
import time
import threading
ln.out("Initiating...", False)

# sets preset (SSID list)
preset = "custom"

ssids = ["Test1", "test2", "funny characters"]

rickroll = [
	"1  Never gonna give you up",
	"2  Never gonna let you down",
	"3  Never gonna run around",
	"4  and desert you",
	"5  Never gonna make you cry",
	"6  Never gonna say goodbye",
	"7  Never gonna tell a lie",
	"8  and hurt you",
	"9  We've known each other for so long",
	"9a  Your heart's been aching but",
	"9b  you're too shy to say it",
	"9c  Inside we both know what's",
	"9d been going on",
	"9e We know the game and we're",
	"9f gonna play it",
	"9g And if you ask me how I'm",
	"9h feeling",
	"9i Don't tell me you're too",
	"9j blind to see"
]

# SELECT PRESET
if preset == "rickroll":
	ssids = rickroll
elif preset == "custom":
	pass


iface = 'en0'
inter = 0.2048 / 1

class Beacon():

	def __init__(self, ssid = "ssid"):
		self.ssid = ssid
		self.bssid = 'a0:99:9b:09:94:31'
		self.dot11 = Dot11(
			type=0, subtype=8,
			addr1='ff:ff:ff:ff:ff:ff',
			addr2=str(self.bssid),
			addr3=str(self.bssid))
		self.beacon = Dot11Beacon(
			timestamp=int(round(time.time() * 1000)),
			cap='ESS') # cap='ESS+privacy' if private network
		self.essid = Dot11Elt(
			ID='SSID',
			info=self.ssid,
			len=len(self.ssid))
		self.rates = Dot11EltRates(
			rates=[130, 132, 139, 150, 2, 4, 11, 12, 18, 22, 24, 36], len = 12)
		# self.rsn = Dot11Elt(ID='RSNinfo', info=(
		# 	'\x01\x00'                 # RSN V1
		# 	'\x00\x0f\xac\x02'         # Group Cipher Suite
		# 	'\x02\x00'                 # 2 Pairwise Cipher Suites (next two lines)
		# 	'\x00\x0f\xac\x04'         # AES Cipher
		# 	'\x00\x0f\xac\x02'         # TKIP Cipher
		# 	'\x01\x00'                 # 1 Authentication Key Managment Suite (line below)
		# 	'\x00\x0f\xac\x02'         # Pre-Shared Key
		# 	'\x00\x00'))               # RSN Capabilities
		self.frame = RadioTap(ChannelFrequency=2412)/self.dot11/self.beacon/self.essid#/self.rsn

	def get(self):
		return self.frame

	def loop(self, inter = 0.1024, count = 0, iface = 'en0'):
		sendp(self.get(), iface = iface, monitor = True, inter = inter, loop = True, verbose = False)


# array of Beacon objects to be processed
frames = []
for ssid in ssids:
	frames.append(Beacon(ssid))

try:

	for i in range(0, len(frames)):
		frame = frames[i]
		t = threading.Thread(target = frame.loop, args = (inter, 0, 'en0'))	# 1 tu: 1024 uS
		t.daemon = True
		t.start()
		ln.out("Initiated frame [%d]" % i, False)

	print("")

	i = 0
	while 1:
		i += 1
		ln.out("Frames sent: %d" % (i * len(frames)), False)
		time.sleep(inter)

except (KeyboardInterrupt, SystemExit):
	print("")
	ln.out("Done")
	exit()

exit()

