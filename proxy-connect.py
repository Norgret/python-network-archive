from scapy.all import *
import threading
import random
import time
import sys
import os

# 78.88.229.104:4145
# 80.50.141.118:40340
# 92.42.8.21:4145
#
# 	c854 4b75 0e39 aabb ccdd eeff 0800 4500  .TKu.9........E.
# 	003d 0000 4000 4006 158a c0a8 004a 5c2a  .=..@.@......J\*
# 	0815 e9cc 1031 8d76 05c3 f5c8 3d72 8018  .....1.v....=r..
# 	0816 bd58 0000 0101 080a 46fc eed8 1a33  ...X......F....3
# 	4bec 0401 0050 b03a 7b19 00              K....P.:{..
#		 0401 0050 b03a 7b19 00
# 		   ^ 0x04: SOCKS4 version
# 		   ^ 0x01: CMD (establish stream)
# 			   ^ 0x0050: dst port (2 bytes, port 80)
# 					   ^ 0xb03a7b19: dst IP
# 							   ^ 0x00: null byte; null-terminated
#


class Socks4Connect(Packet):
	name = "Socks 4 Establish Connection"
	fields_desc = [XByteField("version", 4),
		XByteField("cmd", 1),
		ShortField("dport", None),
		DestIPField("host", None),
		XByteField("terminator", 0x00)]

# pkt = IP(dst=proxy.ip)/TCP(sport=random.randint(1024, 65535), dport=proxy.port)/Socks4Connect(cmd=1, dport=proxy.port, host='11.22.33.44')

# pkt.show2()
# print(hexdump(pkt))


class TCP_socket():

	def __init__(self, iface, host, port, timeout=0.5, verbose=False):
		self.iface = iface
		self.host = host
		self.sport = random.randint(1024, 65535)
		self.dport = port
		self.timeout = timeout
		self.IP = IP(dst=self.host)
		self.verbose = verbose
		self.sock = AsyncSniffer(iface=self.iface, filter="src %s" % self.host, prn=self.sock_controller)	# captures replies from host
		self.last_pkt_received = None	# used by sock_controller()

	# basic IO
	# log():		status updates/errors
	# pkt_out():	sent packet
	# pkt_in():		received packet
	# timestamp: ('%f' % time.time())[7:]
	def log(self, message="error"):
		print("[ TCP_socket: %s ]" % (message))
	def pkt_out(self, message):
		if self.verbose:
			print("%s -> %s\t%s" % ("local", self.host, message))
	def pkt_in(self, message):
		if self.verbose:
			print("%s <- %s\t%s" % ("local", self.host, message))

	def syn(self):
		return self.IP/TCP(sport=self.sport, dport=self.dport, flags='S', options=[('MSS', 1460), ('NOP', None), ('WScale', 6), ('NOP', None), ('NOP', None), ('Timestamp', (1236684959, 0)), ('SAckOK', ''), ('EOL', None)])

	def ack(self, pkt=None, flags='A'):
		if not pkt:
			pkt = self.last_pkt_received
		return self.IP/TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, seq=pkt[TCP].ack, ack=pkt[TCP].seq + 1, flags=flags)

	def psh(self, pkt=None, flags='PA'):
		if not pkt:
			pkt = self.last_pkt_received
		return self.ack(pkt, flags=flags)

	def fin(self, pkt=None, flags='FA'):
		if not pkt:
			pkt = self.last_pkt_received
		return self.ack(pkt, flags=flags)

	# returns a packet with matching flags
	def listen(self, flags):
		def pkt_handler(pkt):
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == flags:
					pkt.show()
					pkt.command()
					# return pkt
					exit()
		sniffer = AsyncSniffer(iface=self.iface, filter='src %s' % self.host, prn=pkt_handler)
		sniffer.start()

	# send commands to host
	def send_payload(self, payload):
		self.pkt_out("PSH-ACK")
		psh_reply = sr1(self.psh()/payload, timeout=self.timeout, verbose=0)
		while not psh_reply:
			self.log("PSH timed out, expected ACK")
			self.pkt_out("PSH-ACK")
			psh_reply = sr1(self.psh()/payload, timeout=self.timeout, verbose=0)


	# controls connection
	# acks packets, terminates connection if FIN is received
	# provides verbose output regarding host replies
	def sock_controller(self, pkt):

		if pkt.haslayer(TCP):
			self.last_pkt_received = pkt
			flags = []
			for flag in pkt[TCP].flags:
				if flag == 'S':
					flags.append('SYN')
				elif flag == 'P':
					flags.append('PSH')
					send(self.ack(), verbose=0)
					self.pkt_out('ACK')
				elif flag == 'F':
					flags.append('FIN')
				elif flag == 'R':
					flags.append('RST')
				elif flag == 'A':
					flags.append('ACK')
				else:
					flags.append('[%s]' % flag)

			# generates verbose output
			flags = '-'.join(flags)
			self.pkt_in(flags)

			# terminates connection if FIN was received
			if 'F' in pkt[TCP].flags:
				self.pkt_out('ACK')
				send(self.ack(), verbose=0)
				self.log("connection terminated")
				# self.terminate(received_fin=True)
				exit()
			elif 'R' in pkt[TCP].flags:
				# send(self.ack(), verbose=0)
				self.log("connection reset by host")
				os._exit(1)
				# return 0
				# raise SystemExit


	# initiates TCP handshake, starts listener
	def connect(self):
		self.sock.start()

		self.log("establishing a connection...")
		self.pkt_out("SYN")
		synack = sr1(self.syn(), timeout=self.timeout, verbose=0)
		while not synack:
			self.log("SYN timed out, expected SYN-ACK")
			self.pkt_out('SYN')
			synack = sr1(self.syn(), timeout=self.timeout, verbose=0)

		ack = self.ack(synack)
		send(ack, verbose=0)
		self.pkt_out('ACK')
		self.log("handshake complete")

	# closes socket
	def terminate(self, received_fin=False):
		send(self.fin(), verbose=0)
		self.sock.join()
		exit()

# 213.96.240.156:4145
# 92.42.8.21:4145
# 37.195.209.169:4153
class Proxy:
	def __init__(self):
		self.ip = '37.195.209.169'
		self.port = 4153
proxy = Proxy()


iface = 'en0'
port = 80
dst = '176.58.123.25'	# ident.me


def main():
	sock = TCP_socket(iface=iface, host=proxy.ip, port=port, verbose=1)
	active = sock.connect()
	# if active:
	# sock.send_payload(Socks4Connect(cmd=1, dport=port, host=dst))
	# sock.listen(flags='PA')
	# sock.send_payload("GET / HTTP/1.1\r\nHost: ident.me\r\n\r\n")
	# time.sleep(1)
	sock.terminate()


try:
	main()
except KeyboardInterrupt:
	print("\n")
	os._exit(1)

exit()
