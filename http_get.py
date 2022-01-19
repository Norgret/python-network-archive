from scapy.all import *
import random

url = 'www.bbc.com'
port = 80
http_req = "GET / HTTP/1.1\r\nHost: www.bbc.com\r\n\r\n"


# DNS lookup
dnsqr = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=url, qtype='A'))

dnsrr = sr1(dnsqr, verbose=0)
del dnsqr
host_ip = dnsrr[DNS].an.rdata
print host_ip

# forge SYN
syn = IP(dst=host_ip)/TCP(sport=random.randint(1025, 65500), dport=port, flags='S')

# receive SYNACK
synack = sr1(syn, verbose=0)

# forge ACK
ack = IP(dst=host_ip)/TCP(sport=synack[TCP].dport, dport=port,
	seq=synack[TCP].ack, ack=synack[TCP].seq + 1, flags='P''A')


#
# send request
#

def handle_packet(pkt):
	pkt.show()

send(ack/http_req)
sniff(iface='en0', filter='host %s' % host_ip, prn=handle_packet)








# IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='google.com', qtype='A'))

