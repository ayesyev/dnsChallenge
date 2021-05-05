from scapy.all import *
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP


dns_packets = rdpcap('resources/htpasswd_export.pcap')
for packet in dns_packets:
    # & packet[IP].src == '192.168.122.76' & packet[DNSQR].qtype == 17
    try:
        if packet.haslayer(DNSQR) \
                and packet[IP].src == '192.168.122.76' \
                and packet[IP].dst == '192.168.100.2' \
                and packet[DNSQR].qtype == 16:
            qname = packet[DNSQR].qname
            #get rid of domain suffix
            qname = qname[:len(qname)-14]

            #get rid of dots

    except IndexError:
        print(packet.show())
        continue
