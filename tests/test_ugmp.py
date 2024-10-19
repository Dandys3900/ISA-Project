from scapy.all import IP, send
import igmp

while True:
    igmp_pkt = IP(dst="224.0.0.1")/igmp.IGMP()
    send(igmp_pkt)
