from scapy.all import IP, send, IPv6, ICMPv6EchoRequest
import igmp

while True:
    igmp_pkt = IP(dst="224.0.0.1") / igmp.IGMP()
    send(igmp_pkt)
    ipv6_packet = IPv6(dst="2001:0db8:85a3:0000:0000:8a2e:0370:7334") / ICMPv6EchoRequest()
    send(ipv6_packet)
