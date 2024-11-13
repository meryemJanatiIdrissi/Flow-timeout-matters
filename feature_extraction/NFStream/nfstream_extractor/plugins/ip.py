from nfstream import NFPlugin
from scapy.all import  IP, IPv6

class AuxPktMinMaxSizeFeatures(NFPlugin):
    """
    This pluguin extracts IP packets flow features
    Attributes
    ----------
    flow.udps.min_ttl: %MIN_TTL  Min flow TTL
    flow.udps.max_ttl: %MAX_TTL  Max flow TTL
    flow.udps.min_ip_pkt_len: %MIN_IP_PKT_LEN Len of the smallest flow IP packet observed
    flow.udps.max_ip_pkt_len: %MAX_IP_PKT_LEN Len of the largest flow IP packet observed
    """

    def on_init(self, packet, flow):
        flow.udps.min_ttl = 100000
        flow.udps.max_ttl = -100000
        flow.udps.min_ip_pkt_len = 100000
        flow.udps.max_ip_pkt_len = -100000

        if packet.ip_version == 4:
            decoded_packet = IP(packet.ip_packet)
            lenght = decoded_packet.len
            try:
                ttl = decoded_packet.ttl
            except:
                ttl = 0

        elif packet.ip_version == 6:
            decoded_packet = IPv6(packet.ip_packet)
            lenght = decoded_packet.plen
            try:
                ttl = decoded_packet.ttl
            except:
                ttl = 0

        flow.udps.min_ip_pkt_len = lenght
        flow.udps.max_ip_pkt_len = lenght
        
        
        flow.udps.min_ttl = ttl
        flow.udps.max_ttl = ttl
        
            

    def on_update(self, packet, flow):
        
        if packet.ip_version == 4:
            decoded_packet = IP(packet.ip_packet)
            lenght = decoded_packet.len
            try:
                ttl = decoded_packet.ttl
            except:
                ttl = 0

        elif packet.ip_version == 6:
            decoded_packet = IPv6(packet.ip_packet)
            lenght = decoded_packet.plen
            try:
                ttl = decoded_packet.ttl
            except:
                ttl = 0
            
        if ttl < flow.udps.min_ttl:
            flow.udps.min_ttl = ttl
        elif ttl > flow.udps.max_ttl:
            flow.udps.max_ttl = ttl
        
        if lenght < flow.udps.min_ip_pkt_len:
            flow.udps.min_ip_pkt_len = lenght
        elif lenght > flow.udps.max_ip_pkt_len:
            flow.udps.max_ip_pkt_len = lenght