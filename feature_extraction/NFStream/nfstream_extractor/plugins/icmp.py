from nfstream import NFPlugin
from scapy.all import IP, IPv6
from scapy.all import ICMP, ICMPv6EchoRequest, ICMPv6EchoReply
from collections import Counter

class AuxICMPFeatures(NFPlugin):
    """
    AuxICMPFeatures(NFPlugin)
    Description:
        This plugin extracts features from ICMP flows.

    Attributes:
        Inherits attributes from NFPlugin.
        flow.udps.icmp_type: Mode of ICMP types
        flow.udps.icmp_type_uq: Number of unique ICMP types
        flow.udps.icmp_type_count: Total count of ICMP types
        flow.udps.icmp_type_sum: Sum of ICMP types
        flow.udps.icmp_v4_type: Mode of ICMPv4 types
        flow.udps.icmp_v4_type_uq: Number of unique ICMPv4 types
        flow.udps.icmp_v4_type_count: Total count of ICMPv4 types
        flow.udps.icmp_v4_type_sum: Sum of ICMPv4 types
        flow.udps.icmp_code: Mode of ICMP codes
        flow.udps.icmp_code_uq: Number of unique ICMP codes
        flow.udps.icmp_code_count: Total count of ICMP codes
        flow.udps.icmp_code_sum: Sum of ICMP codes

    Methods:
        __get_mode_and_unique_values(self, lst): Helper method to calculate mode and number of unique values in a list
        on_init(self, packet, flow): Method called at flow creation to initialize ICMP flow features.
        on_update(self, packet, flow): Method called to update ICMP flow features.
        on_expire(self, flow): Method called when ICMP flow expires to finalize ICMP flow features.
    """
    def __get_mode_and_unique_values(self, lst):
        num_strings = len(lst)

        if num_strings == 0:
            return 0, 0, 0 
        # Count the occurrences of each element in the list
        counts = Counter(lst)

        # Find the mode(s) (most common element(s))
        mode = counts.most_common(1)[0][0]

        # Find the number of unique values
        num_unique = len(counts)

        return mode, num_unique, num_strings
    
    def on_init(self, packet, flow):
        flow.udps.icmp_type = []
        flow.udps.icmp_type_uq = 0
        flow.udps.icmp_type_count = 0
        flow.udps.icmp_type_sum = 0
        flow.udps.icmp_v4_type = []
        flow.udps.icmp_v4_type_uq = 0
        flow.udps.icmp_v4_type_count = 0
        flow.udps.icmp_v4_type_sum = 0
        flow.udps.icmp_code = []
        flow.udps.icmp_code_uq = 0
        flow.udps.icmp_code_count = 0
        flow.udps.icmp_code_sum = 0
        
        if packet.ip_version == 4:
            s_packet = IP(packet.ip_packet)
            if s_packet.haslayer(ICMP):
                icmp_packet = s_packet[ICMP]
                flow.udps.icmp_type.append(icmp_packet.type)
                flow.udps.icmp_v4_type.append(icmp_packet.type * 256 + icmp_packet.type)
                flow.udps.icmp_code.append(icmp_packet.code)
                
        elif packet.ip_version == 6:
            s_packet = IPv6(packet.ip_packet)
            if s_packet.haslayer(ICMPv6EchoRequest):
                icmp_packet = s_packet[ICMPv6EchoRequest]
                flow.udps.icmp_type.append(icmp_packet.type)
                flow.udps.icmp_v4_type.append(icmp_packet.type * 256 + icmp_packet.type)
                flow.udps.icmp_code.append(icmp_packet.code)
                
            elif s_packet.haslayer(ICMPv6EchoReply):
                icmp_packet = s_packet[ICMPv6EchoReply]
                flow.udps.icmp_type.append(icmp_packet.type)
                flow.udps.icmp_v4_type.append(icmp_packet.type * 256 + icmp_packet.type)
                flow.udps.icmp_code.append(icmp_packet.code)
            else:
                pass

    def on_update(self, packet, flow):
        if packet.ip_version == 4:
            s_packet = IP(packet.ip_packet)
            if s_packet.haslayer(ICMP):
                icmp_packet = s_packet[ICMP]
                flow.udps.icmp_type.append(icmp_packet.type)
                flow.udps.icmp_v4_type.append(icmp_packet.type * 256 + icmp_packet.type)
                flow.udps.icmp_code.append(icmp_packet.code)
                
        elif packet.ip_version == 6:
            s_packet = IPv6(packet.ip_packet)
            if s_packet.haslayer(ICMPv6EchoRequest):
                icmp_packet = s_packet[ICMPv6EchoRequest]
                flow.udps.icmp_type.append(icmp_packet.type)
                flow.udps.icmp_v4_type.append(icmp_packet.type * 256 + icmp_packet.type)
                flow.udps.icmp_code.append(icmp_packet.code)
                
            elif s_packet.haslayer(ICMPv6EchoReply):
                icmp_packet = s_packet[ICMPv6EchoReply]
                flow.udps.icmp_type.append(icmp_packet.type)
                flow.udps.icmp_v4_type.append(icmp_packet.type * 256 + icmp_packet.type)
                flow.udps.icmp_code.append(icmp_packet.code)
            else:
                pass
    def on_expire(self, flow):
        if len(flow.udps.icmp_type):
            mode, num_unique, num_strings = self.__get_mode_and_unique_values(flow.udps.icmp_type)
            flow.udps.icmp_type_sum = sum(flow.udps.icmp_type)
            flow.udps.icmp_type = mode
            flow.udps.icmp_type_uq = num_unique
            flow.udps.icmp_type_count = num_strings
        else:
            flow.udps.icmp_type = 0
        
        if len(flow.udps.icmp_v4_type) > 0:
            mode, num_unique, num_strings = self.__get_mode_and_unique_values(flow.udps.icmp_v4_type)
            flow.udps.icmp_v4_type_sum = sum(flow.udps.icmp_v4_type)
            flow.udps.icmp_v4_type = mode
            flow.udps.icmp_v4_type_uq = num_unique
            flow.udps.icmp_v4_type_count = num_strings
        else:
            flow.udps.icmp_v4_type = 0
            
        if len(flow.udps.icmp_code) > 0:
            mode, num_unique, num_strings = self.__get_mode_and_unique_values(flow.udps.icmp_code)
            flow.udps.icmp_code_sum = sum(flow.udps.icmp_code)
            flow.udps.icmp_code = mode
            flow.udps.icmp_code_uq = num_unique
            flow.udps.icmp_code_count = num_strings
            
        else:
            flow.udps.icmp_code = 0
        