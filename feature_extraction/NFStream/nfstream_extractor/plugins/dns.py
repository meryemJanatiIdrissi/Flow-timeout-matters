from nfstream import NFPlugin
from scapy.all import IP, DNS, IPv6, DNSQR, LLMNRQuery, LLMNRResponse
from .pkts_utils.stats import IterableStats

import numpy as np
from collections import Counter

class AuxDNSFeatures(NFPlugin):
    """
    Auxiliary DNS Features Plugin
    This plugin extracts DNS flow features.

    Attributes:
        flow.udps.dns_query_id (int): DNS query transaction Id
        flow.udps.dns_query_type (list): DNS query types
        flow.udps.dns_query_type_uq (int): Number of unique DNS query types
        flow.udps.dns_query_type_count (int): Total number of DNS query types
        flow.udps.dns_query_aa (int): DNS query 'aa' flag count
        flow.udps.dns_query_tc (int): DNS query 'tc' flag count
        flow.udps.dns_query_rd (int): DNS query 'rd' flag count
        flow.udps.dns_query_ra (int): DNS query 'ra' flag count
        flow.udps.dns_query_z (int): DNS query 'z' flag count
        flow.udps.dns_query_ad (int): DNS query 'ad' flag count
        flow.udps.dns_query_cd (int): DNS query 'cd' flag count
        flow.udps.dns_query_rcode (int): DNS query 'rcode' count
        flow.udps.dns_query_qdcount (int): DNS query 'qdcount' count
        flow.udps.dns_query_ancount (int): DNS query 'ancount' count
        flow.udps.dns_query_nscount (int): DNS query 'nscount' count
        flow.udps.dns_query_arcount (int): DNS query 'arcount' count
        flow.udps.dns_query_names (set): Set of DNS query names
        flow.udps.dns_ttl_answer (list): TTL of the first A record (if any)
        flow.udps.dns_ttl_answer_max (int): Maximum TTL of A records
        flow.udps.dns_ttl_answer_min (int): Minimum TTL of A records
        flow.udps.dns_ttl_answer_mean (float): Mean TTL of A records
        flow.udps.dns_answer_len (list): Length of DNS answers
        flow.udps.dns_answer_len_max (int): Maximum length of DNS answers
        flow.udps.dns_answer_len_min (int): Minimum length of DNS answers
        flow.udps.dns_answer_len_mean (float): Mean length of DNS answers
        flow.udps.dns_answer_rrname (str): Resource record name of DNS answers
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
        flow.udps.dns_query_names = set()
        flow.udps.dns_query_id = 0
        flow.udps.dns_query_type = []
        flow.udps.dns_query_type_uq = 0
        flow.udps.dns_query_type_count = 0
        flow.udps.dns_query_aa = 0
        flow.udps.dns_query_tc = 0
        flow.udps.dns_query_rd = 0
        flow.udps.dns_query_ra = 0
        flow.udps.dns_query_z = 0
        flow.udps.dns_query_ad = 0
        flow.udps.dns_query_cd = 0
        flow.udps.dns_query_rcode = 0
        flow.udps.dns_query_qdcount = 0
        flow.udps.dns_query_ancount = 0
        flow.udps.dns_query_nscount = 0
        flow.udps.dns_query_arcount = 0
        flow.udps.dns_ttl_answer = []
        flow.udps.dns_ttl_answer_max = 0
        flow.udps.dns_ttl_answer_min = 0
        flow.udps.dns_ttl_answer_mean = 0
        flow.udps.dns_answer_len = []
        flow.udps.dns_answer_len_max = 0
        flow.udps.dns_answer_len_min = 0
        flow.udps.dns_answer_len_mean = 0
        flow.udps.dns_answer_rrname = 'unknown'
        
        if packet.ip_version == 4:
            s_packet = IP(packet.ip_packet)
        elif packet.ip_version == 6:
            s_packet = IPv6(packet.ip_packet)
            
        if s_packet.haslayer(DNS):
            dns_packet = s_packet[DNS]
            flow.udps.dns_query_id = dns_packet.id
            flow.udps.dns_query_aa = dns_packet.aa
            flow.udps.dns_query_tc = dns_packet.tc
            flow.udps.dns_query_rd = dns_packet.rd
            flow.udps.dns_query_ra = dns_packet.ra
            flow.udps.dns_query_z = dns_packet.z
            flow.udps.dns_query_ad = dns_packet.ad
            flow.udps.dns_query_cd = dns_packet.cd
            flow.udps.dns_query_rcode = dns_packet.rcode
            flow.udps.dns_query_qdcount = dns_packet.qdcount
            flow.udps.dns_query_ancount = dns_packet.ancount
            flow.udps.dns_query_nscount = dns_packet.nscount
            flow.udps.dns_query_arcount = dns_packet.arcount
            
            if dns_packet.haslayer(DNSQR):
                dns_query = dns_packet[DNSQR]
                flow.udps.dns_query_type.append(dns_query.qtype)
                name =  dns_query.qname.decode('utf-8', errors='ignore')
                if name[-1] == '.':
                        name = name[:-1]
                flow.udps.dns_query_names.add(name)
                flow.udps.dns_answer_rrname = name
            
            if hasattr(dns_packet, 'an'):
                dns_answer = dns_packet.an
                if dns_answer is not None:
                    try:
                        flow.udps.dns_ttl_answer.append(dns_answer.ttl)
                        if hasattr(dns_answer, 'rdlen') and dns_answer.rdlen is not None:
                            flow.udps.dns_answer_len.append(dns_answer.rdlen)
                            if dns_answer.rrname is not None:
                                flow.udps.dns_answer_rrname = dns_answer.rrname.decode('utf-8', errors='ignore')
                                if flow.udps.dns_answer_rrname[-1] == '.':
                                    flow.udps.dns_answer_rrname = flow.udps.dns_answer_rrname[:-1]
                    except:
                        pass

    def on_update(self, packet, flow):
        if packet.ip_version == 4:
            s_packet = IP(packet.ip_packet)
        elif packet.ip_version == 6:
            s_packet = IPv6(packet.ip_packet)

        if s_packet.haslayer(DNS):
            dns_packet = s_packet[DNS]
            flow.udps.dns_query_id = dns_packet.id
            flow.udps.dns_query_aa += dns_packet.aa
            flow.udps.dns_query_tc += dns_packet.tc
            flow.udps.dns_query_rd += dns_packet.rd
            flow.udps.dns_query_ra += dns_packet.ra
            flow.udps.dns_query_z += dns_packet.z
            flow.udps.dns_query_ad += dns_packet.ad
            flow.udps.dns_query_cd += dns_packet.cd
            flow.udps.dns_query_rcode += dns_packet.rcode
            flow.udps.dns_query_qdcount += dns_packet.qdcount
            flow.udps.dns_query_ancount += dns_packet.ancount
            flow.udps.dns_query_nscount += dns_packet.nscount
            flow.udps.dns_query_arcount += dns_packet.arcount
            if dns_packet.haslayer(DNSQR):
                dns_query = dns_packet[DNSQR]
                flow.udps.dns_query_type.append(dns_query.qtype)
                try:
                    name =  dns_query.qname.decode('utf-8', errors='ignore')
                    if name[-1] == '.':
                            name = name[:-1]
                    flow.udps.dns_query_names.add(name)
                except:
                    pass
            if hasattr(dns_packet, 'an'):
                dns_answer = dns_packet.an
                if dns_answer is not None:
                    try:
                        flow.udps.dns_ttl_answer.append(dns_answer.ttl)
                        if hasattr(dns_answer, 'rdlen') and dns_answer.rdlen is not None:
                            flow.udps.dns_answer_len.append(dns_answer.rdlen)
                        
                            if dns_answer.rrname is not None:
                                flow.udps.dns_answer_rrname = dns_answer.rrname.decode('utf-8', errors='ignore')
                                if flow.udps.dns_answer_rrname[-1] == '.':
                                    flow.udps.dns_answer_rrname = flow.udps.dns_answer_rrname[:-1]
                    except:
                        pass
                
    def on_expire(self, flow):
        if len(flow.udps.dns_query_type) > 0:
            mode, num_unique, num_strings = self.__get_mode_and_unique_values(flow.udps.dns_query_type)
            flow.udps.dns_query_type = mode
            flow.udps.dns_query_type_uq = num_unique
            flow.udps.dns_query_type_count = num_strings
        else:
            flow.udps.dns_query_type = 0
            
        if  len(flow.udps.dns_ttl_answer) > 0:
            flow.udps.dns_ttl_answer_max = max(flow.udps.dns_ttl_answer)
            flow.udps.dns_ttl_answer_min = min(flow.udps.dns_ttl_answer)
            flow.udps.dns_ttl_answer_mean = np.nanmean(flow.udps.dns_ttl_answer)
            flow.udps.dns_ttl_answer = flow.udps.dns_ttl_answer[0]
        else:
            flow.udps.dns_ttl_answer = 0
        
        if len(flow.udps.dns_answer_len) > 0:
            flow.udps.dns_answer_len_max = max(flow.udps.dns_answer_len)
            flow.udps.dns_answer_len_min = min(flow.udps.dns_answer_len)
            flow.udps.dns_answer_len_mean = np.nanmean(flow.udps.dns_answer_len)
            flow.udps.dns_answer_len = flow.udps.dns_answer_len[0]
        else:
            flow.udps.dns_answer_len = 0
            
        if len(flow.udps.dns_query_names) > 0:
            flow.udps.dns_query_names = ';'.join(flow.udps.dns_query_names)
        else:
            flow.udps.dns_query_names = 'unknown'