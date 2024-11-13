from nfstream import NFPlugin
import dpkt
from scapy.all import IP, TCP, IPv6

class AuxTCPWindowMinMAx(NFPlugin):
    """
    This plugin extracts TCP window flow features

    Attributes:
        flow.udps.tcp_win_max_in (int): Max TCP Window (src->dst).
        flow.udps.tcp_win_max_out (int): Min TCP Window (dst->src).
    """
    def __init__(self):
        super(AuxTCPWindowMinMAx, self).__init__()

    def on_init(self, packet, flow):
        
        flow.udps.tcp_win_max_in = 0
        flow.udps.tcp_win_max_out = 0
        
        if packet.ip_version == 4:
            s_packet = IP(packet.ip_packet)
        elif packet.ip_version == 6:
            s_packet = IPv6(packet.ip_packet)

            
        if s_packet.haslayer(TCP):
            flow.udps.tcp_win_max_in = s_packet[TCP].window
            flow.udps.tcp_win_max_out = s_packet[TCP].window        

    def on_update(self, packet, flow):
        
        if packet.ip_version == 4:
            s_packet = IP(packet.ip_packet)
        elif packet.ip_version == 6:
            s_packet = IPv6(packet.ip_packet)

        if s_packet.haslayer(TCP):
            win = s_packet[TCP].window
            if packet.direction == 0 and win > flow.udps.tcp_win_max_in and packet.protocol == 6 :
                flow.udps.tcp_win_max_in = win
            elif packet.direction == 1 and win > flow.udps.tcp_win_max_out and packet.protocol == 6:
                flow.udps.tcp_win_max_out = win


class AuxTCPFlagsFeatures(NFPlugin): 
    """
    This plugin extracts TCP flags flow features

    Attributes:
        flow.udps.src2dst_flags (int): Cumulative of all client TCP flags.
        flow.udps.dst2src_flags (int): Cumulative of all server TCP flags.
        flow.udps.tcp_flags (int): Cumulative of all flow TCP flags.
    """
    def __init__(self):
        super(AuxTCPFlagsFeatures, self).__init__()

    def get_flags(self, flag):
        flag = int(flag)
        di = {'urg': 32, 'ack': 16, 'psh': 8, 'rst': 4, 'syn': 2, 'fin': 1}
        flags = [k for k, v in di.items() if v & flag]
        return set(flags)
    
    def get_cumul(self, l):
        di = {'urg': 32, 'ack': 16, 'psh': 8, 'rst': 4, 'syn': 2, 'fin': 1}
        cumul = 0
        for i in l:
            cumul += di[i]
        return cumul

    def on_init(self, packet, flow):
        curr_flag = 0
        flow.udps.bi_flags = set()
        flow.udps.s2d_flags = set()
        flow.udps.d2s_flags = set()
        
        flow.udps.src2dst_flags = 0
        flow.udps.dst2src_flags = 0
        flow.udps.tcp_flags = 0 
        try:
            if packet.ip_version == 4 and packet.protocol == 6:
                decoded_packet = dpkt.ip.IP(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
                
            elif packet.ip_version == 6 and packet.protocol == 6:
                decoded_packet = dpkt.ip6.IP6(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
            
            if curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                flow.udps.bi_flags = flow.udps.bi_flags.union(cur_s)
            if packet.direction == 0 and curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                flow.udps.s2d_flags = flow.udps.s2d_flags.union(cur_s)
            elif packet.direction == 1 and curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                flow.udps.d2s_flags = flow.udps.d2s_flags.union(cur_s)
        except:
            pass


    def on_update(self, packet, flow):
        curr_flag = 0
        try:
            if packet.ip_version == 4 and packet.protocol == 6:
                decoded_packet = dpkt.ip.IP(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
    
            if packet.ip_version == 4 and packet.protocol == 6:
                decoded_packet = dpkt.ip.IP(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
                
            elif packet.ip_version == 6 and packet.protocol == 6:
                decoded_packet = dpkt.ip6.IP6(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
            
            if curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                flow.udps.bi_flags = flow.udps.bi_flags.union(cur_s)
            if packet.direction == 0 and curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                flow.udps.s2d_flags = flow.udps.s2d_flags.union(cur_s)
            elif packet.direction == 1 and curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                flow.udps.d2s_flags = flow.udps.d2s_flags.union(cur_s)
        except:
            pass
            
    def on_expire(self, flow):
        try:
            flow.udps.tcp_flags = self.get_cumul(flow.udps.bi_flags)
            flow.udps.src2dst_flags = self.get_cumul(flow.udps.s2d_flags)
            flow.udps.dst2src_flags = self.get_cumul(flow.udps.d2s_flags)
        except:
            pass

        del flow.udps.bi_flags
        del flow.udps.s2d_flags
        del flow.udps.d2s_flags

class AuxRetransmissionCounter(NFPlugin):
    """
    This pluguin extracts TCP retransmission flow features
    Attributes
    ----------
    flow.udps.retransmitted_in_packets:  %RETRANSMITTED_IN_PKTS Number of retransmitted TCP flow packets (src->dst)
    flow.udps.retransmitted_out_packets: %RETRANSMITTED_OUT_PKTS Number of retransmitted TCP flow packets (dst->src)
    flow.udps.retransmitted_in_bytes: %RETRANSMITTED_IN_BYTES Number of retransmitted TCP flow bytes (src->dst)
    flow.udps.retransmitted_out_bytes: %RETRANSMITTED_OUT_BYTES Number of retransmitted TCP flow bytes (dst->src)
    """
    def __init__(self):
        super(AuxRetransmissionCounter, self).__init__()

    def on_init(self, packet, flow):
        
        flow.udps.retransmitted_in_packets = 0
        flow.udps.retransmitted_out_packets = 0
        flow.udps.retransmitted_in_bytes = 0
        flow.udps.retransmitted_out_bytes = 0
        flow.udps.last_tcp_ack_number_in = -1
        flow.udps.last_tcp_ack_number_out = -1
        flow.udps.last_tcp_seq_number_in = -1
        flow.udps.last_tcp_seq_number_out = -1
        
        if packet.ip_version == 4:
            s_packet = IP(packet.ip_packet)
        elif packet.ip_version == 6:
            s_packet = IPv6(packet.ip_packet)

        if s_packet.haslayer(TCP):
            seq_number = s_packet[TCP].seq
            ack_number = s_packet[TCP].ack
            if packet.direction == 0 :
                flow.udps.last_tcp_ack_number_in = ack_number
                flow.udps.last_tcp_seq_number_in = seq_number
            elif packet.direction == 1 :
                flow.udps.last_tcp_ack_number_out = ack_number
                flow.udps.last_tcp_seq_number_out = seq_number
            
    def on_update(self, packet, flow):
        
        if packet.ip_version == 4:
            s_packet = IP(packet.ip_packet)
        elif packet.ip_version == 6:
            s_packet = IPv6(packet.ip_packet)
            
        if s_packet.haslayer(TCP):
            seq_number = s_packet[TCP].seq
            ack_number = s_packet[TCP].ack
            if packet.direction == 0:
                if ack_number <= flow.udps.last_tcp_ack_number_in and seq_number <= flow.udps.last_tcp_seq_number_in :
                    flow.udps.retransmitted_in_packets += 1
                    flow.udps.retransmitted_in_bytes += packet.ip_size
                flow.udps.last_tcp_ack_number_in = max(ack_number, flow.udps.last_tcp_ack_number_in)
                flow.udps.last_tcp_seq_number_in = max(seq_number, flow.udps.last_tcp_seq_number_in)
                    
            elif packet.direction == 1:
                if ack_number <= flow.udps.last_tcp_ack_number_out and seq_number <= flow.udps.last_tcp_seq_number_out :
                    flow.udps.retransmitted_out_packets += 1
                    flow.udps.retransmitted_out_bytes += packet.ip_size
                flow.udps.last_tcp_ack_number_out = max(ack_number, flow.udps.last_tcp_ack_number_out)
                flow.udps.last_tcp_seq_number_out = max(seq_number, flow.udps.last_tcp_seq_number_out)
                    
    def on_expire(self, flow):
        del flow.udps.last_tcp_ack_number_in
        del flow.udps.last_tcp_ack_number_out
        del flow.udps.last_tcp_seq_number_in
        del flow.udps.last_tcp_seq_number_out
 
class FlowTCPTermination(NFPlugin):
    """
    This pluguin handle TCP flow termination and count the number of packets recieved after 2 bidirectional FIN flags and their ACK 
    are recieved. Furthermore, it computes the interval of time that the connection is half closed.

    Attributes
    ----------
    flow.udps.tcp_half_closed_time_ms: time in ms that connection is half closed 
    flow.udps.num_pkts_after_termination: the number of packet recieved in 15s after the four -way handshake
    """
    def on_init(self, packet, flow):
        flow.udps.tcp_half_closed_time_ms = -2
        flow.udps.num_pkts_after_termination = 0
        flow.udps.direction_first_fin = -1 # variable that stores direction of first FIN packet
        flow.udps.condition_rst = False
        flow.udps.condition_fin = False
        flow.udps.first_fin = -1
        flow.udps.last = -1
        
        if packet.protocol==6:
            if flow.udps.tcp_half_closed_time_ms == -2:
                flow.udps.tcp_half_closed_time_ms = -1
                
            elif packet.fin == 1 and flow.udps.direction_first_fin == -1:
                flow.udps.direction_first_fin = packet.direction
                flow.udps.first_fin = packet.time
            
            elif packet.rst == 1:
                flow.udps.condition_rst = True  
                flow.udps.last = packet.time
            else:
                pass
 
    def on_update(self, packet, flow):
        if packet.protocol==6:
            
            if flow.udps.tcp_half_closed_time_ms == -2:
                flow.udps.tcp_half_closed_time_ms = -1
                
            if packet.fin == 1 and flow.udps.direction_first_fin == -1: # stroe direction of fisrt FIN of the flow
                flow.udps.direction_first_fin = packet.direction
                flow.udps.first_fin = packet.time
            
            if packet.rst == 1 and flow.udps.condition_rst == False:
                flow.udps.condition_rst = True  
                flow.udps.last = packet.time
                if flow.udps.first_fin !=-1:
                    flow.udps.tcp_half_closed_time_ms = flow.udps.last - flow.udps.first_fin
                else:
                    flow.udps.tcp_half_closed_time_ms = flow.udps.last - flow.bidirectional_last_seen_ms
            
            if (flow.src2dst_fin_packets > 0) and (flow.dst2src_fin_packets > 0) and (packet.syn==1):               
                flow.expiration_id = 2
                if flow.udps.first_fin > 0:
                    flow.udps.tcp_half_closed_time_ms = packet.time - flow.udps.first_fin
        
            elif (flow.src2dst_fin_packets != 0) and (flow.dst2src_fin_packets != 0) and (packet.ack == 1 and packet.fin==1) \
                         and (flow.udps.direction_first_fin == packet.direction) and flow.udps.condition_fin == False: 
                
                flow.udps.condition_fin = True  
                flow.udps.last = packet.time
                flow.udps.tcp_half_closed_time_ms = flow.udps.last - flow.udps.first_fin
                
            elif (flow.udps.condition_fin or flow.udps.condition_rst) and (packet.syn == 0):
                flow.udps.num_pkts_after_termination += 1
                flow.udps.tcp_half_closed_time_ms = packet.time - flow.udps.first_fin

                
            elif (flow.udps.condition_fin) and (packet.syn == 1) :
                flow.expiration_id = 2
                if flow.udps.first_fin > 0:
                    flow.udps.tcp_half_closed_time_ms = packet.time - flow.udps.first_fin
                
            else:
                pass
        else:
            pass
        
    def on_expire(self, flow):
        """
        Correct the flow expiration reason if it ended by FIN flags
        """
        #if (flow.protocol==6) and (flow.udps.condition_fin or flow.udps.condition_rst):
        #    flow.expiration_id =  2
        if flow.udps.tcp_half_closed_time_ms < 0:
            flow.udps.tcp_half_closed_time_ms = 0
        del flow.udps.direction_first_fin
        del flow.udps.condition_rst
        del flow.udps.condition_fin
        del flow.udps.first_fin
        del flow.udps.last 
     
class FlowTCPHandshake(NFPlugin):
    """
    This pluguin handle TCP connection establishment 
    Attributes
    ----------
    flow.udps.tcp_init_ms: time in ms between first SYN and SYN-ACK packet
    flow.udps.tcp_synack_ack_ms: time in ms between SYN-ACK packet and its acknowledgment
    """
    def on_init(self, packet, flow):
        flow.udps.tcp_init_ms = -2
        flow.udps.tcp_synack_ack_ms = -2
        flow.udps.direction_first_syn = -1
        flow.udps.time_first_syn = -1
        flow.udps.time_syn_ack = -1
        flow.udps.last_handshake_ack = -1
        
        if packet.protocol==6:
            if flow.udps.tcp_init_ms == -2:
                flow.udps.tcp_init_ms = -1
                flow.udps.tcp_synack_ack_ms = -1
            if packet.syn == 1 and flow.udps.direction_first_syn == -1:
                flow.udps.direction_first_syn = packet.direction
                flow.udps.time_first_syn = packet.time
            elif packet.syn == 1 and packet.ack == 1 :
                flow.udps.time_syn_ack = packet.time
            else:
                pass
        else:
            pass

    def on_update(self, packet, flow):
        
        if packet.protocol==6:
            if flow.udps.tcp_init_ms == -2:
                flow.udps.tcp_init_ms = -1
                flow.udps.tcp_synack_ack_ms = -1
            if packet.syn == 1 and flow.udps.direction_first_syn == -1:
                flow.udps.direction_first_syn = packet.direction
                flow.udps.time_first_syn = packet.time
            elif packet.syn == 1 and packet.ack == 1 and packet.direction != flow.udps.direction_first_syn:
                flow.udps.time_syn_ack = packet.time
                flow.udps.tcp_init_ms = packet.time - flow.udps.time_first_syn
            elif flow.udps.time_syn_ack > 0 and packet.direction == flow.udps.direction_first_syn and packet.ack == 1:
                flow.udps.tcp_synack_ack_ms = packet.time - flow.udps.time_syn_ack
            else:
                pass
        else:
            pass
    def on_expire(self, flow):
        
        if flow.udps.tcp_init_ms < 0:
            flow.udps.tcp_init_ms = 0
        if flow.udps.tcp_synack_ack_ms < 0:
            flow.udps.tcp_synack_ack_ms = 0
        
        
        del flow.udps.direction_first_syn
        del flow.udps.time_first_syn
        del flow.udps.time_syn_ack 
        del flow.udps.last_handshake_ack