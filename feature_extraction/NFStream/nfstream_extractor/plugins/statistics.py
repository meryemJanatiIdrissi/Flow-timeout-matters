from nfstream import NFPlugin
import math
import numpy as np
from runstats import *
from .pkts_utils.stats import IterableStats

def median_absolute_deviation(arr):
    """
    Calculate the median absolute deviation (MAD) of an array.

    Parameters:
    - arr (array-like): Input array or object that can be converted to an array.

    Returns:
    - float: The median absolute deviation of the input array.
    """
    return np.median(np.absolute(arr-np.median(arr)))

def quartile(arr):
    """
    Calculate the first quartile (Q1), median, and third quartile (Q3) of an array.

    Args:
        arr (numpy.ndarray): The input array.

    Returns:
        tuple: A tuple containing the first quartile (Q1), median, and third quartile (Q3).

    Examples:
        >>> quartile(np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
        (3.0, 5.5, 8.0)
    """
    sorted_arr = np.sort(arr)
    median = sorted_median(sorted_arr)
    sorted_len = len(sorted_arr)
    half = int(sorted_len/2)
    if sorted_len % 2 == 0:
        return sorted_median(sorted_arr[0:half]),median,sorted_median(sorted_arr[half:sorted_len])
    else:
        return sorted_median(sorted_arr[0:half+1]),median,sorted_median(sorted_arr[half:sorted_len])

def sorted_median(sorted_arr):
    """
    Calculate the median of a sorted array.

    Args:
        sorted_arr (numpy.ndarray): The sorted input array.

    Returns:
        float: The median of the array.

    Examples:
        >>> sorted_median(np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
        5.5
    """
    arr_len = len(sorted_arr)
    half = int(arr_len/2)
    if arr_len % 2 == 0:
        return (sorted_arr[half-1]+sorted_arr[half])/2
    else:
        return sorted_arr[half]


class AuxPktSizeFeatures(NFPlugin):
    """
    This pluguin counts the number of packet per size interval
    Attributes
    ----------
    flow.udps.num_pkts_up_to_128_bytes: %NUM_PKTS_UP_TO_128_BYTES number of packet having less than 128 bytes
    flow.udps.num_pkts_128_to_256_bytes: %NUM_PKTS_128_TO_256_BYTES number of packet having size between  128 and 256 bytes
    flow.udps.num_pkts_256_to_512_bytes: %NUM_PKTS_256_TO_512_BYTES number of packet having size between  256 and 512 bytes
    flow.udps.num_pkts_512_to_1024_bytes: %NUM_PKTS_512_TO_1024_BYTES number of packet having size between  512 and 1024 bytes
    flow.udps.num_pkts_1024_to_1514_bytes: %NUM_PKTS_1024_TO_1514_BYTES number of packet having size greater than 1024 bytes
    """
    
    def on_init(self, packet, flow):
        flow.udps.num_pkts_up_to_128_bytes = 0
        flow.udps.num_pkts_128_to_256_bytes = 0
        flow.udps.num_pkts_256_to_512_bytes = 0
        flow.udps.num_pkts_512_to_1024_bytes = 0
        flow.udps.num_pkts_1024_to_1514_bytes = 0
        if packet.ip_size <= 128:
            flow.udps.num_pkts_up_to_128_bytes += 1
        elif packet.ip_size > 128 and packet.ip_size <= 256:
            flow.udps.num_pkts_128_to_256_bytes += 1
        elif packet.ip_size > 256 and packet.ip_size <= 512:
            flow.udps.num_pkts_256_to_512_bytes += 1
        elif packet.ip_size > 512 and packet.ip_size <= 1024:
            flow.udps.num_pkts_512_to_1024_bytes += 1
        elif packet.ip_size > 1024 and packet.ip_size <= 1514:
            flow.udps.num_pkts_1024_to_1514_bytes += 1

    def on_update(self, packet, flow):
        if packet.ip_size <= 128:
            flow.udps.num_pkts_up_to_128_bytes += 1
        elif packet.ip_size > 128 and packet.ip_size <= 256:
            flow.udps.num_pkts_128_to_256_bytes += 1
        elif packet.ip_size > 256 and packet.ip_size <= 512:
            flow.udps.num_pkts_256_to_512_bytes += 1
        elif packet.ip_size > 512 and packet.ip_size <= 1024:
            flow.udps.num_pkts_512_to_1024_bytes += 1
        elif packet.ip_size > 1024 and packet.ip_size <= 1514:
            flow.udps.num_pkts_1024_to_1514_bytes += 1


class AuxSecBytesFeatures(NFPlugin):
    """
    This pluguin computes second_bytes and throughput for each direction
    Attributes
    ----------
    flow.udps.src_to_dst_second_bytes: %SRC_TO_DST_SECOND_BYTES        Bytes/sec (src->dst)
    flow.udps.dst_to_src_second_bytes: %DST_TO_SRC_SECOND_BYTES        Bytes/sec2 (dst->src)
    flow.udps.src_to_dst_avg_throughput: %SRC_TO_DST_AVG_THROUGHPUT       Src to dst average thpt (bps)
    flow.udps.dst_to_src_avg_throughput: %DST_TO_SRC_AVG_THROUGHPUT       Dst to src average thpt (bps)
    flow.udps.src_to_dst_second_bytes2: %SRC_TO_DST_SECOND_BYTES        Bytes/sec (src->dst)
    flow.udps.dst_to_src_second_bytes2: %DST_TO_SRC_SECOND_BYTES        Bytes/sec2 (dst->src)
    flow.udps.src_to_dst_avg_throughput2: %SRC_TO_DST_AVG_THROUGHPUT       Src to dst average thpt (bps)
    flow.udps.dst_to_src_avg_throughput2: %DST_TO_SRC_AVG_THROUGHPUT       Dst to src average thpt (bps)
    """
    def on_init(self, packet, flow):
        flow.udps.dic_src2dst = {}
        flow.udps.dic_dst2src = {}
        flow.udps.k_s2d = 0
        flow.udps.k_d2s = 0
        flow.udps.src_to_dst_second_bytes = 0
        flow.udps.dst_to_src_second_bytes = 0
        flow.udps.src_to_dst_avg_throughput = 0
        flow.udps.dst_to_src_avg_throughput = 0
        ###
        flow.udps.src_to_dst_second_bytes2 = 0
        flow.udps.dst_to_src_second_bytes2 = 0
        flow.udps.src_to_dst_avg_throughput2 = 0
        flow.udps.dst_to_src_avg_throughput2 = 0

        
        if packet.direction == 0:
            flow.udps.k_s2d = flow.udps.k_s2d + 1
            flow.udps.dic_src2dst[flow.udps.k_s2d] = {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
        elif packet.direction == 1:
            flow.udps.k_d2s = flow.udps.k_d2s + 1
            flow.udps.dic_dst2src[flow.udps.k_d2s] = {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
            
        
    def on_update(self, packet, flow):
        if packet.direction == 0:
            if flow.udps.k_s2d < 1:
                flow.udps.k_s2d = flow.udps.k_s2d + 1
                flow.udps.dic_src2dst[flow.udps.k_s2d] = {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
            else:

                if flow.udps.dic_src2dst[flow.udps.k_s2d]['is_completed'] == True:
                    #print('completed s2d, key :', last_key)
                    flow.udps.k_s2d = flow.udps.k_s2d+ 1
                    #print('new key :', new_key)
                    flow.udps.dic_src2dst[flow.udps.k_s2d]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
                else:
                    start = flow.udps.dic_src2dst[flow.udps.k_s2d]['start']
                    end = flow.udps.dic_src2dst[flow.udps.k_s2d]['end']
                    delta1 = (packet.time - start) / 1000
                    delta2 = (packet.time - end) / 1000
                    if delta1 <= 1:
                        flow.udps.dic_src2dst[flow.udps.k_s2d]['end']= packet.time
                        flow.udps.dic_src2dst[flow.udps.k_s2d]['size'] = flow.udps.dic_src2dst[flow.udps.k_s2d]['size'] + packet.ip_size
                        if delta1 == 1:
                            flow.udps.dic_src2dst[flow.udps.k_s2d]['is_completed'] = True
                    elif delta1 > 1:
                        flow.udps.dic_src2dst[flow.udps.k_s2d]['is_completed'] = True
                        if math.floor(delta2) >= 1:
                            for i in range(math.floor(delta2)):
                                flow.udps.k_s2d = flow.udps.k_s2d + i + 1
                                flow.udps.dic_src2dst[flow.udps.k_s2d]= {'is_completed':True, 'start': 0, 'end':0, 'size':0}
                            if delta2 % 1 != 0:
                                last_key = list(flow.udps.dic_src2dst.keys())[-1]
                                flow.udps.k_s2d = flow.udps.k_s2d + 1
                                flow.udps.dic_src2dst[flow.udps.k_s2d]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}             
                        else:
                            flow.udps.k_s2d = flow.udps.k_s2d + 1
                            flow.udps.dic_src2dst[flow.udps.k_s2d]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
                        
        elif packet.direction == 1:
            if flow.udps.k_d2s < 1:
                flow.udps.k_d2s = flow.udps.k_d2s + 1
                flow.udps.dic_dst2src[flow.udps.k_d2s] = {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
            else:
                if flow.udps.dic_dst2src[flow.udps.k_d2s]['is_completed']  == True:
                    #print('completed s2d, key :', last_key)
                    flow.udps.k_d2s = flow.udps.k_d2s+1
                    #print('new key :', new_key)
                    flow.udps.dic_dst2src[flow.udps.k_d2s]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
                else:
                    start = flow.udps.dic_dst2src[flow.udps.k_d2s]['start']
                    end = flow.udps.dic_dst2src[flow.udps.k_d2s]['end']
                    delta1 = (packet.time - start) / 1000
                    delta2 = (packet.time - end) / 1000
                    if delta1 <= 1:
                        flow.udps.dic_dst2src[flow.udps.k_d2s]['end']= packet.time
                        flow.udps.dic_dst2src[flow.udps.k_d2s]['size'] = flow.udps.dic_dst2src[flow.udps.k_d2s]['size'] + packet.ip_size
                        if delta1 == 1:
                            flow.udps.dic_dst2src[flow.udps.k_d2s]['is_completed'] = True
                    elif delta1 > 1:
                        flow.udps.dic_dst2src[flow.udps.k_d2s]['is_completed'] = True
                        if math.floor(delta2) >= 1:
                            for i in range(math.floor(delta2)):
                                flow.udps.k_d2s = flow.udps.k_d2s + i + 1
                                flow.udps.dic_dst2src[flow.udps.k_d2s]= {'is_completed':True, 'start': 0, 'end':0, 'size':0}
                            if delta2 % 1 != 0:
                                flow.udps.k_d2s = flow.udps.k_d2s + 1
                                flow.udps.dic_dst2src[flow.udps.k_d2s]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}             
                        else:
                            flow.udps.k_d2s = flow.udps.k_d2s + 1
                            flow.udps.dic_dst2src[flow.udps.k_d2s]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
    def on_expire(self, flow):
        thpt_s2d = 0
        thpt_d2s = 0
        scb_s2d = 0
        scb_d2s = 0
        #print(self.dic_src2dst, '\n\n')
        #print('dic_dst2src   ', self.dic_dst2src)
        l_s2d = 0
        l_d2s = 0
        for k in list(flow.udps.dic_src2dst.keys()):
            size = flow.udps.dic_src2dst[k]['size']
            if size > 0:
                scb_s2d += size
                thpt_s2d += (8 * size)
                l_s2d += 1
        for k in list(flow.udps.dic_dst2src.keys()):
            size = flow.udps.dic_dst2src[k]['size']
            if size > 0:
                scb_d2s += size
                thpt_d2s += (8 * size)
                l_d2s += 1
        
        if l_s2d > 0:
            scb_s2d = scb_s2d / l_s2d
            thpt_s2d = thpt_s2d / l_s2d
        else:
            scb_s2d = flow.src2dst_bytes
            thpt_s2d = 8 * flow.src2dst_bytes
            
        if l_d2s > 0:
            scb_d2s = scb_d2s / l_d2s
            thpt_d2s = thpt_d2s / l_d2s
        else:
            scb_d2s = flow.dst2src_bytes
            thpt_d2s = 8 * flow.dst2src_bytes
       
        flow.udps.src_to_dst_second_bytes = scb_s2d 
        flow.udps.dst_to_src_second_bytes = scb_d2s 
        flow.udps.src_to_dst_avg_throughput = thpt_s2d
        flow.udps.dst_to_src_avg_throughput = thpt_d2s
        
        flow.udps.src_to_dst_second_bytes2 = flow.src2dst_bytes/(flow.src2dst_duration_ms/1000) if flow.src2dst_duration_ms > 0 else flow.src2dst_bytes
        flow.udps.dst_to_src_second_bytes2 = flow.dst2src_bytes/(flow.dst2src_duration_ms/1000) if flow.dst2src_duration_ms > 0 else flow.dst2src_bytes
        flow.udps.src_to_dst_avg_throughput2 = (8 * flow.src2dst_bytes/(flow.src2dst_duration_ms/1000)) if flow.src2dst_duration_ms > 0 else (8 * flow.src2dst_bytes)
        flow.udps.dst_to_src_avg_throughput2 = (8 * flow.dst2src_bytes/(flow.dst2src_duration_ms/1000)) if flow.dst2src_duration_ms > 0 else (8 * flow.dst2src_bytes)
        
        del flow.udps.dic_src2dst
        del flow.udps.dic_dst2src
        del flow.udps.k_s2d
        del flow.udps.k_d2s

class FirstPacketPayloadLen(NFPlugin):
    '''
    Credit: This pluguin is implemented by OSF-EIMTC https://github.com/ArielCyber/OSF-EIMTC
    First packet's payload length per direction,
    note that the first packet is always from src to dst hence
    bidirectional first packet's payload length is equal to src2dst_packet_payload_len.

    if there are no packets from dst to src, then the value is defaulted to None (empty).

    Attributes:
        src2dst_first_packet_payload_len (int): The payload length of the first packet from source to destination.
        dst2src_first_packet_payload_len (int or None): The payload length of the first packet from destination to source. Defaults to None if no such packets are observed.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_init(self, packet, flow):
        '''
        on_init(self, packet, flow): Method called at flow creation.
        '''
        flow.udps.src2dst_first_packet_payload_len = packet.payload_size
        flow.udps.dst2src_first_packet_payload_len = None
        
    def on_update(self, packet, flow):
        if flow.udps.dst2src_first_packet_payload_len is None and packet.direction == 1:
           flow.udps.dst2src_first_packet_payload_len = packet.payload_size 
    def on_expire(self, flow):
        if flow.udps.dst2src_first_packet_payload_len is None:
            flow.udps.dst2src_first_packet_payload_len = 0 

class FLowPayloadFeatures(NFPlugin):
    """
    This pluguin count the total transport size and the total payload in bytes of exchanged 
    packets in both directions
    Attributes
    ----------
    flow.udps.bidirectional_transport_bytes: total bytes of exchanged transport segments
    flow.udps.bidirectional_payload_bytes: total bytes of exchanged packets payload
    flow.udps.src2dst_transport_bytes: SRC2DST total bytes of exchanged transport segments
    flow.udps.src2dst_payload_bytes: SRC2DST total bytes of exchanged packets payload
    flow.udps.dst2src_transport_bytes: DST2SRC total bytes of exchanged transport segments
    flow.udps.dst2src_payload_bytes: DST2SRC total bytes of exchanged packets payload
    """
    def on_init(self, packet, flow):
        flow.udps.bidirectional_transport_bytes = packet.transport_size
        flow.udps.bidirectional_payload_bytes = packet.payload_size
        flow.udps.src2dst_transport_bytes = 0
        flow.udps.src2dst_payload_bytes = 0
        flow.udps.dst2src_transport_bytes = 0
        flow.udps.dst2src_payload_bytes = 0
        
        if packet.direction == 0:
            flow.udps.src2dst_transport_bytes = packet.transport_size
            flow.udps.src2dst_payload_bytes = packet.payload_size        
        else:
            flow.udps.dst2src_transport_bytes = packet.transport_size
            flow.udps.dst2src_payload_bytes = packet.payload_size 
        

    def on_update(self, packet, flow):
        flow.udps.bidirectional_transport_bytes += packet.transport_size
        flow.udps.bidirectional_payload_bytes += packet.payload_size
        
        if packet.direction == 0:
            flow.udps.src2dst_transport_bytes += packet.transport_size
            flow.udps.src2dst_payload_bytes += packet.payload_size        
        else:
            flow.udps.dst2src_transport_bytes += packet.transport_size
            flow.udps.dst2src_payload_bytes += packet.payload_size 

class RecvSentPacketRatio(NFPlugin):
    '''
        Credit: This pluguin is implemented by OSF-EIMTC https://github.com/ArielCyber/OSF-EIMTC
        The ratio of the number of received packets to the number of sent packets.
        = recv/sent.
    Attributes
    ----------
    flow.udps.sent_recv_packet_ratio: The ratio of the number of received packets to the number of sent packets.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
    def on_expire(self, flow):
        flow.udps.sent_recv_packet_ratio =  flow.dst2src_packets / flow.src2dst_packets

class MostFreqPayloadLenRatio(NFPlugin):
    '''
    Credit: This plugin is implemented by OSF-EIMTC https://github.com/ArielCyber/OSF-EIMTC
    The ratio of the number of packets with the most frequent payload length for direction X to the total number of packets
    in direction X, for each direction x in {src2dst, dst2src}.

    Attributes:
        flow.src2dst_most_freq_payload_ratio (float): The ratio of packets with the most frequent payload length in the src2dst direction.
        flow.src2dst_most_freq_payload_len (int): The most frequent payload length observed in the src2dst direction.
        flow.dst2src_most_freq_payload_ratio (float): The ratio of packets with the most frequent payload length in the dst2src direction.
        flow.dst2src_most_freq_payload_len (int): The most frequent payload length observed in the dst2src direction.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_init(self, packet, flow):
        '''
        on_init(self, packet, flow): Method called at flow creation.
        '''

        flow.udps.src2dst_most_freq_payload_ratio = 0
        flow.udps.src2dst_most_freq_payload_len   = 0
        flow.udps.src2dst_payload_freq = dict()
        flow.udps.dst2src_most_freq_payload_ratio = 0
        flow.udps.dst2src_most_freq_payload_len   = 0
        flow.udps.dst2src_payload_freq = dict()

        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.direction == 0: # src2dst
            if packet.payload_size not in flow.udps.src2dst_payload_freq:
                flow.udps.src2dst_payload_freq[packet.payload_size] = 0
            flow.udps.src2dst_payload_freq[packet.payload_size] +=1
        else:
            if packet.payload_size not in flow.udps.dst2src_payload_freq:
                flow.udps.dst2src_payload_freq[packet.payload_size] = 0
            flow.udps.dst2src_payload_freq[packet.payload_size] +=1

    def on_expire(self, flow):
        if flow.src2dst_packets != 0:
            freq_dict = flow.udps.src2dst_payload_freq
            most_freq_payload_freq = max(freq_dict.values())
            flow.udps.src2dst_most_freq_payload_len   = list(freq_dict.keys())[np.argmax(list(freq_dict.values()))]
            flow.udps.src2dst_most_freq_payload_ratio = most_freq_payload_freq / flow.src2dst_packets
        if flow.dst2src_packets != 0:
            freq_dict = flow.udps.dst2src_payload_freq
            most_freq_payload_freq = max(freq_dict.values())
            flow.udps.dst2src_most_freq_payload_len   = list(freq_dict.keys())[np.argmax(list(freq_dict.values()))]
            flow.udps.dst2src_most_freq_payload_ratio = most_freq_payload_freq / flow.dst2src_packets

        # Cleanup        
        del flow.udps.src2dst_payload_freq
        del flow.udps.dst2src_payload_freq


class Packets_size_and_interarrival_time(NFPlugin):
    '''
    Credit: This plugin is implemented by OSF-EIMTC https://github.com/ArielCyber/OSF-EIMTC
    W.I.P:
        1. Optimize median calculations by using histogram (if possible)
        2. Add info about this plugin and its origin paper.
        
    UPDATES: Removed bidirectional_ps and bidirectional_piat that are already computed by NFStream. 
    Features are renamed to be compatible with NFStream.
    
    Attributes:
        flow.bidirectional_ps_first_quartile (int): First quartile of packet sizes in both directions.
        flow.bidirectional_ps_second_quartile (int): Second quartile (median) of packet sizes in both directions.
        flow.bidirectional_ps_third_quartile (int): Third quartile of packet sizes in both directions.
        flow.bidirectional_ps_median_absoulte_deviation (float): Median absolute deviation of packet sizes in both directions.
        flow.bidirectional_ps_skewness (float): Skewness of packet sizes in both directions.
        flow.bidirectional_ps_kurtosis (float): Kurtosis of packet sizes in both directions.
        flow.bidirectional_piat_first_quartile (int): First quartile of packet interarrival times in both directions.
        flow.bidirectional_piat_second_quartile (int): Second quartile (median) of packet interarrival times in both directions.
        flow.bidirectional_piat_third_quartile (int): Third quartile of packet interarrival times in both directions.
        flow.bidirectional_piat_median_absoulte_deviation (float): Median absolute deviation of packet interarrival times in both directions.
        flow.bidirectional_piat_skewness (float): Skewness of packet interarrival times in both directions.
        flow.bidirectional_piat_kurtosis (float): Kurtosis of packet interarrival times in both directions.
    '''
    def on_init(self, packet, flow):
        flow.udps.packets_size = list()
        flow.udps.packets_interarrival_time = list()
        self.on_update(packet,flow)

    def on_update(self, packet, flow):
        flow.udps.packets_size.append(packet.raw_size)
        flow.udps.packets_interarrival_time.append(packet.delta_time)

    def on_expire(self, flow):
        packets_size_statistics = Statistics(flow.udps.packets_size)
        packets_interarrival_time_statistics = Statistics(flow.udps.packets_interarrival_time)

        #Packets Size Statistical
        packets_size_Q1,packets_size_Q2,packets_size_Q3 = quartile(np.array(flow.udps.packets_size))
        #flow.udps.packets_size_min = packets_size_statistics.minimum() if packets_size_statistics._count > 0 else 0
        #flow.udps.packets_size_max = packets_size_statistics.maximum() if packets_size_statistics._count > 0 else 0
        flow.udps.bidirectional_ps_stddev = packets_size_statistics.stddev() if packets_size_statistics._count >= 2 else 0
        flow.udps.bidirectional_ps_first_quartile = packets_size_Q1
        flow.udps.bidirectional_ps_second_quartile = packets_size_Q2
        flow.udps.bidirectional_ps_third_quartile = packets_size_Q3
        #flow.udps.bidirectional_ps_mean = packets_size_statistics.mean()
        flow.udps.bidirectional_ps_median_absoulte_deviation = median_absolute_deviation(np.array(flow.udps.packets_size))
        #flow.udps.packets_size_variance = packets_size_statistics.variance() if packets_size_statistics._count >= 2 else 0
        flow.udps.bidirectional_ps_skewness = packets_size_statistics.skewness() if flow.udps.bidirectional_ps_stddev != 0 else 0
        flow.udps.bidirectional_ps_kurtosis = packets_size_statistics.kurtosis() if flow.udps.bidirectional_ps_stddev != 0 else 0
        #flow.udps.bidirectional_ps_sum = sum(flow.udps.packets_size)
        
        #Packets Interarrival Time Statistical
        packets_interarrival_time_Q1,packets_interarrival_time_Q2,packets_interarrival_time_Q3 = quartile(np.array(flow.udps.packets_interarrival_time))
        #flow.udps.packets_interarrival_time_min = packets_interarrival_time_statistics.minimum() if packets_interarrival_time_statistics._count > 0 else 0
        #flow.udps.packets_interarrival_time_max = packets_interarrival_time_statistics.maximum() if packets_interarrival_time_statistics._count > 0 else 0
        flow.udps.bidirectional_piat_stddev = packets_interarrival_time_statistics.stddev() if packets_interarrival_time_statistics._count >= 2 else 0
        flow.udps.bidirectional_piat_first_quartile = packets_interarrival_time_Q1
        flow.udps.bidirectional_piat_second_quartile = packets_interarrival_time_Q2
        flow.udps.bidirectional_piat_third_quartile = packets_interarrival_time_Q3
        #flow.udps.packets_interarrival_time_mean = packets_interarrival_time_statistics.mean()
        flow.udps.bidirectional_piat_median_absoulte_deviation = median_absolute_deviation(np.array(flow.udps.packets_interarrival_time))
        #flow.udps.packets_interarrival_time_variance = packets_interarrival_time_statistics.variance() if packets_interarrival_time_statistics._count >= 2 else 0
        flow.udps.bidirectional_piat_skewness = packets_interarrival_time_statistics.skewness() if flow.udps.bidirectional_piat_stddev != 0 else 0
        flow.udps.bidirectional_piat_kurtosis = packets_interarrival_time_statistics.kurtosis() if flow.udps.bidirectional_piat_stddev != 0 else 0
        #flow.udps.bidirectional_piat_sum = sum(flow.udps.packets_interarrival_time)
        
        #CleanUP
        del flow.udps.bidirectional_piat_stddev
        del flow.udps.bidirectional_ps_stddev 
        del flow.udps.packets_size
        del flow.udps.packets_interarrival_time

class PacketRelativeTime(NFPlugin):
    '''
    Credit: This plugin is implemented by OSF-EIMTC https://github.com/ArielCyber/OSF-EIMTC
    W.I.P:
        1. Optimize median calculations by using histogram (if possible)
        2. Add info about this plugin and its origin paper.
    UPDATES: Removed duplicated features.

    Attributes:
        flow.bidirectional_mean_packet_relative_times (float): Mean of packet relative times in both directions.
        flow.bidirectional_stddev_packet_relative_times (float): Standard deviation of packet relative times in both directions.
        flow.bidirectional_variance_packet_relative_times (float): Variance of packet relative times in both directions.
        flow.bidirectional_coeff_of_var_packet_relative_times (float): Coefficient of variation of packet relative times in both directions.
        flow.bidirectional_skew_from_median_packet_relative_times (float): Skewness from median of packet relative times in both directions.
        flow.src2dst_mean_packet_relative_times (float): Mean of packet relative times from source to destination.
        flow.src2dst_stddev_packet_relative_times (float): Standard deviation of packet relative times from source to destination.
        flow.src2dst_variance_packet_relative_times (float): Variance of packet relative times from source to destination.
        flow.src2dst_coeff_of_var_packet_relative_times (float): Coefficient of variation of packet relative times from source to destination.
        flow.src2dst_skew_from_median_packet_relative_times (float): Skewness from median of packet relative times from source to destination.
        flow.dst2src_mean_packet_relative_times (float): Mean of packet relative times from destination to source.
        flow.dst2src_stddev_packet_relative_times (float): Standard deviation of packet relative times from destination to source.
        flow.dst2src_variance_packet_relative_times (float): Variance of packet relative times from destination to source.
        flow.dst2src_coeff_of_var_packet_relative_times (float): Coefficient of variation of packet relative times from destination to source.
        flow.dst2src_skew_from_median_packet_relative_times (float): Skewness from median of packet relative times from destination to source.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_init(self, packet, flow):
        # bidirectional
        flow.udps.bidirectional_packet_relative_times = list()
        #flow.udps.bidirectional_min_packet_relative_times              = 0
        #flow.udps.bidirectional_max_packet_relative_times              = 0
        flow.udps.bidirectional_mean_packet_relative_times             = 0
        flow.udps.bidirectional_stddev_packet_relative_times           = 0
        flow.udps.bidirectional_variance_packet_relative_times         = 0
        flow.udps.bidirectional_coeff_of_var_packet_relative_times     = 0
        flow.udps.bidirectional_skew_from_median_packet_relative_times = 0
        # src -> dst
        flow.udps.src2dst_packet_relative_times = list()
        #flow.udps.src2dst_min_packet_relative_times              = 0
        #flow.udps.src2dst_max_packet_relative_times              = 0
        flow.udps.src2dst_mean_packet_relative_times             = 0
        flow.udps.src2dst_stddev_packet_relative_times           = 0
        flow.udps.src2dst_variance_packet_relative_times         = 0
        flow.udps.src2dst_coeff_of_var_packet_relative_times     = 0
        flow.udps.src2dst_skew_from_median_packet_relative_times = 0
        # dst -> src
        flow.udps.dst2src_packet_relative_times = list()
        #flow.udps.dst2src_min_packet_relative_times              = 0
        #flow.udps.dst2src_max_packet_relative_times              = 0
        flow.udps.dst2src_mean_packet_relative_times             = 0
        flow.udps.dst2src_stddev_packet_relative_times           = 0
        flow.udps.dst2src_variance_packet_relative_times         = 0
        flow.udps.dst2src_coeff_of_var_packet_relative_times     = 0
        flow.udps.dst2src_skew_from_median_packet_relative_times = 0

        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.direction == 0: # src -> dst
            flow.udps.src2dst_packet_relative_times.append(packet.time
                                    - flow.bidirectional_first_seen_ms)
        elif packet.direction == 1:
            flow.udps.dst2src_packet_relative_times.append(packet.time
                                    - flow.bidirectional_first_seen_ms)
            
        flow.udps.bidirectional_packet_relative_times.append(packet.time
                                    - flow.bidirectional_first_seen_ms)

        
    def on_expire(self, flow):
        # bidirectional
        stats = IterableStats(flow.udps.bidirectional_packet_relative_times)
        #flow.udps.bidirectional_min_packet_relative_times              = stats.min()
        #flow.udps.bidirectional_max_packet_relative_times              = stats.max()
        flow.udps.bidirectional_mean_packet_relative_times             = stats.average()
        flow.udps.bidirectional_stddev_packet_relative_times           = stats.std_deviation() 
        flow.udps.bidirectional_variance_packet_relative_times         = stats.variance()
        flow.udps.bidirectional_coeff_of_var_packet_relative_times     = stats.coeff_of_variation()
        flow.udps.bidirectional_skew_from_median_packet_relative_times = stats.skew_from_median()
        # src -> dst
        stats = IterableStats(flow.udps.src2dst_packet_relative_times)
        #flow.udps.src2dst_min_packet_relative_times              = stats.min()
        #flow.udps.src2dst_max_packet_relative_times              = stats.max()
        flow.udps.src2dst_mean_packet_relative_times             = stats.average()
        flow.udps.src2dst_stddev_packet_relative_times           = stats.std_deviation()
        flow.udps.src2dst_variance_packet_relative_times         = stats.variance()
        flow.udps.src2dst_coeff_of_var_packet_relative_times     = stats.coeff_of_variation()
        flow.udps.src2dst_skew_from_median_packet_relative_times = stats.skew_from_median()
        # dst -> src
        stats = IterableStats(flow.udps.dst2src_packet_relative_times)
        #flow.udps.dst2src_min_packet_relative_times              = stats.min()
        #flow.udps.dst2src_max_packet_relative_times              = stats.max()
        flow.udps.dst2src_mean_packet_relative_times             = stats.average()
        flow.udps.dst2src_stddev_packet_relative_times           = stats.std_deviation()
        flow.udps.dst2src_variance_packet_relative_times         = stats.variance()
        flow.udps.dst2src_coeff_of_var_packet_relative_times     = stats.coeff_of_variation()
        flow.udps.dst2src_skew_from_median_packet_relative_times = stats.skew_from_median()
        
        # Cleanup        
        del stats
        del flow.udps.bidirectional_packet_relative_times
        del flow.udps.src2dst_packet_relative_times
        del flow.udps.dst2src_packet_relative_times

class ResReqDiffTime(NFPlugin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_init(self, packet, flow):
        '''
        Credit: This pluguin is implemented by OSF-EIMTC https://github.com/ArielCyber/OSF-EIMTC
        on_init(self, packet, flow): Method called at flow creation.
        '''
        flow.udps.req_res_time_diff = list() 
        flow.udps.current_flow_direction = 0 # 0 for forward, 1 for backward
        flow.udps.current_flow_direction_timestamp = packet.time
        flow.udps.min_req_res_time_diff = 0
        flow.udps.max_req_res_time_diff = 0
        flow.udps.mean_req_res_time_diff = 0
        flow.udps.stddev_req_res_time_diff = 0
        flow.udps.variance_req_res_time_diff = 0
        flow.udps.coeff_of_var_req_res_time_diff = 0
        flow.udps.skew_from_median_req_res_time_diff = 0

    def on_update(self, packet, flow):
        if packet.direction != flow.udps.current_flow_direction:
            flow.udps.req_res_time_diff.append(packet.time - flow.udps.current_flow_direction_timestamp)
            flow.udps.current_flow_direction = packet.direction
            flow.udps.current_flow_direction_timestamp = packet.time

    def on_expire(self, flow): 
        stats = IterableStats(flow.udps.req_res_time_diff)
        flow.udps.min_req_res_time_diff = stats.min()
        flow.udps.max_req_res_time_diff = stats.max()
        flow.udps.mean_req_res_time_diff = stats.average()
        flow.udps.median_req_res_time_diff = stats.median()
        flow.udps.stddev_req_res_time_diff = stats.std_deviation()
        flow.udps.variance_req_res_time_diff = stats.variance()
        flow.udps.coeff_of_var_req_res_time_diff = stats.coeff_of_variation()
        flow.udps.skew_from_median_req_res_time_diff = stats.skew_from_median()
        
        # Cleanup
        del stats
        del flow.udps.current_flow_direction_timestamp
        del flow.udps.current_flow_direction
        del flow.udps.req_res_time_diff 
        

class SmallPacketPayloadRatio(NFPlugin):
    '''
    Credit: This plugin is implemented by OSF-EIMTC https://github.com/ArielCyber/OSF-EIMTC
    The ratio of the number of small packets for direction X to the total number of packets
    in direction X, for each direction x in {src2dst, dst2src}.

    Attributes:
        small_size (int): The size (in bytes) of the payload that a packet is considered small (i.e., payload size < small_size).
        flow.src2dst_small_packet_payload_packets (int): Number of small packets from source to destination.
        flow.src2dst_small_packet_payload_ratio (float): Ratio of small packets from source to destination.
        flow.dst2src_small_packet_payload_packets (int): Number of small packets from destination to source.
        flow.dst2src_small_packet_payload_ratio (float): Ratio of small packets from destination to source.
    '''
    def __init__(self, small_size = 32, **kwargs):
        '''
            small_size: the size (in bytes) of the payload that
            a packet is considered to be small (i.e, payload size < small_size).
        '''
        super().__init__(**kwargs)
        self.small_size = small_size

    def on_init(self, packet, flow):
        '''
        on_init(self, packet, flow): Method called at flow creation.
        '''
        flow.udps.src2dst_small_packet_payload_packets = 0
        flow.udps.src2dst_small_packet_payload_ratio   = 0
        flow.udps.dst2src_small_packet_payload_packets = 0
        flow.udps.dst2src_small_packet_payload_ratio   = 0
        

        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.payload_size < self.small_size:
            if packet.direction == 0: # src2dst
                flow.udps.src2dst_small_packet_payload_packets += 1
            else:
                flow.udps.dst2src_small_packet_payload_packets += 1

    def on_expire(self, flow):
        if flow.src2dst_packets != 0:
            flow.udps.src2dst_small_packet_payload_ratio = (flow.udps.src2dst_small_packet_payload_packets 
                                                            / flow.src2dst_packets)
        if flow.dst2src_packets != 0:
            flow.udps.dst2src_small_packet_payload_ratio = (flow.udps.dst2src_small_packet_payload_packets
                                                            / flow.dst2src_packets)
