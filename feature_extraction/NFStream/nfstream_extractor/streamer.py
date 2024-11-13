from nfstream import NFStreamer as nfs
from plugins.dns import AuxDNSFeatures
from plugins.ftp import AuxFTPFeatures
from plugins.icmp import AuxICMPFeatures
from plugins.ip import AuxPktMinMaxSizeFeatures
from plugins.statistics import AuxPktSizeFeatures, AuxSecBytesFeatures, FirstPacketPayloadLen, Packets_size_and_interarrival_time, \
                                FLowPayloadFeatures, MostFreqPayloadLenRatio, PacketRelativeTime, ResReqDiffTime,  SmallPacketPayloadRatio, \
                                RecvSentPacketRatio
                                
from plugins.tcp import AuxTCPFlagsFeatures, AuxRetransmissionCounter, AuxTCPWindowMinMAx, FlowTCPHandshake, FlowTCPTermination
import dpkt

def get_snapshot_length(file, snapshot_length):
    """
    Get the snapshot length from a pcap file.

    Args:
        file (str): Path to the pcap file.
        snapshot_length (int): Default snapshot length.

    Returns:
        int: The snapshot length from the pcap file if successful, otherwise the default snapshot length.
    """
    try:
        f = open(file, 'rb')
        pcap = dpkt.pcap.Reader(f)
        snaplen = pcap.snaplen
        f.close()
    except:
        return snapshot_length
        
    return snaplen



def NFStreamer(source,
                         decode_tunnels=True,
                         bpf_filter=None,
                         promiscuous_mode=False,
                         snapshot_length=1536,
                         idle_timeout=120,
                         active_timeout=1800,
                         accounting_mode=1,
                         n_dissections=20,
                         statistical_analysis=True,
                         splt_analysis=0,
                         n_meters=0,
                         performance_report=0,
                         ):
    """
    Create an NFStreamer instance for streaming and processing network packets.

    Args:
        source (str): Source of the network packets.
        decode_tunnels (bool, optional): Whether to decode tunneling protocols. Defaults to True.
        bpf_filter (str, optional): BPF filter for packet selection. Defaults to None.
        promiscuous_mode (bool, optional): Whether to use promiscuous mode for capturing packets. Defaults to False.
        snapshot_length (int, optional): Maximum number of bytes to capture per packet. Defaults to 1536.
        idle_timeout (int, optional): Timeout for idle flows. Defaults to 120.
        active_timeout (int, optional): Timeout for active flows. Defaults to 1800.
        accounting_mode (int, optional): Mode for accounting. Defaults to 1.
        n_dissections (int, optional): Number of dissections. Defaults to 20.
        statistical_analysis (bool, optional): Whether to perform statistical analysis on packets. Defaults to True.
        splt_analysis (int, optional): Splt analysis parameter. Defaults to 0.
        n_meters (int, optional): Number of meters. Defaults to 0.
        performance_report (int, optional): Whether to generate a performance report. Defaults to 0.

    Returns:
        nfs: An instance of NFStreamer configured with the provided parameters.
    """
    
    if not promiscuous_mode:
        snapshot_length = get_snapshot_length(source, snapshot_length)
    
    udps_plugins = [AuxPktSizeFeatures(), AuxPktMinMaxSizeFeatures(), AuxTCPFlagsFeatures(),
                        AuxTCPWindowMinMAx(), AuxICMPFeatures(), AuxDNSFeatures(), AuxFTPFeatures(),
                        AuxRetransmissionCounter(), AuxSecBytesFeatures(), FlowTCPHandshake(),
                        FlowTCPTermination(), FirstPacketPayloadLen(), FLowPayloadFeatures(), RecvSentPacketRatio(),
                        MostFreqPayloadLenRatio(), Packets_size_and_interarrival_time(), PacketRelativeTime(), ResReqDiffTime(),
                        SmallPacketPayloadRatio()]

    return nfs(source=source,
                decode_tunnels=decode_tunnels,
                bpf_filter=bpf_filter,
                promiscuous_mode=promiscuous_mode,
                snapshot_length=snapshot_length,
                idle_timeout=idle_timeout,
                active_timeout=active_timeout,
                accounting_mode=accounting_mode,
                n_dissections=n_dissections,
                statistical_analysis=statistical_analysis,
                splt_analysis=splt_analysis,
                udps=udps_plugins,
                n_meters=n_meters,
                performance_report=performance_report)