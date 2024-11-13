from nfstream import NFPlugin
from scapy.all import  IP, IPv6

class AuxFTPFeatures(NFPlugin):
    """
    AuxFTPFeatures(NFPlugin)
    Description:
        This plugin extracts FTP flow features

    Attributes:
        Inherits attributes from NFPlugin.
        flow.udps.ftp_command_ret_code: %FTP_COMMAND_RET_CODE FTP client command return code
        flow.udps.ftp_pass_count: Number of 'PASS' commands in FTP flow
        flow.udps.ftp_user_count: Number of 'USER' commands in FTP flow
        flow.udps.ftp_user_logged: Indicates if a user is logged in (1 for True, 0 for False)
        flow.udps.ftp_series_100: Count of FTP command return codes in the 100 series
        flow.udps.ftp_series_200: Count of FTP command return codes in the 200 series
        flow.udps.ftp_series_300: Count of FTP command return codes in the 300 series
        flow.udps.ftp_series_400: Count of FTP command return codes in the 400 series
        flow.udps.ftp_series_500: Count of FTP command return codes in the 500 series
        flow.udps.ftp_series_600: Count of FTP command return codes in the 600 series
        flow.udps.ftp_series_1000: Count of FTP command return codes greater than or equal to 1000

    Methods:
        on_init(self, packet, flow): Method called at flow creation to initialize FTP flow features.
        on_update(self, packet, flow): Method called to update FTP flow features.
        on_expire(self, flow): Method called when FTP flow expires to finalize FTP flow features.
    """

    def on_init(self, packet, flow):
        flow.udps.ftp_command_ret_code = []
        flow.udps.ftp_pass_count = 0
        flow.udps.ftp_user_count = 0
        flow.udps.ftp_user_logged = 0
        
        flow.udps.ftp_series_100 = 0
        flow.udps.ftp_series_200 = 0
        flow.udps.ftp_series_300 = 0
        flow.udps.ftp_series_400 = 0
        flow.udps.ftp_series_500 = 0
        flow.udps.ftp_series_600 = 0
        flow.udps.ftp_series_1000 = 0
        
        if packet.protocol == 6 and (packet.dst_port == 21 or packet.src_port == 21):
            if packet.ip_version == 4:
                s_packet = IP(packet.ip_packet)
            elif packet.ip_version == 6:
                s_packet = IPv6(packet.ip_packet)  
            if hasattr(s_packet.getlayer(2), 'load'):
                try:
                    load = s_packet.getlayer(2).load.decode('utf-8', errors='ignore')
                    if 'PASS' in load:
                        flow.udps.ftp_pass_count += 1
                    if 'USER' in load:
                        flow.udps.ftp_user_count += 1
                    words = load.split()
                    word = words[0] if len(words) > 0 else '-1'
                    numb = int(word) if word.isdigit() else -1
                    if  numb <= 10068 and numb >= 100:
                        flow.udps.ftp_command_ret_code.append(numb)
                except:
                    pass
        
    def on_update(self, packet, flow):
        if packet.protocol == 6 and (packet.dst_port == 21 or packet.src_port == 21):
            if packet.ip_version == 4:
                s_packet = IP(packet.ip_packet)
            elif packet.ip_version == 6:
                s_packet = IPv6(packet.ip_packet)  
                
            if hasattr(s_packet.getlayer(2), 'load'):
                try:
                    load = s_packet.getlayer(2).load.decode('utf-8', errors='ignore')
                    if 'PASS' in load:
                        flow.udps.ftp_pass_count += 1
                    if 'USER' in load:
                        flow.udps.ftp_user_count += 1
                    words = load.split()
                    word = words[0] if len(words) > 0 else '-1'
                    numb = int(word) if word.isdigit() else -1
                    if  numb <= 10068 and numb >= 100:
                        flow.udps.ftp_command_ret_code.append(numb)
                except:
                    pass
                    
    def on_expire(self, flow):
        if len(flow.udps.ftp_command_ret_code) > 0:
            
            for value in flow.udps.ftp_command_ret_code:
                if 100 <= value < 200:
                    flow.udps.ftp_series_100 += 1
                elif 200 <= value < 300:
                    flow.udps.ftp_series_200 += 1
                elif 300 <= value < 400:
                    flow.udps.ftp_series_300 += 1
                elif 400 <= value < 500:
                    flow.udps.ftp_series_400 += 1
                elif 500 <= value < 600:
                    flow.udps.ftp_series_500 += 1
                elif 600 <= value < 10000:
                    flow.udps.ftp_series_600 += 1
                elif value >= 10000:
                    flow.udps.ftp_series_1000 +=1       
    
            if 230 in flow.udps.ftp_command_ret_code or 232 in flow.udps.ftp_command_ret_code:
                flow.udps.ftp_user_logged = 1 
            flow.udps.ftp_command_ret_code = flow.udps.ftp_command_ret_code[-1]
        else:
            flow.udps.ftp_command_ret_code = 0