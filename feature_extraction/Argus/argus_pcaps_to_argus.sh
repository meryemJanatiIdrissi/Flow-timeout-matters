#!/bin/bash


echo -n "Type 1 for USTC, 2 for CIC17, 3 for UNSW, 4 for CUPID: "
read VAR

if [[ $VAR -eq 1 ]]
then
  PCAP_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/ustc/pcaps/Malware"
  ARGUS_OUTPUT_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/ustc/Argus/timeout60/Malware/argus"
  FEATURES_OUTPUT_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/ustc/Argus/timeout60/Malware/features"
  
elif [[ $VAR -eq 2 ]]
then
 
  PCAP_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cic17/pcaps"
  ARGUS_OUTPUT_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cic17/Argus/default/argus"
  FEATURES_OUTPUT_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cic17/Argus/default/features"
  
elif [[ $VAR -eq 3 ]]
then
  PCAP_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/unsw/pcaps/22-01-2015"
  ARGUS_OUTPUT_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/unsw/Argus/22-01-2015/default/argus"
  FEATURES_OUTPUT_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/unsw/Argus/22-01-2015/default/features"

elif [[ $VAR -eq 4 ]]
then
  name_dir='AutomaticallyGeneratedAttacks'
  T=30
  
  PCAP_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cupid/pcaps/${name_dir}"
  ARGUS_OUTPUT_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cupid/Argus/default/${name_dir}/argus"
  FEATURES_OUTPUT_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cupid/Argus/default/${name_dir}/features"
fi

echo "Processing Datasets $VAR ... "

# HumanGeneratedBenignData
# HumanGeneratedAttackData
# Baselines
# AutomaticallyGeneratedAttacks


# Ensure the output directories exist
mkdir -p "$ARGUS_OUTPUT_DIR"
mkdir -p "$FEATURES_OUTPUT_DIR"

# Timeout values
COMMON_TIMEOUT=60 # in seconds

# Create or overwrite the Argus configuration file
cat <<EOL > argus.conf
ARGUS_IP_TIMEOUT=$COMMON_TIMEOUT
ARGUS_TCP_TIMEOUT=$COMMON_TIMEOUT
ARGUS_ICMP_TIMEOUT=$COMMON_TIMEOUT
ARGUS_IGMP_TIMEOUT=$COMMON_TIMEOUT
ARGUS_FRAG_TIMEOUT=$COMMON_TIMEOUT
ARGUS_ARP_TIMEOUT=$COMMON_TIMEOUT
ARGUS_OTHER_TIMEOUT=$COMMON_TIMEOUT
EOL

echo "Configuration file 'argus.conf' created with common timeout value: $COMMON_TIMEOUT"


# Iterate over each pcap file in the directory
for pcap_file in "$PCAP_DIR"/*.pcapng; do
    # Get the base name of the pcap file (without the directory and extension)
    base_name=$(basename "$pcap_file" .pcapng)
    
    # Define the output file names
    argus_output_file="$ARGUS_OUTPUT_DIR/${base_name}.argus"
    features_output_file="$FEATURES_OUTPUT_DIR/${base_name}_features.csv"
    
    # Process the pcap file with Argus
    echo "Processing $pcap_file with Argus..."
    #argus -F argus.conf -r "$pcap_file" -w "$argus_output_file"
    argus -r "$pcap_file" -w "$argus_output_file"
    
    echo "Extracting all features from $argus_output_file..."
    ra -r "$argus_output_file" -s srcid rank stime ltime trans flgs seq dur runtime idle mean stddev sum min max smac dmac soui doui saddr daddr proto sport dport stos dtos sdsb ddsb sco dco sttl dttl shops dhops sipid dipid smpls dmpls autoid sas das ias cause nstroke snstroke dnstroke pkts spkts dpkts bytes sbytes dbytes appbytes sappbytes dappbytes pcr load sload dload loss sloss dloss ploss psloss pdloss retrans sretrans dretrans pretrans psretrans pdretrans sgap dgap rate srate drate dir sintpkt sintdist sintpktact sintdistact sintpktidl sintdistidl dintpkt dintdist dintpktact dintdistact dintpktidl dintdistidl sjit sjitact sjitidle djit djitact djitidle state label suser duser swin dwin svlan dvlan svid dvid svpri dvpri srng erng stcpb dtcpb tcprtt synack ackdat tcpopt -c , > "$features_output_file"
  
    
    echo "Features extracted to $features_output_file"
done
rm -rf "$ARGUS_OUTPUT_DIR"

echo "All pcap files have been processed and features extracted."
