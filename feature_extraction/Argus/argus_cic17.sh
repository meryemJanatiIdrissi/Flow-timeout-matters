#!/bin/bash


echo -n "Processing USTC-TFC2016 dataset ... "

PCAP_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cic17/pcaps"
OUTPUT_BASE_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cic17/Argus"


# List of timeout values
TIMEOUT_VALUES=(default 0.5 1 2 3 4 5 6 10 30 60) 



for timeout in "${TIMEOUT_VALUES[@]}"; do
    timeout_in_seconds=$(echo "$timeout * 60" | bc)
# Create or overwrite the Argus configuration file
    cat <<EOL > argus.conf
ARGUS_IP_TIMEOUT=$timeout_in_seconds
ARGUS_TCP_TIMEOUT=$timeout_in_seconds
ARGUS_ICMP_TIMEOUT=$timeout_in_seconds
ARGUS_IGMP_TIMEOUT=$timeout_in_seconds
ARGUS_FRAG_TIMEOUT=$timeout_in_seconds
ARGUS_ARP_TIMEOUT=$timeout_in_seconds
ARGUS_OTHER_TIMEOUT=$timeout_in_seconds
EOL

    echo "Configuration file 'argus.conf' created with common timeout value: $timeout"

    if [[ "$timeout" == "default" ]]; then
        ARGUS_OUTPUT_DIR="$OUTPUT_BASE_DIR/$timeout/argus"
        FEATURES_OUTPUT_DIR="$OUTPUT_BASE_DIR/$timeout/features"
    else
        ARGUS_OUTPUT_DIR="$OUTPUT_BASE_DIR/timeout$timeout/argus"
        FEATURES_OUTPUT_DIR="$OUTPUT_BASE_DIR/timeout$timeout/features"
    fi


    # Ensure the output directories exist
    mkdir -p "$ARGUS_OUTPUT_DIR"
    mkdir -p "$FEATURES_OUTPUT_DIR"

    echo "_____________________ Dir ${ARGUS_OUTPUT_DIR}"
    echo "----------------- Dir ${FEATURES_OUTPUT_DIR}"

    # Iterate over each pcap file in the directory
    for pcap_file in "$PCAP_DIR"/*.pcap; do
        # Get the base name of the pcap file (without the directory and extension)
        base_name=$(basename "$pcap_file" .pcap)

        # Define the output file names
        argus_output_file="$ARGUS_OUTPUT_DIR/${base_name}.argus"
        features_output_file="$FEATURES_OUTPUT_DIR/${base_name}_features.csv"

        # Process the pcap file with Argus
        echo "Processing $pcap_file with Argus..."
        if [[ "$timeout" == "default" ]]; then
            argus -r "$pcap_file" -w "$argus_output_file" # With default parameters
        else
            argus -F argus.conf -r "$pcap_file" -w "$argus_output_file"
        fi



        echo "Extracting all features from $argus_output_file..."
        ra -r "$argus_output_file" -s srcid rank stime ltime trans flgs seq dur runtime idle mean stddev sum min max smac dmac soui doui saddr daddr proto sport dport stos dtos sdsb ddsb sco dco sttl dttl shops dhops sipid dipid smpls dmpls autoid sas das ias cause nstroke snstroke dnstroke pkts spkts dpkts bytes sbytes dbytes appbytes sappbytes dappbytes pcr load sload dload loss sloss dloss ploss psloss pdloss retrans sretrans dretrans pretrans psretrans pdretrans sgap dgap rate srate drate dir sintpkt sintdist sintpktact sintdistact sintpktidl sintdistidl dintpkt dintdist dintpktact dintdistact dintpktidl dintdistidl sjit sjitact sjitidle djit djitact djitidle state label suser duser swin dwin svlan dvlan svid dvid svpri dvpri srng erng stcpb dtcpb tcprtt synack ackdat tcpopt -c , > "$features_output_file"


        echo "Features extracted to $features_output_file"
    done
    rm -rf "$ARGUS_OUTPUT_DIR"
done



echo "All pcap files have been processed and features extracted."
