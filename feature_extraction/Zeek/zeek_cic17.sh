#!/bin/bash

echo -n "Processing CIC-IDS2017 dataset ... "

PCAP_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cic17/pcaps"
OUTPUT_BASE_DIR="/home/janati/Desktop/Meryem/IDS-Datasets/Datasets/cic17/Zeek"


# List of timeout values
TIMEOUT_VALUES=(default 0.5 1 2 3 4 5 6 10 30 60)

# Function to process a single pcap file
process_pcap() {
    local pcap_file=$1
    local timeout=$2
    local OUTPUT_DIR=$3 
    mkdir -p "$OUTPUT_DIR" # Ensure the output directory exists
    echo "timeout ${timeout}"
    
    local base_name=$(basename "$pcap_file" .pcap)
    local temp_output_dir="${OUTPUT_DIR}/${base_name}_temp"

    # Create a temporary output directory for each pcap file
    mkdir -p "$temp_output_dir"

    # Create or update the Zeek script to use the temporary output directory
    cat <<EOL > custom_timeout.zeek
@load base/frameworks/logging
redef Log::default_logdir = "$temp_output_dir";
EOL


    # Run Zeek with the custom script and pcap file
    if [[ "${timeout}" == "default" ]]; then
        echo 'AM i here'
        zeek -C -r "$pcap_file" custom_timeout.zeek  # With default parameters
    else
        echo 'or here'
        zeek -C -r "$pcap_file" custom_timeout.zeek  tcp_inactivity_timeout=${timeout}mins udp_inactivity_timeout=${timeout}mins  icmp_inactivity_timeout=${timeout}mins
    fi
    

    # Rename the output files
    for log_file in "$temp_output_dir"/*.log; do
        mv "$log_file" "${OUTPUT_DIR}/${base_name}_$(basename "$log_file")"
    done
    # Remove the temporary output directory
    rm -r "$temp_output_dir"
}



for timeout in "${TIMEOUT_VALUES[@]}"; do
    if [[ "$timeout" == "default" ]]; then
        output_dir="$OUTPUT_BASE_DIR/$timeout/logs"
    else
        output_dir="$OUTPUT_BASE_DIR/timeout$timeout/logs"
    fi

    # Iterate over each pcap file in the directory and process them
    for pcap_file in "$PCAP_DIR"/*.pcap; do
        process_pcap "$pcap_file" "$timeout" "$output_dir"
        echo "Done processing file $pcap_file"
    done
    PARENT_PATH=$(dirname "$output_dir")

    /usr/bin/cp -R ${PARENT_PATH}/logs/ ${PARENT_PATH}/conn_logs/ && /usr/bin/find ${PARENT_PATH}/conn_logs/ -type f ! -name "*conn.*" -delete
done


echo "Processing complete. Output files renamed and stored"
