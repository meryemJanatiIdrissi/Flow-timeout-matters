# feature extrator (NFStream-based)
Feature Extractor for NetFlow features extraction based on NFStream. It implements several `NFPlugin` for extracting protocol-specific features and global NetFlow features:
`

## Usage

### Export NetFlow from PCAP files without pickle bytes to pandas DataFrame

```python
from streamer import NFStreamer
my_streamer = NFStreamer(source="path/to/pcap/file.pcap", # or network interface
                         idle_timeout=120,
                         active_timeout=1800,
                         export_bytes = False)
                         
# Export the NF to a dataframe

df = my_streamer.to_pandas()
```

### Export NetFlow from PCAP files without pickle bytes to csv file

```python
from streamer import NFStreamer
my_streamer = NFStreamer(source="path/to/pcap/file.pcap", # or network interface
                         idle_timeout=120,
                         active_timeout=1800,
                         export_bytes = False)
                         
# Export the NF to a dataframe

df = my_streamer.to_csv('path/to/output_file.csv')
```

### Arguments
- `source` [default=None]: Packet capture source. Pcap file path, list of pcap file paths (considered as a single file), or network interface name.
- `decode_tunnels` [default=True]: Enable/Disable GTP/CAPWAP/TZSP tunnels decoding.
- `bpf_filter` [default=None]: Specify a BPF filter for filtering selected traffic.
- `promiscuous_mode` [default=True]: Enable/Disable promiscuous capture mode.
- `snapshot_length` [default=1536]: Control packet slicing size (truncation) in bytes.
- `idle_timeout` [default=120]: Flows that are idle (no packets received) for more than this value in seconds are expired.
- `active_timeout` [default=1800]: Flows that are active for more than this value in seconds are expired.
- `accounting_mode` [default=0]: Specify the accounting mode that will be used to report bytes-related features (0: Link layer, 1: IP layer, 2: Transport layer, 3: Payload).
- `udps` [default=None]: Specify user-defined NFPlugins used to extend NFStreamer (see `feature_extractor/streamer.py`).
- `n_dissections` [default=20]: Number of per flow packets to dissect for L7 visibility feature. When set to 0, L7 visibility feature is disabled.
- `statistical_analysis` [default=False]: Enable/Disable post-mortem flow statistical analysis.
- `splt_analysis` [default=0]: Specify the sequence of first packets length for early statistical analysis. When set to 0, splt_analysis is disabled.
- `max_nflows` [default=0]: Specify the number of maximum flows to capture before returning. Unset when equal to 0.
- `n_meters` [default=0]: Specify the number of parallel metering processes. When set to 0, NFStreamer will automatically scale metering according to available physical cores on the running host.
- `performance_report` [default=0]: Performance report interval in seconds. Disabled when set to 0. Ignored for offline capture.
- `system_visibility_mode` [default=0]: Enable system process mapping by probing the host machine.
- `system_visibility_poll_ms` [default=100]: Set the polling interval in milliseconds for system process mapping feature (0 is the maximum achievable rate).
