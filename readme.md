<p align="center">
  <img src="https://github.com/user-attachments/assets/4893c298-dd62-4d8e-90e0-b4ccf77d74ce" width="25%">
</p>

# Wireshark Lua Plugins

This repository contains a collection of Lua scripts designed to extend Wireshark's functionality. These plugins facilitate enhanced packet analysis and provide additional insights into network traffic.

## Plugins Overview

1. **check_asn.lua**:  
   - Uses an external ASN (Autonomous System Number) database in TSV format to enrich packet data with ASN information.  
   - The required database file can be downloaded from [this link](https://iptoasn.com/data/ip2asn-v4.tsv.gz) and extracted before use.
   - You must indicate the path to the tsv file with the ASN database in the script.
   - Once the plugin is loaded, it is ready for use without additional actions, automatically adding an `asn` field to packet details.  

2. **check_ipinfo.lua**:  
   - Enhances packet details by fetching comprehensive IP information from external services (https://ipinfo.io), including geolocation, ISP details, and more.  
   - Requires an internet connection for real-time lookups.  

3. **rtp_h265_typ33_extractor.lua**:  
   - A specialized dissector that processes RTP packets carrying H.265 streams (payload type 33).  
   - Extracts h.265 stream from pcap file and saves to new file. Can be played later e.g. in VLC.

4. **ja3_tls.lua**:
   - This Lua script is a Wireshark plugin for analyzing TLS traffic.
   - It extracts JA3 and JA3S fingerprints from ClientHello and ServerHello messages and displays them in the packet details tree.
   - The script also performs basic anomaly detection, such as spotting possible data exfiltration or large downloads.
   - Additionally, it provides a Tools menu option to export all collected session statistics into a CSV file on the user’s Desktop.

## Installation

To utilize these plugins in Wireshark, place the Lua scripts in the appropriate directory based on your operating system:

- **macOS:** `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`  
- **Windows:** `C:\Program Files\Wireshark\Plugins\`  
- **Linux:** `/usr/lib/wireshark/plugins/`  

## Applying Changes Without Restarting

Instead of restarting Wireshark, you can reload the Lua plugins dynamically:

- Go to **Analyze -> Reload Lua Plugins** to apply changes without restarting.

## Usage

- Once installed, the plugins will automatically process relevant packets during capture or analysis.
- For **check_ipinfo.lua**, a **Check IPinfo** button will appear in the **Tools** menu to activate its functionality.
- For **rtp_h265_typ33_extractor.lua**, an **Extract H265 from RTP** button will appear in the **Tools** menu to enable extraction.
- **check_asn.lua** automatically adds an `asn` field to packet details and is ready for use immediately after loading, requiring no additional actions beyond placing the pre-downloaded database in the correct location.
- **ja3_tls.lua** automatically adds an `TLS JA3/JA3S Analysis` field to packet details and is ready for use immediately after loading. To export all fingerprints and session statistics go to menu Tools → Export JA3 Analysis. A CSV file named tls_fingerprints.csv will be saved on your Desktop.

## Compatibility

These scripts are developed and tested for Wireshark versions 4.4.3 or later.

## Contributing

Contributions are welcome! If you have improvements or additional scripts to share:

1. Fork this repository.
2. Create a new branch for your feature or fix.
3. Commit your changes with clear descriptions.
4. Push to your branch and submit a pull request.


---

*Note: These plugins are provided as-is. Ensure you understand the functionality of each script before use, especially in production environments.*
