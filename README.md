# threatHunt_pcaps.sh

## Overview

The `threatHunt_pcaps.sh` script is designed to quickly parse multiple pcap files in a directory for threat hunting. It includes various functions that analyze different 
aspects of the network traffic, such as strange ports, GeoIP country codes, DNS queries, user agents, TLS versions, NMAP scans, and file extraction.

## Usage

1. **Place Script in Directory**: Put the script in the same directory as the pcap files you want to analyze.
2. **Make Executable**: Make the script executable using:
    ```bash
    chmod +x ./threatHunt_pcaps.sh
    ```
3. **Run the Script**:
    ```bash
    ./threatHunt_pcaps.sh
    ```

## Results

After running the script, you will find results organized into labeled directories such as `strangeports`, `badCountryGeoIP`, `allCountryGeoIP`, `dns`, `userAgents`, 
`outdatedTLSVersions`, and `nmapScans`.

## Functions

The script includes several functions that can be enabled/disabled *(#comment out)* at the bottom of the file. Here are the main functions:

- **getStrangePorts**: Analyzes ports and outputs results to `./strangeports`.
- **getBadCountryCodes**: Identifies GeoIP data from 'bad' countries (CN, RU, NK) and outputs results to `./badCountryGeoIP`.
- **getAllCountryCodes**: Extracts all GeoIP country codes and outputs results to `./allCountryGeoIP`.
- **getDns**: Parses DNS queries and outputs results to `./dns`.
- **getUserAgents**: Analyzes HTTP user agents and outputs results to `./userAgents`.
- **getTLSversion**: Detects outdated TLS versions (handshakes older than TLS 1.2) and outputs results to `./outdatedTLSVersions`.
- **runNmapDetection**: Identifies NMAP scans in the pcap files and outputs results to `./nmapScans`.
- **extractFiles**: Attempts to extract file objects from HTTP, SMB, and TFTP streams and saves them in `./extractedFiles`.

## Notes

- The script requires `tshark` for parsing pcap files. Ensure it is installed on your system.
- Some functions may require additional configuration, such as setting up the MaxMind GeoIP database.

##  
![alt text](https://github.com/ArronJablonowski/threatHunt_pcaps/blob/main/1.png?raw=true)


* Reveiw the results: 

![alt text](https://github.com/ArronJablonowski/threatHunt_pcaps/blob/main/2.png?raw=true)
