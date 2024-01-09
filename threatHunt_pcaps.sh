## !/usr/bin/bash 
##
## threatHunt_pcaps.sh is used to quickly parse multiple pcap files in a directory for threat hunting.  
##          
## Usage: 
##    Put this script in the same directory as PCAPs to be analyzed. Then: 
##    ~/$ chmod +x ./threatHunt_pcaps.sh
##    ~/$ ./threatHunt_pcaps.sh  
##
## Notes: 
##  IF Modifying - 
##   TShark Filters that use "{}" on Ubuntu don't like commas for seperators. ie. {1,2,3}. Use a space instead. 
##   TShark Filters on MacOS will use commas in filters. ie. {1,2,3}
##
 

### GET STRANGE PORTS ###
getStrangePorts () {
    echo "Analyzing Ports"
    mkdir -p ./strangeports
    # Get all NON TCP Ports and all TCP Ports that are not in filter {} 
    for f in *.pcap*; do tshark -r $f -Y "!tcp.port in {22 23 25 80 443 445 993 995 8000..8005}" -w ./strangeports/strangeports-$f;done 
    mergecap -w ./strangeports/allstrangeports.pcapng ./strangeports/* 
    rm ./strangeports/strangeports-* 

}

### GeoIP Country Codes ###
getBadCountryCodes () {
    echo "Analyzing GEO IPs"
    mkdir -p ./badcountryGeoIP
    # Find any GeoIP data to weird countries
    for f in *.pcap*; do tshark -r $f -Y "ip.geoip.country_iso in {CN RU NK}" -w ./badcountryGeoIP/badcountryGeoIP-$f;done 
    mergecap -w ./badcountryGeoIP/allbadcountryGeoIP.pcapng ./badcountryGeoIP/* 
    rm ./badcountryGeoIP/badcountryGeoIP-*
}

### GET ALL DNS #### 
getDns () {
    echo "Analyzing DNS"
    mkdir -p ./dns
    for f in *.pcap*; do tshark -r $f -Y "dns" -w ./dns/dns-$f;done 
    mergecap -w ./dns/alldns.pcapng ./dns/* 
    # Stack (longtail) all DNS by source IP 
    tshark -r ./dns/alldns.pcapng -T fields -e ip.src -e dns.qry.name -R "dns.flags.response eq 0" -2 | sort | uniq -c | sort -nr > ./dns/allDnsStackedByIP.txt
    # Stack (longtail) all DNS Names 
    tshark -r ./dns/alldns.pcapng -T fields -e dns.qry.name -R "dns.flags.response eq 0" -2 | sort | uniq -c | sort -nr > ./dns/allDnsNamesStacked.txt
    rm ./dns/dns-*

}

### User Agents ###
getUserAgents () {
    echo "Analyzing User Agents"
    mkdir -p ./userAgents
    # Get all User Agents 
    for f in *.pcap*; do tshark -r $f -Y "http.user_agent" -w ./userAgents/userAgents-$f;done 
    mergecap -w ./userAgents/alluserAgents.pcapng ./userAgents/* 
    # Stack (longtail) all User Agents into a text file 
    tshark -r ./userAgents/alluserAgents.pcapng -Y "http.user_agent" -T fields -e http.user_agent | sort | uniq -c | sort -nr > ./userAgents/alluserAgentsStack.txt
    rm ./userAgents/userAgents-*

}

### OLD TLS Versions ###
getTLSversion () {
    echo "Analyzing TLS Versions"
    mkdir -p ./outdatedTLSVersions
    #Get outdated TLSVersions (handshakes) older than TLS version 1.2 (0x0303) 
    for f in *.pcap*; do tshark -r $f -Y "tls.handshake.version < 0x0303" -w ./outdatedTLSVersions/outdatedTLSVersions-$f;done 
    mergecap -w ./outdatedTLSVersions/alloutdatedTLSVersions.pcapng ./outdatedTLSVersions/* 
    rm ./outdatedTLSVersions/outdatedTLSVersions-*

}

### Detect NMAP Scans ###
runNmapDetection () {
    echo "Running NMAP Detection"
    mkdir -p ./nmapScans
    # Attempt to find NMAP scans in the PCAP file
    for f in *.pcap*; do tshark -r $f -Y "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size<=1024" -w ./nmapScans/nmapScans-$f;done 
    mergecap -w ./nmapScans/allnmapScans.pcapng ./nmapScans/* 
    rm ./nmapScans/nmapScans-*

}

### Extract File Objects ###
extractFiles () {
    echo "Extracting File Objects"
    mkdir -p ./extractedFiles
    # Attempt to extract files from Http
    mkdir -p ./extractedFiles/http 
    echo " -- Analyzing http streams"
    for f in *.pcap*; do tshark -n -r $f -q --export-objects http,./extractedFiles/http/ > /dev/null 2>&1;done 
    # Attempt to extract files from Smb
    mkdir -p ./extractedFiles/smb
    echo " -- Analyzing smb streams"
    for f in *.pcap*; do tshark -n -r $f -q --export-objects smb,./extractedFiles/smb/ > /dev/null 2>&1;done
    # Attempt to extract files from Tftp
    mkdir -p ./extractedFiles/tftp
    echo " -- Analyzing tftp streams"
    for f in *.pcap*; do tshark -n -r $f -q --export-objects tftp,./extractedFiles/tftp/ > /dev/null 2>&1;done

}

##########################
### FUNCTIONS RUN HERE ###
##########################
getDns
getStrangePorts
getBadCountryCodes
getUserAgents
getTLSversion
runNmapDetection
extractFiles

echo " "
echo " Script Complete."
echo " "
