#!/usr/bin/env bash
set -euo pipefail

VERSION="2.0.0"

INPUT_DIR="."
OUTPUT_DIR=""
MODULES="dns,strangeports,geoip,useragents,tls,nmap,extract,http,beaconing,scans,ioc"
WATCH_COUNTRIES="CN,RU,KP"
SAFE_PORTS="21,22,23,25,53,80,110,123,143,443,445,587,993,995,3389,8000-8005"
IOC_FILE=""
YARA_RULES=""
OVERWRITE=0
KEEP_TEMP=0

usage() {
    cat <<'USAGE'
threatHunt_pcaps.sh - quick PCAP triage for incident responders

Usage:
  ./threatHunt_pcaps.sh [options]

Options:
  -i, --input-dir DIR       Directory containing .pcap/.pcapng files (default: .)
  -o, --output-dir DIR      Output directory (default: ./threatHunt_results_<timestamp>)
  -m, --modules LIST        Comma-separated modules to run
                            default: dns,strangeports,geoip,useragents,tls,nmap,extract,http,beaconing,scans,ioc
                            optional: zeek,suricata,yara
  -c, --countries LIST      Watchlisted ISO country codes (default: CN,RU,KP)
  -p, --safe-ports LIST     Comma-separated common TCP/UDP ports/ranges (default includes 21,22,53,80,443,445)
      --ioc-file FILE       File with IPs, domains, JA3/JA4 hashes, or User-Agent strings
      --yara-rules FILE     YARA rules file or directory for extracted file triage
      --overwrite           Remove an existing output directory before running
      --keep-temp           Keep per-module temporary PCAPs
  -h, --help                Show this help
  -v, --version             Show version

Examples:
  ./threatHunt_pcaps.sh -i ./captures -o ./case-001-results --ioc-file ./iocs.txt
  ./threatHunt_pcaps.sh --modules dns,tls,http,beaconing,zeek
USAGE
}

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

while (($#)); do
    case "$1" in
        -i|--input-dir) INPUT_DIR="${2:-}"; shift 2 ;;
        -o|--output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
        -m|--modules) MODULES="${2:-}"; shift 2 ;;
        -c|--countries) WATCH_COUNTRIES="${2:-}"; shift 2 ;;
        -p|--safe-ports) SAFE_PORTS="${2:-}"; shift 2 ;;
        --ioc-file) IOC_FILE="${2:-}"; shift 2 ;;
        --yara-rules) YARA_RULES="${2:-}"; MODULES="${MODULES},yara"; shift 2 ;;
        --overwrite) OVERWRITE=1; shift ;;
        --keep-temp) KEEP_TEMP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -v|--version) printf 'threatHunt_pcaps.sh %s\n' "$VERSION"; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ -d "$INPUT_DIR" ]] || die "Input directory does not exist: $INPUT_DIR"
INPUT_DIR="$(cd "$INPUT_DIR" && pwd)"

if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$INPUT_DIR/threatHunt_results_$(date '+%Y%m%d_%H%M%S')"
fi
if [[ "$OUTPUT_DIR" != /* ]]; then
    OUTPUT_DIR="$(pwd)/$OUTPUT_DIR"
fi

if [[ -e "$OUTPUT_DIR" && "$OVERWRITE" -ne 1 ]]; then
    die "Output directory already exists: $OUTPUT_DIR (use --overwrite or choose another path)"
fi
if [[ -e "$OUTPUT_DIR" && "$OVERWRITE" -eq 1 ]]; then
    rm -rf "$OUTPUT_DIR"
fi
mkdir -p "$OUTPUT_DIR"

MANIFEST="$OUTPUT_DIR/run_manifest.txt"
SUMMARY="$OUTPUT_DIR/summary.md"

exec > >(tee -a "$OUTPUT_DIR/run.log") 2> >(tee -a "$OUTPUT_DIR/run.log" >&2)

PCAPS=()
while IFS= read -r -d '' pcap_file; do
    PCAPS+=("$pcap_file")
done < <(find "$INPUT_DIR" -maxdepth 1 -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) -print0)
((${#PCAPS[@]} > 0)) || die "No .pcap or .pcapng files found in $INPUT_DIR"

have tshark || die "tshark is required"
have mergecap || die "mergecap is required"

module_enabled() {
    local needle="$1"
    [[ ",${MODULES}," == *",${needle},"* ]]
}

display_filter_list() {
    local raw="$1"
    local sep="$2"
    local out="" item
    IFS=',' read -r -a items <<< "$raw"
    for item in "${items[@]}"; do
        item="${item// /}"
        [[ -n "$item" ]] || continue
        item="${item/-/..}"
        out+="${out:+$sep}$item"
    done
    printf '%s' "$out"
}

csv_filter_list() {
    display_filter_list "$1" ","
}

space_filter_list() {
    display_filter_list "$1" " "
}

filter_set() {
    local raw="$1"
    if tshark -Y "tcp.port in {1,2}" -r "${PCAPS[0]}" -c 1 >/dev/null 2>&1; then
        printf '{%s}' "$(display_filter_list "$raw" ",")"
    else
        printf '{%s}' "$(display_filter_list "$raw" " ")"
    fi
}

write_manifest() {
    {
        printf 'threatHunt_pcaps version: %s\n' "$VERSION"
        printf 'run started: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'input directory: %s\n' "$INPUT_DIR"
        printf 'output directory: %s\n' "$OUTPUT_DIR"
        printf 'modules: %s\n' "$MODULES"
        printf 'watchlisted countries: %s\n' "$WATCH_COUNTRIES"
        printf 'safe ports: %s\n' "$SAFE_PORTS"
        printf 'ioc file: %s\n' "${IOC_FILE:-none}"
        printf 'yara rules: %s\n' "${YARA_RULES:-none}"
        printf 'tshark: %s\n' "$(tshark -v | head -1)"
        printf 'mergecap: %s\n' "$(mergecap -v | head -1)"
        printf '\ninput files:\n'
        printf '  %s\n' "${PCAPS[@]}"
    } > "$MANIFEST"
}

append_summary() {
    printf '%s\n' "$*" >> "$SUMMARY"
}

start_summary() {
    {
        printf '# PCAP Threat Hunt Summary\n\n'
        printf -- '- Generated: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf -- '- Input directory: `%s`\n' "$INPUT_DIR"
        printf -- '- Output directory: `%s`\n' "$OUTPUT_DIR"
        printf -- '- PCAP files: %s\n' "${#PCAPS[@]}"
        printf -- '- Modules: `%s`\n\n' "$MODULES"
        printf '## Quick Index\n\n'
    } > "$SUMMARY"
}

run_filter_module() {
    local name="$1" filter="$2" out_name="$3"
    local dir="$OUTPUT_DIR/$name" tmp="$OUTPUT_DIR/.tmp/$name" f base outputs=()
    mkdir -p "$dir" "$tmp"
    log "Running $name filter"
    for f in "${PCAPS[@]}"; do
        base="$(basename "$f")"
        if tshark -r "$f" -Y "$filter" -w "$tmp/${out_name}-${base}" >/dev/null 2>&1; then
            if tshark -r "$tmp/${out_name}-${base}" -T fields -e frame.number -c 1 2>/dev/null | grep -q .; then
                outputs+=("$tmp/${out_name}-${base}")
            fi
        else
            warn "$name failed for $base"
        fi
    done
    if ((${#outputs[@]} > 0)); then
        mergecap -w "$dir/all_${out_name}.pcapng" "${outputs[@]}"
        append_summary "- [$name](./$name/all_${out_name}.pcapng)"
    else
        append_summary "- $name: no matching packets"
    fi
}

tshark_fields_all() {
    local filter="$1"
    shift
    local f
    for f in "${PCAPS[@]}"; do
        tshark -n -r "$f" -Y "$filter" -T fields "$@" 2>/dev/null || warn "field extraction failed for $(basename "$f")"
    done
}

top_count() {
    local infile="$1" outfile="$2"
    if [[ -s "$infile" ]]; then
        sort "$infile" | sed '/^[[:space:]]*$/d' | uniq -c | sort -nr > "$outfile"
    else
        : > "$outfile"
    fi
}

module_dns() {
    local dir="$OUTPUT_DIR/dns"
    mkdir -p "$dir"
    run_filter_module "dns" "dns" "dns"
    tshark_fields_all "dns.flags.response == 0 && dns.qry.name" -e ip.src -e dns.qry.name -E separator=$'\t' > "$dir/dns_queries_by_src.tsv"
    tshark_fields_all "dns.flags.response == 0 && dns.qry.name" -e dns.qry.name > "$dir/dns_names.raw"
    top_count "$dir/dns_names.raw" "$dir/top_dns_names.txt"
    awk -F'\t' 'length($2) >= 50 {print}' "$dir/dns_queries_by_src.tsv" | sort | uniq -c | sort -nr > "$dir/long_dns_queries.txt" || true
    tshark_fields_all "dns.flags.rcode == 3" -e ip.src -e dns.qry.name -E separator=$'\t' | sort | uniq -c | sort -nr > "$dir/nxdomain_by_src_name.txt"
    append_summary "  - Top DNS names: [top_dns_names.txt](./dns/top_dns_names.txt)"
    append_summary "  - Long DNS queries: [long_dns_queries.txt](./dns/long_dns_queries.txt)"
    append_summary "  - NXDOMAINs: [nxdomain_by_src_name.txt](./dns/nxdomain_by_src_name.txt)"
}

module_strangeports() {
    local ports
    ports="$(filter_set "$SAFE_PORTS")"
    run_filter_module "strangeports" "(tcp && !(tcp.port in $ports)) || (udp && !(udp.port in $ports))" "strangeports"
    tshark_fields_all "tcp || udp" -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport -E separator=$'\t' \
        | awk -F'\t' '{port=$3 ? $3 : $4; if (port) print $1 "\t" $2 "\t" port}' \
        | sort | uniq -c | sort -nr > "$OUTPUT_DIR/strangeports/top_ports_by_pair.txt"
    append_summary "  - Port counts by pair: [top_ports_by_pair.txt](./strangeports/top_ports_by_pair.txt)"
}

module_geoip() {
    local dir="$OUTPUT_DIR/geoip" countries
    countries="$(filter_set "$WATCH_COUNTRIES")"
    mkdir -p "$dir"
    run_filter_module "geoip/all_countries" "ip.geoip.country_iso" "geoip"
    run_filter_module "geoip/watchlisted_countries" "ip.geoip.country_iso in $countries" "watchlisted_geoip"
    tshark_fields_all "ip.geoip.country_iso" -e ip.src -e ip.dst -e ip.geoip.src_country_iso -e ip.geoip.dst_country_iso -e ip.geoip.src_asnum -e ip.geoip.dst_asnum -e ip.geoip.src_org -e ip.geoip.dst_org -E separator=$'\t' \
        | sort | uniq -c | sort -nr > "$dir/geoip_summary.tsv"
    append_summary "  - GeoIP summary: [geoip_summary.tsv](./geoip/geoip_summary.tsv)"
}

module_useragents() {
    local dir="$OUTPUT_DIR/userAgents"
    mkdir -p "$dir"
    run_filter_module "userAgents" "http.user_agent" "userAgents"
    tshark_fields_all "http.user_agent" -e ip.src -e http.host -e http.user_agent -E separator=$'\t' > "$dir/user_agents.tsv"
    cut -f3 "$dir/user_agents.tsv" | sort | sed '/^[[:space:]]*$/d' | uniq -c | sort -nr > "$dir/top_user_agents.txt"
    append_summary "  - Top User-Agents: [top_user_agents.txt](./userAgents/top_user_agents.txt)"
}

module_tls() {
    local dir="$OUTPUT_DIR/tls"
    mkdir -p "$dir"
    run_filter_module "outdatedTLSVersions" "tls.handshake.version < 0x0303" "outdated_tls"
    tshark_fields_all "tls.handshake.extensions_server_name || tls.handshake.ja3 || tls.handshake.ja4" \
        -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3 -e tls.handshake.ja4 -E separator=$'\t' > "$dir/tls_fingerprints.tsv"
    cut -f3 "$dir/tls_fingerprints.tsv" | sort | sed '/^[[:space:]]*$/d' | uniq -c | sort -nr > "$dir/top_sni.txt"
    cut -f4 "$dir/tls_fingerprints.tsv" | sort | sed '/^[[:space:]]*$/d' | uniq -c | sort -nr > "$dir/top_ja3.txt"
    cut -f5 "$dir/tls_fingerprints.tsv" | sort | sed '/^[[:space:]]*$/d' | uniq -c | sort -nr > "$dir/top_ja4.txt"
    append_summary "- [tls](./tls/tls_fingerprints.tsv)"
    append_summary "  - Top SNI: [top_sni.txt](./tls/top_sni.txt)"
    append_summary "  - Top JA3: [top_ja3.txt](./tls/top_ja3.txt)"
    append_summary "  - Top JA4: [top_ja4.txt](./tls/top_ja4.txt)"
}

module_nmap() {
    run_filter_module "nmapScans" "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024" "nmapScans"
}

module_extract() {
    local dir="$OUTPUT_DIR/extractedFiles" proto f
    mkdir -p "$dir"/{http,smb,tftp}
    log "Extracting HTTP/SMB/TFTP file objects"
    for proto in http smb tftp; do
        for f in "${PCAPS[@]}"; do
            tshark -n -r "$f" -q --export-objects "$proto,$dir/$proto/" >/dev/null 2>&1 || true
        done
    done
    find "$dir" -type f -print0 | while IFS= read -r -d '' f; do
        shasum -a 256 "$f"
    done | sort > "$dir/sha256.txt"
    append_summary "- [extracted files](./extractedFiles/)"
    append_summary "  - SHA256 inventory: [sha256.txt](./extractedFiles/sha256.txt)"
}

module_http() {
    local dir="$OUTPUT_DIR/http"
    mkdir -p "$dir"
    tshark_fields_all "http" -e ip.src -e ip.dst -e http.request.method -e http.host -e http.request.uri -e http.response.code -e http.content_type -e http.server -e http.authorization -e http.user_agent -E separator=$'\t' > "$dir/http.tsv"
    cut -f4 "$dir/http.tsv" | sort | sed '/^[[:space:]]*$/d' | uniq -c | sort -nr > "$dir/top_http_hosts.txt"
    awk -F'\t' '$9 != "" {print}' "$dir/http.tsv" > "$dir/http_authorization_headers.tsv" || true
    awk -F'\t' 'tolower($5) ~ /\.(exe|dll|scr|ps1|bat|cmd|vbs|js|jar|iso|img|hta)(\?|$)/ {print}' "$dir/http.tsv" > "$dir/suspicious_http_extensions.tsv" || true
    append_summary "- [http](./http/http.tsv)"
    append_summary "  - HTTP hosts: [top_http_hosts.txt](./http/top_http_hosts.txt)"
    append_summary "  - Authorization headers observed: [http_authorization_headers.tsv](./http/http_authorization_headers.tsv)"
    append_summary "  - Suspicious URI extensions: [suspicious_http_extensions.tsv](./http/suspicious_http_extensions.tsv)"
}

module_beaconing() {
    local dir="$OUTPUT_DIR/beaconing"
    mkdir -p "$dir"
    tshark_fields_all "tcp || udp" -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport -E separator=$'\t' \
        | awk -F'\t' '
            {
                port=$4 ? $4 : $5;
                if ($1 && $2 && $3 && port) print $1 "\t" $2 "\t" $3 "\t" port;
            }' > "$dir/connections.tsv"
    awk -F'\t' '
        {
            key=$2 " -> " $3 ":" $4;
            count[key]++;
            if (!(key in first) || $1 < first[key]) first[key]=$1;
            if ($1 > last[key]) last[key]=$1;
        }
        END {
            for (key in count) {
                duration=last[key]-first[key];
                if (count[key] >= 5 && duration > 0) printf "%d\t%.3f\t%s\n", count[key], duration/(count[key]-1), key;
            }
        }' "$dir/connections.tsv" | sort -nr > "$dir/periodic_connection_candidates.tsv"
    append_summary "- [beaconing candidates](./beaconing/periodic_connection_candidates.tsv)"
}

module_scans() {
    local dir="$OUTPUT_DIR/scans"
    mkdir -p "$dir"
    tshark_fields_all "tcp.flags.syn == 1 && tcp.flags.ack == 0" -e ip.src -e ip.dst -e tcp.dstport -E separator=$'\t' \
        | awk -F'\t' '{print $1 "\t" $2 "\t" $3}' > "$dir/syn_attempts.tsv"
    awk -F'\t' '
        {
            src=$1;
            count[src]++;
            dst_seen[src SUBSEP $2]=1;
            port_seen[src SUBSEP $3]=1;
        }
        END {
            for (key in dst_seen) {
                split(key, parts, SUBSEP);
                dst_count[parts[1]]++;
            }
            for (key in port_seen) {
                split(key, parts, SUBSEP);
                port_count[parts[1]]++;
            }
            for (src in count) {
                if (dst_count[src] >= 10 || port_count[src] >= 10) {
                    print count[src] "\t" dst_count[src] "\t" port_count[src] "\t" src;
                }
            }
        }' "$dir/syn_attempts.tsv" | sort -nr > "$dir/scan_candidates.tsv"
    tshark_fields_all "icmp || icmpv6" -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -E separator=$'\t' \
        | sort | uniq -c | sort -nr > "$dir/icmp_activity.txt"
    append_summary "- [scan candidates](./scans/scan_candidates.tsv)"
    append_summary "  - ICMP activity: [icmp_activity.txt](./scans/icmp_activity.txt)"
}

module_ioc() {
    [[ -n "$IOC_FILE" ]] || { append_summary "- ioc: skipped, no IOC file supplied"; return; }
    [[ -f "$IOC_FILE" ]] || die "IOC file not found: $IOC_FILE"
    local dir="$OUTPUT_DIR/ioc"
    mkdir -p "$dir"
    log "Matching IOC file"
    tshark_fields_all "ip || dns || http || tls" \
        -e ip.src -e ip.dst -e dns.qry.name -e http.host -e http.request.uri -e http.user_agent -e tls.handshake.extensions_server_name -e tls.handshake.ja3 -e tls.handshake.ja4 -E separator=$'\t' \
        > "$dir/observable_inventory.tsv"
    rg -i -F -f "$IOC_FILE" "$dir/observable_inventory.tsv" > "$dir/ioc_matches.tsv" || true
    append_summary "- [ioc matches](./ioc/ioc_matches.tsv)"
}

module_zeek() {
    if ! have zeek; then
        warn "zeek not found; skipping"
        append_summary "- zeek: skipped, binary not found"
        return
    fi
    local dir="$OUTPUT_DIR/zeek" merged="$dir/merged.pcapng"
    mkdir -p "$dir"
    mergecap -w "$merged" "${PCAPS[@]}"
    (cd "$dir" && zeek -r "$merged") || warn "zeek returned a non-zero status"
    append_summary "- [zeek logs](./zeek/)"
}

module_suricata() {
    if ! have suricata; then
        warn "suricata not found; skipping"
        append_summary "- suricata: skipped, binary not found"
        return
    fi
    local dir="$OUTPUT_DIR/suricata" f
    mkdir -p "$dir"
    for f in "${PCAPS[@]}"; do
        suricata -r "$f" -l "$dir" >/dev/null 2>&1 || warn "suricata returned non-zero for $(basename "$f")"
    done
    append_summary "- [suricata output](./suricata/)"
}

module_yara() {
    [[ -n "$YARA_RULES" ]] || { append_summary "- yara: skipped, no YARA rules supplied"; return; }
    if ! have yara; then
        warn "yara not found; skipping"
        append_summary "- yara: skipped, binary not found"
        return
    fi
    local dir="$OUTPUT_DIR/extractedFiles"
    [[ -d "$dir" ]] || module_extract
    find "$dir" -type f -print0 | xargs -0 yara -r "$YARA_RULES" > "$dir/yara_matches.txt" 2>/dev/null || true
    append_summary "- [YARA matches](./extractedFiles/yara_matches.txt)"
}

cleanup() {
    if [[ "$KEEP_TEMP" -ne 1 ]]; then
        rm -rf "$OUTPUT_DIR/.tmp"
    fi
}
trap cleanup EXIT

write_manifest
start_summary

log "Starting PCAP hunt against ${#PCAPS[@]} file(s)"

module_enabled dns && module_dns
module_enabled strangeports && module_strangeports
module_enabled geoip && module_geoip
module_enabled useragents && module_useragents
module_enabled tls && module_tls
module_enabled nmap && module_nmap
module_enabled extract && module_extract
module_enabled http && module_http
module_enabled beaconing && module_beaconing
module_enabled scans && module_scans
module_enabled ioc && module_ioc
module_enabled zeek && module_zeek
module_enabled suricata && module_suricata
module_enabled yara && module_yara

{
    printf '\n## Files\n\n'
    find "$OUTPUT_DIR" -maxdepth 3 -type f | sed "s#^$OUTPUT_DIR/##" | sort | sed 's#^#- #'
} >> "$SUMMARY"

log "Script complete. Summary: $SUMMARY"
