# threatHunt_pcaps

`threatHunt_pcaps.sh` is a portable TShark-based triage tool for quickly hunting through one or more PCAP/PCAPNG files during incident response.

It produces filtered evidence PCAPs, analyst-friendly text/TSV summaries, extracted file inventories, IOC matches, and an overall Markdown report.

## Quick Start

```bash
chmod +x ./threatHunt_pcaps.sh
./threatHunt_pcaps.sh -i ./captures -o ./case-001-results
```

## Requirements

Required:

- `tshark`
- `mergecap`

Optional:

- `zeek` for Zeek log generation
- `suricata` for EVE/signature output
- `yara` for extracted-file scanning

On macOS, Wireshark installed through Homebrew usually provides the required tools:

```bash
brew install wireshark
```

On Ubuntu, prefer the current Wireshark packages over older distro defaults when possible.

## Usage

```bash
./threatHunt_pcaps.sh [options]
```

Important options:

- `-i, --input-dir DIR`: directory containing `.pcap` or `.pcapng` files.
- `-o, --output-dir DIR`: output directory. Defaults to `threatHunt_results_<timestamp>`.
- `-m, --modules LIST`: comma-separated modules to run.
- `-c, --countries LIST`: watchlisted ISO country codes. Default: `CN,RU,KP`.
- `-p, --safe-ports LIST`: common ports or ranges to suppress from the strange-port filter.
- `--ioc-file FILE`: match local IP/domain/JA3/JA4/User-Agent indicators.
- `--yara-rules FILE_OR_DIR`: scan extracted files with YARA.
- `--overwrite`: replace an existing output directory.
- `--keep-temp`: keep temporary per-input filtered PCAPs.

Examples:

```bash
./threatHunt_pcaps.sh -i ./pcaps -o ./results --ioc-file ./iocs.txt
./threatHunt_pcaps.sh -i ./pcaps -m dns,tls,http,beaconing,zeek
./threatHunt_pcaps.sh -i ./pcaps --countries IR,KP,RU --safe-ports 22,53,80,443,8443
```

## Modules

Default modules:

- `dns`: DNS query summaries, long-query candidates, NXDOMAIN activity.
- `strangeports`: TCP/UDP traffic outside configured common ports.
- `geoip`: all GeoIP traffic plus configurable watchlisted country matches.
- `useragents`: HTTP User-Agent inventory and frequency counts.
- `tls`: outdated TLS handshakes, SNI, JA3, and JA4 summaries.
- `nmap`: simple Nmap-like SYN/window-size heuristic.
- `extract`: HTTP/SMB/TFTP object extraction and SHA256 inventory.
- `http`: HTTP host, URI, method, response, content type, authorization, and suspicious-extension summaries.
- `beaconing`: recurring connection candidates by source/destination/port.
- `scans`: horizontal/vertical SYN scan candidates and ICMP activity.
- `ioc`: local indicator matching when `--ioc-file` is supplied.

Optional modules:

- `zeek`: runs Zeek against a merged capture when `zeek` is installed.
- `suricata`: runs Suricata per capture when `suricata` is installed.
- `yara`: scans extracted files when `yara` and `--yara-rules` are provided.

## Output

Each run creates:

- `summary.md`: analyst index and links to key outputs.
- `run_manifest.txt`: script version, inputs, enabled modules, TShark version, and options.
- `run.log`: command progress and warnings.
- Per-module folders containing filtered PCAPs and TSV/text summaries.

The script writes to a fresh timestamped directory by default, so repeated runs do not merge old outputs back into new evidence.

## GeoIP Notes

GeoIP fields require MaxMind databases configured for Wireshark/TShark. Check the active paths with:

```bash
tshark -G folders
```

The country-code module is intentionally configurable. Treat geography as enrichment and triage context, not as a standalone verdict.

## Screenshots

![Initial run screenshot](https://github.com/ArronJablonowski/threatHunt_pcaps/blob/main/1.png?raw=true)

![Results screenshot](https://github.com/ArronJablonowski/threatHunt_pcaps/blob/main/2.png?raw=true)
