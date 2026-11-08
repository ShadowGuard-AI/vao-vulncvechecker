# vao-VulnCVEChecker

Takes a list of software packages and their versions as input and checks for known CVEs affecting them, using a direct API call to the cve-search API and verifying each returned entry against the queried product and version before attributing it. Dotted numeric versions compare with trailing zero segments dropped, so a package listed as 2.31 matches an entry recorded as 2.31.0. Package entries must have a non-empty string name and a non-empty string or numeric version, and the run is rejected up front when an entry fails that check. It can also run a default Nikto scan and an Nmap scan with -sV service version detection only (no NSE vulnerability scripts), and writes a consolidated JSON report. Scanner output and scanner failure are recorded in separate report fields. The output file must not resolve to the input packages file; the run refuses to overwrite its own input.

## Install
`git clone https://github.com/ShadowGuard-AI/vao-vulncvechecker.git`

## Usage
`python3 main.py -p packages.json [-o vulnerability_report.json]`

## Parameters
- `-h`: Show help message and exit
- `-p`: JSON file containing a list of software packages and their versions.
- `-o`: Output file for the vulnerability report (default: vulnerability_report.json).
- `--cve_search_url`: Base URL for the cve-search API. Defaults to https://cve.circl.lu/api/search/
- `--nikto_scan`: Target URL for Nikto scan. Will attempt to call Nikto to check for web vulnerabilities.
- `--nmap_target`: Target IP address or hostname for Nmap scan. Will attempt to call Nmap to scan for vulnerabilities.

## License
MIT License. See LICENSE.
