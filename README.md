# vao-VulnCVEChecker
Takes a list of software packages and their versions as input and checks for known CVEs affecting them, using a direct API call to the cve-search API and verifying each returned entry against the queried product and version before attributing it. It can also run a default Nikto scan and an Nmap scan with -sV service version detection only (no NSE vulnerability scripts), and writes a consolidated JSON report. Scanner output and scanner failure are recorded in separate report fields.

## Install
`git clone https://github.com/ShadowStrikeHQ/vao-vulncvechecker`

## Usage
`./vao-vulncvechecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: JSON file containing a list of software packages and their versions.
- `-o`: No description provided
- `--cve_search_url`: Base URL for the cve-search API. Defaults to https://cve.circl.lu/api/search/
- `--nikto_scan`: Target URL for Nikto scan.  Will attempt to call Nikto to check for web vulnerabilities.
- `--nmap_target`: Target IP address or hostname for Nmap scan. Will attempt to call Nmap to scan for vulnerabilities.

## License
Copyright (c) ShadowStrikeHQ
