# vao-VulnCVEChecker
Takes a list of software packages and their versions as input and checks for known CVEs affecting them. Utilizes the `cve-search` library or a direct API call to a CVE database and outputs a report of identified vulnerabilities. - Focused on Automates the execution and aggregation of results from multiple open-source vulnerability scanners (e.g., Nikto, Nmap NSE scripts for specific vulnerabilities). Orchestrates scans, parses reports, and correlates findings to provide a consolidated vulnerability overview.

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
