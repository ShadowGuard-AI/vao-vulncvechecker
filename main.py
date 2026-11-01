import argparse
import logging
import json
import requests
import sys
from urllib.parse import quote

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Check software packages for known CVEs.')
    parser.add_argument('-p', '--packages', type=str, help='JSON file containing a list of software packages and their versions.')
    parser.add_argument('-o', '--output', type=str, default='vulnerability_report.json', help='Output file for the vulnerability report (default: vulnerability_report.json).')
    parser.add_argument('--cve_search_url', type=str, default='https://cve.circl.lu/api/search/', help='Base URL for the cve-search API. Defaults to https://cve.circl.lu/api/search/')
    parser.add_argument('--nikto_scan', type=str, help='Target URL for Nikto scan.  Will attempt to call Nikto to check for web vulnerabilities.')
    parser.add_argument('--nmap_target', type=str, help='Target IP address or hostname for Nmap scan. Will attempt to call Nmap to scan for vulnerabilities.')


    return parser.parse_args()

def validate_package_data(package_data):
    """
    Validates the structure of the package data.

    Args:
        package_data (list): A list of dictionaries, where each dictionary
                            represents a software package and its version.

    Returns:
        bool: True if the package data is valid, False otherwise.
    """
    if not isinstance(package_data, list):
        logging.error("Package data must be a list.")
        return False

    for package in package_data:
        if not isinstance(package, dict):
            logging.error("Each package must be a dictionary.")
            return False
        if 'name' not in package or 'version' not in package:
            logging.error("Each package must have 'name' and 'version' keys.")
            return False
    return True

def _entry_matches(result, package_name, package_version):
    """Verify a returned entry against the queried product and version."""
    if not isinstance(result, dict):
        return False
    wanted_product = str(package_name).lower()
    wanted_version = str(package_version)
    products = []
    if result.get('product'):
        products.append((str(result['product']).lower(), str(result.get('version', ''))))
    for p in result.get('products', []) or []:
        if isinstance(p, dict):
            products.append((str(p.get('product', '')).lower(), str(p.get('version', ''))))
        else:
            products.append((str(p).lower(), ''))
    for field in ('vulnerable_configuration', 'vulnerable_configurations', 'configurations', 'cpes'):
        vals = result.get(field) or []
        if isinstance(vals, str):
            vals = [vals]
        for v in vals:
            text = v if isinstance(v, str) else json.dumps(v)
            for token in text.replace('\\', '').split(':'):
                pass
            # CPE form cpe:2.3:a:vendor:product:version:... or cpe:/a:vendor:product:version
            parts = text.split(':')
            if len(parts) >= 6 and parts[0].endswith('cpe'):
                products.append((parts[4].lower(), parts[5]))
            elif text.lower().startswith('cpe:/') and len(parts) >= 4:
                pp = text[5:].split(':')
                if len(pp) >= 4:
                    products.append((pp[2].lower(), pp[3]))
    for prod, ver in products:
        if prod != wanted_product:
            continue
        if not ver or ver in ('*', '-'):
            return True
        if ver == wanted_version:
            return True
    return False


def check_cve(package_name, package_version, cve_search_url):
    """Returns (cves, error). error is None on a completed query."""
    try:
        # cve-search API search form: /api/search/<vendor>/<product>; here the
        # package name and version are separately URL-encoded path/query parts.
        base = cve_search_url.rstrip('/') + '/'
        url = f"{base}{quote(str(package_name), safe='')}/{quote(str(package_version), safe='')}"
        logging.info(f"Querying cve-search API: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        results = response.json()
        if isinstance(results, dict):
            results = results.get('results') or results.get('data') or []
        cves = []
        for result in results or []:
            if _entry_matches(result, package_name, package_version):
                cves.append(result.get('id', 'N/A'))
            else:
                logging.info(f"Skipping returned entry {result.get('id') if isinstance(result, dict) else result} that does not match {package_name} {package_version}")
        if not results:
            logging.info(f"No CVEs found for {package_name} {package_version}")
        return cves, None
    except requests.exceptions.Timeout as e:
        logging.error(f"Timeout querying cve-search API for {package_name}: {e}")
        return [], f"timeout: {e}"
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying cve-search API: {e}")
        return [], str(e)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response from cve-search API: {e}")
        return [], str(e)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return [], str(e)

def run_nikto_scan(target_url):
  """
  Runs a Nikto scan against the specified target URL.
  This function requires Nikto to be installed and accessible in the system's PATH.

  Args:
      target_url (str): The URL to scan.

  Returns:
      str: The output of the Nikto scan, or None if an error occurred.
  """
  import subprocess
  if str(target_url).startswith('-'):
    logging.error("Refusing Nikto target that begins with a dash; it would be parsed as scanner flags.")
    return None
  try:
    logging.info(f"Running Nikto scan against {target_url}")
    process = subprocess.run(['nikto', '-host', '--', target_url], capture_output=True, text=True, check=True)
    return process.stdout
  except subprocess.CalledProcessError as e:
    logging.error(f"Nikto scan failed: {e}")
    return None
  except FileNotFoundError:
    logging.error("Nikto is not installed or not in your PATH. Please install Nikto to use this feature.")
    return None
  except Exception as e:
    logging.error(f"An unexpected error occurred while running Nikto: {e}")
    return None

def run_nmap_scan(target):
    """
    Runs an Nmap scan against the specified target.
    This function requires Nmap to be installed and accessible in the system's PATH.

    Args:
        target (str): The IP address or hostname to scan.

    Returns:
        str: The XML output of the Nmap scan, or None if an error occurred.
    """
    import subprocess
    if str(target).startswith('-'):
        logging.error("Refusing Nmap target that begins with a dash; it would be parsed as scanner flags.")
        return None
    try:
        logging.info(f"Running Nmap scan against {target}")
        process = subprocess.run(['nmap', '-sV', '-oX', '-', '--', target], capture_output=True, text=True, check=True)
        return process.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap scan failed: {e}")
        return None
    except FileNotFoundError:
        logging.error("Nmap is not installed or not in your PATH. Please install Nmap to use this feature.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while running Nmap: {e}")
        return None


def main():
    """
    Main function to orchestrate the vulnerability assessment.
    """
    args = setup_argparse()

    if not args.packages:
        logging.error("Please provide a JSON file containing software packages using the -p or --packages argument.")
        sys.exit(1)

    try:
        with open(args.packages, 'r') as f:
            try:
                package_data = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from file: {e}")
                sys.exit(1)
    except FileNotFoundError:
        logging.error(f"File not found: {args.packages}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading the file: {e}")
        sys.exit(1)

    if not validate_package_data(package_data):
        sys.exit(1)

    if not package_data:
        logging.error("Package list is empty; nothing was checked.")
        sys.exit(1)

    vulnerability_report = {}
    failures = 0
    for package in package_data:
        package_name = package['name']
        package_version = package['version']
        cves, error = check_cve(package_name, package_version, args.cve_search_url)
        key = f"{package_name} {package_version}"
        if error is not None:
            failures += 1
            vulnerability_report[key] = {"error": error}
        elif cves:
            vulnerability_report[key] = cves
        else:
            vulnerability_report[key] = []

    if args.nikto_scan:
        nikto_output = run_nikto_scan(args.nikto_scan)
        if nikto_output:
            vulnerability_report['nikto_scan'] = nikto_output
        else:
          vulnerability_report['nikto_scan_error'] = "Nikto scan failed or not run"

    if args.nmap_target:
        nmap_output = run_nmap_scan(args.nmap_target)
        if nmap_output:
            vulnerability_report['nmap_scan'] = nmap_output
        else:
            vulnerability_report['nmap_scan_error'] = "Nmap scan failed or not run"

    try:
        with open(args.output, 'w') as outfile:
            json.dump(vulnerability_report, outfile, indent=4)
        logging.info(f"Vulnerability report saved to {args.output}")
    except IOError as e:
        logging.error(f"Error writing to file: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred while writing the report: {e}")
        sys.exit(1)

    if package_data and failures == len(package_data):
        logging.error("Every CVE query failed; the run did not complete a check.")
        sys.exit(1)

if __name__ == "__main__":
    # Usage Examples
    # 1. Run the script with a package list and output to a specific file:
    #    python vao-VulnCVEChecker.py -p packages.json -o my_report.json

    # 2. Run the script with a package list and the default output file:
    #    python vao-VulnCVEChecker.py -p packages.json

    # 3. Run the script with a custom cve-search API URL:
    #    python vao-VulnCVEChecker.py -p packages.json --cve_search_url https://alternative-cve-search/api/search/

    # 4. Run Nikto against a target URL:
    #    python vao-VulnCVEChecker.py -p packages.json --nikto_scan http://example.com

    # 5. Run Nmap against a target IP or Hostname:
    #    python vao-VulnCVEChecker.py -p packages.json --nmap_target 192.168.1.100

    # 6. Run All Tools
    # python vao-VulnCVEChecker.py -p packages.json --nmap_target 192.168.1.100 --nikto_scan http://example.com

    main()