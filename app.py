import os
import csv
import json
import tqdm
import pynzbgetapi
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
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

class hostResult:
    source = None
    host = None
    port = None
    username = None
    password = None
    connections = None
    
    def __init__(self, source, host, port, username, password, connections):
        self.source = source
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connections = connections
        
    
    def toJSON(self):
        return self.__dict__

def main():
    shodan_hosts_file = 'shodan_results.txt'
    download_hosts(shodan_hosts_file)
    hostnames = extract_hostnames(shodan_hosts_file)

    successful_searches = 0
    unsuccessful_searches = 0
    results: set[hostResult] = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(search_for_keys, hostname): hostname for hostname in hostnames}

        with tqdm.tqdm(total=len(future_to_url), desc="Processing Hosts", unit="host", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results.extend(future.result())
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
    
    # read the results.json file before saving, to avoid duplicates
    if os.path.exists('results.json'):
        with open('results.json', 'r') as json_file:
            existing_results = set[hostResult](json.load(json_file, object_hook=lambda d: hostResult(**d)))
            
            # join and distinct the lists
            results.extend(x for x in existing_results if x.toJSON() not in [y.toJSON() for y in results])
    
    save_json(results)
    save_html(results)

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

def save_html(results: set[hostResult]):
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
        html_file.write('      <th>Source</th>\n')
        html_file.write('      <th>Host</th>\n')
        html_file.write('      <th>Port</th>\n')
        html_file.write('      <th>Username</th>\n')
        html_file.write('      <th>Password</th>\n')
        html_file.write('      <th>Connections</th>\n')
        html_file.write('    </tr>\n')

        for result in results:
            html_file.write('    <tr>\n')
            html_file.write(f'      <td>{result.source}</td>\n')
            html_file.write(f'      <td>{result.host}</td>\n')
            html_file.write(f'      <td>{result.port}</td>\n')
            html_file.write(f'      <td>{result.username}</td>\n')
            html_file.write(f'      <td>{result.password}</td>\n')
            html_file.write(f'      <td>{result.connections}</td>\n')
            html_file.write('    </tr>\n')

        html_file.write('  </table>\n')
        html_file.write('</body>\n')
        html_file.write('</html>\n')

    print(f"{Fore.GREEN}HTML output generated: results.html{Style.RESET_ALL}")

def save_json(results: set[hostResult]):
    with open('results.json', 'w') as json_file:
        json.dump([item.toJSON() for item in results], json_file, indent=4)

    print(f"{Fore.GREEN}JSON output generated: results.json{Style.RESET_ALL}")

def search_for_keys(url) -> set[hostResult]:
    hosts = []
    logging.info(f"Now searching {url}")
    try:
        ng_api = pynzbgetapi.NZBGetAPI(url, timeout=5)
        json_response = ng_api.config()
        servers_found = 0
        current_host = None
        
        # filter all the servers out of the configuration
        result = [i for i in json_response if i['Name'].startswith('Server')]
        
        current_host = None
        port = None
        username = None
        password = None
        connections = None

        for item in result:
            property_name = item["Name"].split(".", 1)[1]
            property_value = item["Value"]
            
            # getting a host means a new set of server properties
            if property_name == "Host":
                current_host = property_value
                port = None
                username = None
                password = None
                connections = None
            elif property_name == "Port":
                port = property_value
            elif property_name == "Username":
                username = property_value
            elif property_name == "Password":
                password = property_value
            elif property_name == "Connections":
                connections = property_value
            else:
                continue
            
            # if it's a complete host, append it to the list
            if current_host and port and username and password and connections:
                servers_found += 1
                hosts.append(hostResult(url, current_host, port, username, password, connections)) 
        
        logging.info(f"Found {servers_found} servers in {url}")
        return hosts
    except requests.exceptions.Timeout:
        logging.warning(f"Connection to {url} timed out after 5 seconds.")
        raise  # Re-raise the exception to be caught by the caller
    except Exception as e:
        logging.error(f"An error occurred while trying to get {url}: {e}")
        raise  # Re-raise the exception to be caught by the caller

def download_hosts(shodan_hosts_file: str):
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
            with open(shodan_hosts_file, 'w') as f:
                for item in tqdm.tqdm(hostnames_ports, desc="Saving Hosts", unit="host", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"):
                    f.write("%s\n" % item)

            print(f"{Fore.GREEN}Fresh list of hosts downloaded from Shodan.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No hosts found in Shodan search.{Style.RESET_ALL}")

    except Exception as e:
        logging.error(f"An error occurred while downloading hosts from Shodan: {e}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Program interrupted by user.")
    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")

