# NZBGet Scraper

A simple tool to scrape NZBGet servers from Shodan.

## How to use

1. `chmod +x install.sh`
2. `./install.sh`
3. activate the venv `source venv/bin/activate`
4. run `python app.py`

## Requirements

* Python 3.9+
* `shodan` library (install with `pip install -U --user shodan`)
* Finally, initialize the Shodan CLI with your API key: `shodan init API_KEY`

## License

This project is licensed under the MIT License. See the LICENSE file for details.
