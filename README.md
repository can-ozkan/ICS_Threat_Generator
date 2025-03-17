# ICS_Threat_Generator
The aim of this repository is to provide the software implementation of our ICS Threat Generation Methodology. \
Before use, request an API Key from NIST from https://nvd.nist.gov/developers/request-an-api-key. \
Then, replace your API key in final_app.py file api_key variable at line 474

## Installation
python3 -m venv venv \
sourve venv/bin/activate \
pip3 install -r requirements   
sudo apt-get install python3-tk  

## Usage
python3 ./my_gui \
Once enumeration is done, click on the show results tab and select all_threats.txt
