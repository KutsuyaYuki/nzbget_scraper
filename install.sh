#!/bin/bash

# Make a venv
python3 -m venv venv

# Activate the venv
source venv/bin/activate

# Install the requirements
pip install -r requirements.txt
