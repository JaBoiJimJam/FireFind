#!/bin/bash
set -e 

### Installs dos2unix if not already installed
sudo apt install dos2unix

### Navigate to project directory
cd /home/kali/Desktop/FireFind/

### Convert line endings from DOS to Unix
dos2unix run_firefind.sh

### Convert line endings from DOS to Unix
dos2unix start_dev.sh

### Make scripts executable
chmod +x run_firefind.sh

### Make scripts executable
chmod +x start_dev.sh

### Run the main script
./run_firefind.sh

