#!/bin/bash

apt-get update
apt-get -y upgrade
apt-get install -y nmap
apt-get install -y python3
apt-get install -y python3-pip
pip3 install shodan
pip3 install argparse

echo "Complete..."
