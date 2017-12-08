#!/bin/bash

apt-get update
apt-get -y upgrade
apt-get install python3
apt-get install python3-pip
pip3 install shodan
pip3 install argparse

echo "Complete..."
