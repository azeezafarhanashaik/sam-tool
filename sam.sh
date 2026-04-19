#!/bin/bash

clear

echo "==============================="
echo " SAM - Static Malware Analyzer"
echo "==============================="

echo "1. Scan URL"
echo "2. Scan File"
echo "3. Exit"

read -p "Select Option: " option

if [ $option -eq 1 ]
then
python3 url_scanner.py

elif [ $option -eq 2 ]
then
python3 file_scanner.py

else
exit
fi
