#!/bin/bash
./package.sh
export PYTHONPATH=$PYTHONPATH:./lib
clear
rm logs/*

./safeCreate.py ./requests/safereq.json
if [ $? -ne 0 ]; then exit; fi 
./addSHinfra.py ./requests/safereq.json
if [ $? -ne 0 ]; then exit; fi 
./acctCreate.py ./requests/acctreq.json
