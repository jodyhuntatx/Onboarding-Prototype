#!/bin/bash
./package.sh
export PYTHONPATH=$PYTHONPATH:./lib
clear
rm logs/*

./safeCreate.py safereq.json
if [ $? -ne 0 ]; then exit; fi 
./acctCreate.py acctreq.json
if [ $? -ne 0 ]; then exit; fi 
./testSHfunctions.py safereq.json
if [ $? -ne 0 ]; then exit; fi 
./safeDelete.py safereq.json
