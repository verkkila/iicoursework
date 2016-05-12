#!/bin/sh

python3 main.py 127.0.0.1 $1
python3 main.py 127.0.0.1 $1 -e
python3 main.py 127.0.0.1 $1 -v -e
