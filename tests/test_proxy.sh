#!/bin/sh

python2 ../main.py 127.0.0.1 $1
python2 ../main.py 127.0.0.1 $1 -h
python2 ../main.py 127.0.0.1 $1 -e
python2 ../main.py 127.0.0.1 $1 -v -e

python3 ../main.py 127.0.0.1 $1
python3 ../main.py 127.0.0.1 $1 -h
python3 ../main.py 127.0.0.1 $1 -e
python3 ../main.py 127.0.0.1 $1 -e -h
