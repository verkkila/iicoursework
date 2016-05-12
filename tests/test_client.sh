#!/bin/sh

python2 ../client.py 8dh10w8hasdhu9 10000
python2 ../client.py ii.virtues.fi abcdef
python2 ../client.py 182dh1398 180293j
python2 ../client.py ii.virtues.fi 10000
python2 ../client.py ii.virtues.fi 10000 -e
python2 ../client.py ii.virtues.fi 10000 -e -h
python2 ../client.py ii.virtues.fi 10000 -e -h -v

python3 ../client.py 8dh10w8hasdhu9 10000
python3 ../client.py ii.virtues.fi abcdef
python3 ../client.py 182dh1398 180293j
python3 ../client.py ii.virtues.fi 10000
python3 ../client.py ii.virtues.fi 10000 -e
python3 ../client.py ii.virtues.fi 10000 -e -h
python3 ../client.py ii.virtues.fi 10000 -e -h -v
