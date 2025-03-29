#!/bin/bash
lsof -ti:5000 | xargs kill
#python server.py >>out.txt 2>>out.txt&
python server.py &
