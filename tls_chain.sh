#!/bin/bash
pushd credentials >/dev/null 2>&1

python3 manage.py --dns-names `hostname` --generate-root cia
python3 manage.py --dns-names `hostname` --generate-cert cia client1
python3 manage.py --dns-names `hostname` --generate-cert cia server1
