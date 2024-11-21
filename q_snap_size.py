#!/usr/bin/python3

import sys
import getopt
import getpass
import requests
import urllib.parse
import json
import time
import os
import keyring
from datetime import datetime
import urllib.parse
import urllib3
urllib3.disable_warnings()
import re

import pprint
pp = pprint.PrettyPrinter(indent=4)

def usage():
    print("Usage goes here!")
    exit(0)

def dprint(message):
    if DEBUG:
        dfh = open('debug.out', 'a')
        dfh.write(message + "\n")
        dfh.close()

def oprint(fp, message):
    if fp:
        fp.write(message + '\n')
    else:
        print(message)
    return
def api_login(qumulo, user, password, token):
    in_keyring = True
    headers = {'Content-Type': 'application/json'}
    if not token:
        if not user:
            user = input("User: ")
        if not password:
            password = keyring.get_password(RING_SYSTEM, user)
        if not password:
            in_keyring = False
            password = getpass.getpass("Password: ")
        payload = {'username': user, 'password': password}
        payload = json.dumps(payload)
        autht = requests.post('https://' + qumulo + '/api/v1/session/login', headers=headers, data=payload,
                              verify=False, timeout=timeout)
        dprint(str(autht.ok))
        auth = json.loads(autht.content.decode('utf-8'))
        dprint(str(auth))
        if autht.ok:
            auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + auth['bearer_token']}
            if not in_keyring:
                use_ring = input("Put these credentials into keyring? [y/n]: ")
                if use_ring.startswith('y') or use_ring.startswith('Y'):
                    keyring.set_password(RING_SYSTEM, user, password)
        else:
            sys.stderr.write("ERROR: " + auth['description'] + '\n')
            exit(2)
    else:
        auth_headers = {'accept': 'application/json', 'Content-type': 'application/json', 'Authorization': 'Bearer ' + token}
    dprint("AUTH_HEADERS: " + str(auth_headers))
    return(auth_headers)

def qumulo_get(addr, api):
    dprint("API_GET: " + api)
    good = False
    while not good:
        good = True
        try:
            res = requests.get('https://' + addr + '/api' + api, headers=auth, verify=False, timeout=timeout)
        except requests.exceptions.ConnectionError:
            print("Connection Error: Retrying..")
            time.sleep(5)
            good = False
            continue
        if res.content == b'':
            print("NULL RESULT[GET]: retrying..")
            good = False
            time.sleep(5)
    if res.status_code == 200:
        dprint("RESULTS: " + str(res.content))
        results = json.loads(res.content.decode('utf-8'))
        return(results)
    elif res.status_code == 404:
        return("404")
    else:
        sys.stderr.write("API ERROR: " + str(res.status_code) + "\n")
        sys.stderr.write(str(res.content) + "\n")
        exit(3)

def get_token_from_file(file):
    with open(file, 'r') as fp:
        tf = fp.read().strip()
    fp.close()
    t_data = json.loads(tf)
    dprint(t_data['bearer_token'])
    return(t_data['bearer_token'])

def snap_match(path, plist):
    for p in plist:
        if re.search(p, path):
            return(True)
    return(False)

def convert_to_bytes(size, unit):
    if unit[0] in ['k', 'K']:
        return(size*1000)
    elif unit[0] in ['m', 'M']:
        return (size*1000*1000)
    elif unit[0] in ['g', 'G']:
        return(size*1000*1000*1000)
    elif unit[0] in ['t', 'T']:
        return(size*1000*1000*1000*1000)
    elif unit[0] in ['p', 'P']:
        return(size*1000*1000*1000*1000)
    else:
        sys.stderr.write("Unsupported unit: " + unit + ".  Supported: kb, mb, tb, pb\n")
        exit(1)

if __name__ == "__main__":
    DEBUG = False
    VERBOSE = False
    default_token_file = ".qfsd_cred"
    timeout = 30
    token_file = ""
    token = ""
    user = ""
    password = ""
    RING_SYSTEM = "q_snap_size"
    fp = ""
    outfile = ""
    paths = []
    REPLICATION_SNAPS = True
    snaps = {}
    snap_size = {}
    size = 0
    unit = ''

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:f:c:o:rs:vu:', ['help', 'DEBUG', 'token=', 'creds=', 'token-file=',
                                                                   'config-file=', 'output-file=' 'exclude-replication',
                                                                    'size=', 'verbose', 'unit='])
    for opt, a in optlist:
        if opt in ['-h', '--help']:
            usage()
        if opt in ('-D', '--DEBUG'):
            DEBUG = True
        if opt in ('-t', '--token'):
            token = a
        if opt in ('-c', '--creds'):
            if ':' in a:
                (user, password) = a.split(':')
            else:
                user = a
        if opt in ('-f', '--token-file'):
            token_file = a
        if opt in ('-o', '--output-file'):
            outfile = a
        if opt in ('-r', '--exclude-replication'):
            REPLICATION_SNAPS = False
        if opt in ('-s', '--size'):
            up = re.search('[a-z]+', a.lower())
            try:
                upn = int(up.span()[0])
                size = int(a[:upn])
                unit = a[upn:].lower()
                size = convert_to_bytes(size, unit)
                dprint("SIZE: " + str(size))
            except:
                size = int(a)
        if opt in ('-v', '--verbose'):
            VERBOSE = True
        if opt in ('-u', '--unit'):
            unit = a[0].lower()

    qumulo = args.pop(0)
    paths = args
    if not user and not token:
        if not token_file:
            token_file = default_token_file
        if os.path.isfile(token_file):
            token = get_token_from_file(token_file)
    auth = api_login(qumulo, user, password, token)
    dprint(str(auth))
    snap_sizes = qumulo_get(qumulo, '/v1/snapshots/capacity-used-per-snapshot/')
    for ssize in snap_sizes['entries']:
        snap_size[ssize['id']] = int(ssize['capacity_used_bytes'])
    snap_list = qumulo_get(qumulo, '/v4/snapshots/status/')
    for s in snap_list['entries']:
        if s['in_delete']:
            continue
        if not REPLICATION_SNAPS and re.search('[0-9]+_replication_from_', s['name']):
            continue
        if len(paths) > 0:
            if not snap_match(s['source_file_path'], paths):
                continue
        if size > 0 and snap_size[s['id']] < size:
            continue
        snaps[s['source_file_path']] = {'id': s['id'], 'timestamp': s['timestamp'], 'policy': s['policy_name'],
                                        'expiration': s['expiration'], 'size': snap_size[s['id']]}
        if s['lock_key'] is None:
            snaps[s['source_file_path']]['locked'] = False
        else:
            snaps[s['source_file_path']]['locked'] = True
    pp.pprint(snaps)


