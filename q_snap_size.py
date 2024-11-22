#!/usr/bin/python3

import sys
import getopt
import getpass
import requests
import json
import time
import os
import keyring
from datetime import datetime
from dateutil import tz
import urllib3
urllib3.disable_warnings()
import re
import pprint
pp = pprint.PrettyPrinter(indent=4)

def usage():
    sys.stderr.write("Usage: q_snap_size.py [-hDvr] [-c user[:password]] [-t token] [-f token_file] [-s size] [-u unit] qumulo [path] ... [path]\n")
    sys.stderr.write("-h | --help : Prints Usage\n")
    sys.stderr.write("-D | --DEBUG : Generated info for debugging\n")
    sys.stderr.write("-v | --verbose : Provides more details in the report\n")
    sys.stderr.write("-r | --exclude-replication : Exclude replication-based snapshots\n")
    sys.stderr.write("-c | --creds : Specify credentials format is user[:password]\n")
    sys.stderr.write("-t | --token : Specify an access token\n")
    sys.stderr.write("-f | --token-file : Specify is token file [def: .qfds_cred]\n")
    sys.stderr.write("-s | --size : Exclude snapshots under a given size\n")
    sys.stderr.write('-u | --unit : Specify a unit of size in the report [def: bytes]\n')
    sys.stderr.write("qumulo : Name or IP of a Qumulo node\n")
    sys.stderr.write("path ... path : One or more path patterns to include (regex supported), space separated\n")
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
    if unit[0] in ['m', 'M']:
        return (size*1000*1000)
    if unit[0] in ['g', 'G']:
        return(size*1000*1000*1000)
    if unit[0] in ['t', 'T']:
        return(size*1000*1000*1000*1000)
    if unit[0] in ['p', 'P']:
        return(size*1000*1000*1000*1000)
    sys.stderr.write("Unsupported unit: " + unit + ".  Supported: kb, mb, gb,tb, pb\n")
    exit(1)

def convert_from_bytes(bytes, unit):
    if unit == 'k':
        return(int(bytes/1000))
    if unit == 'm':
        return(int(bytes/1000/1000))
    if unit == 'g':
        return(int(bytes/1000/1000/1000))
    if unit == 't':
        return(int(bytes/1000/1000/1000/1000))
    if unit == 'p':
        return(int(bytes/1000/1000/1000/1000/1000))
    sys.stderr.write("Unsupported unit: " + unit + ".  Supported: kb, mb, gb, tb, pb\n")
    exit(2)

def convert_to_localtime(time_s):
    c_time = time_s.split('.')
    cts = datetime.strptime(c_time[0], "%Y-%m-%dT%H:%M:%S")
    cts = cts.replace(tzinfo=utc_tz)
    cts_local = cts.astimezone(local_tz)
    return(datetime.strftime(cts_local, '%Y-%m-%d %H:%M:%S'))

if __name__ == "__main__":
    DEBUG = False
    VERBOSE = False
    default_token_file = ".qfsd_cred"
    timeout = 30
    token_file = ""
    token = ""
    user = ""
    password = ""
    qumulo = ""
    RING_SYSTEM = "q_snap_size"
    fp = ""
    outfile = ""
    paths = []
    REPLICATION_SNAPS = True
    snaps = {}
    snap_size = {}
    size = 0
    unit = ''
    rep_unit = ''
    ofp = ""
    local_tz = tz.tzlocal()
    utc_tz = tz.tzutc()

    optlist, args = getopt.getopt(sys.argv[1:], 'hDt:f:c:o:rs:vu:', ['help', 'DEBUG', 'token=', 'creds=', 'token-file=',
                                                                   'output-file=' 'exclude-replication',
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
            rep_unit = a[0].lower()

    try:
        qumulo = args.pop(0)
    except:
        usage()
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
        if rep_unit:
            s_size = convert_from_bytes(snap_size[s['id']], rep_unit)
        else:
            s_size = snap_size[s['id']]
        create_time = convert_to_localtime(s['timestamp'])
        expiration_time = ""
        if s['expiration']:
            expiration_time = convert_to_localtime(s['expiration'])
        snaps[s['name']] = {'id': s['id'], 'path': s['source_file_path'], 'timestamp': create_time,
                                        'expiration': expiration_time,  'size': s_size}
        if s['lock_key'] is None:
            snaps[s['name']]['locked'] = False
        else:
            snaps[s['name']]['locked'] = True
        if s['policy_name'] is None:
            snaps[s['name']]['policy'] = "N/A"
        else:
            snaps[s['name']]['policy'] = s['policy_name']

    # pp.pprint(snaps)
    if outfile:
        ofp = open(outfile, "w")
    if VERBOSE:
        oprint(ofp, "Path:,Name:,Size:,Policy:,Created:,Expiration:,Locked:")
    else:
        oprint(ofp, "Path:,Name:,Size:")
    for sp in snaps:
        if VERBOSE:
            oprint(ofp, snaps[sp]['path'] + ',' + sp + ',' + str(snaps[sp]['size']) + ',' + snaps[sp]['policy'] + ',' + snaps[sp]['timestamp'] + ',' + snaps[sp]['expiration'] + ',' + str(snaps[sp]['locked']))
        else:
            oprint(ofp, snaps[sp]['path'] + ',' + sp + ',' + str(snaps[sp]['size']))
    if outfile:
        ofp.close()






