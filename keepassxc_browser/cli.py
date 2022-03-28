#!/usr/bin/python3

import sys
import os
import re
import subprocess
import argparse
import json
import tldextract
from . import protocol as kpp


def find_pass_candidates(domain, connection, auth_id):
    try:
        candidates = connection.get_logins(auth_id,"https://"+domain)
    except kpp.ProtocolError as e:
        print("failure: KeePassXC protocol error:", e, file=sys.stderr)
        sys.exit(1)

    return {
        "%s [%s]" % (entry["name"], entry["login"]): (entry["name"], entry["login"], entry["password"]) for entry in candidates
    }


def select_candidate(items, command):
    process = subprocess.run(command, input='\n'.join(items).encode("utf-8"),
                             stdout=subprocess.PIPE, shell=True)
    return process.stdout.decode("utf-8").strip()


def fetch_candidates(url, auth_id, keyfile):
    conn = kpp.Connection()
    try:
        conn.connect()
    except Exception as e:
        print("failure: cannot connect to KeePassXC server:", e, file=sys.stderr)
        sys.exit(1)

    keyfile_name = os.path.expanduser(keyfile)

    try:
        if os.path.exists(keyfile_name):
            try:
                keyfile = open(keyfile_name, "r")
                cred = kpp.Identity.unserialize(auth_id, keyfile.read())
                keyfile.close()
            except Exception as e:
                print("failure: error when try to read keyfile", e, file=sys.stderr)
                sys.exit(1)

            conn.change_public_keys(cred)

            if not conn.test_associate(cred):
                conn.associate(cred)
        else:
            cred = kpp.Identity(auth_id)
            conn.change_public_keys(cred)
            conn.associate(cred)
            try:
                keyfile = open(keyfile_name, "w")
                keyfile.write(cred.serialize())
                keyfile.close()
            except Exception as e:
                print("failure: error when trying to write keyfile", e, file=sys.stderr)
                sys.exit(1)
    except kpp.ProtocolError as e:
        print("failure: KeePassXC protocol error:", e, file=sys.stderr)
        sys.exit(1)

    extract_result = tldextract.extract(url)

    # Try to find candidates using targets in the following order: fully-qualified domain name (includes subdomains),
    # the registered domain name and finally: the IPv4 address if that's what the URL represents
    candidates = {}
    if extract_result.domain:
        fqdn = '.'.join(i for i in extract_result if i)
        registered_domain = '.'.join(i for i in extract_result[1:] if i)
    else:
        if extract_result.ipv4 == "":
            print("failure: Format of URL '%s' is invalid!" % arguments.url, file=sys.stderr)
            sys.exit(1)
        fqdn = ""
        registered_domain = ""
    for target in filter(None, [fqdn, registered_domain, extract_result.ipv4]):
        target_candidates = find_pass_candidates(target, conn, cred)
        if target_candidates:
            candidates = target_candidates
            break
    else:
        if len(candidates) == 0:
            print("failure: no pass candidates for URL '%s' found!" % arguments.url, file=sys.stderr)
            sys.exit(1)

    return candidates


def main():
    argument_parser = argparse.ArgumentParser(description="Fetch credentials from a running KeepassXC instance")
    argument_parser.add_argument('url')
    argument_parser.add_argument('--store-keyfile', '-k', required=True,
                                 help='Auth token for Keepass-XC')
    argument_parser.add_argument('--auth-id', '-i', default='?',
                                 help='Auth ID for Keepass-XC, will be created if it does not exist')
    argument_parser.add_argument('--selector-command', '-s', default='dmenu',
                                 help='Command used to select from multiple entries (dmenu-compatible)')
    argument_parser.add_argument('--always-select', '-A', action="store_true",
                                 help='run selector command even if there is only one candidate')
    argument_parser.add_argument('--format', '-f', choices=("text","text-zero","json"), default='text',
                                 help="Kind of output ('text-zero' means zero-terminated textual output)")
    argument_parser.add_argument('--all-candidates', '-a', action='store_true',
                                 help='Output all candidates (do not ask for selection)')
    argument_parser.add_argument('--output', '-o', choices=("password","username","both"), default='both',
                                 help='Which information to include in the output')
    argument_parser.add_argument('--output-no-title', '-T', action='store_true',
                                 help='Do not include title field in output')
    argument_parser.add_argument('--output-no-prefix', '-P', action='store_true',
                                 help='Do not prefix output lines with field type (text output only)')
    arguments = argument_parser.parse_args()

    candidates = fetch_candidates(arguments.url, arguments.auth_id, arguments.store_keyfile)

    output_title = not arguments.output_no_title
    output_prefix = not arguments.output_no_prefix
    output_username = arguments.output != "password"
    output_password = arguments.output != "username"

    terminator = "\n" if arguments.format == "text" else "\0"

    def print_text_entry(entry):
        title, username, password = entry
        if output_prefix:
            if output_title:
                print("title", title, end=terminator)
            if output_username:
                print("username", username, end=terminator)
            if output_password:
                print("password", password, end=terminator)
        else:
            if output_title:
                print(title, end=terminator)
            if output_username:
                print(username, end=terminator)
            if output_password:
                print(password, end=terminator)

    def get_dict_entry(entry):
        title, username, password = entry
        result = {}
        if output_title:
            result["title"] = title
        if output_username:
            result["username"] = username
        if output_password:
            result["password"] = password
        return result

    if arguments.all_candidates:
        if arguments.format in ("text", "text-zero"):
            for entry in sorted(candidates.values()):
                print_text_entry(entry)
        elif arguments.format == "json":
            output = []
            for entry in sorted(candidates.values()):
                output.append( get_dict_entry(entry) )
            json.dump(output, sys.stdout)
    else:
        if len(candidates) == 1 and not arguments.always_select:
            entry = candidates.popitem()[1]
        else:
            selection = select_candidate(sorted(candidates), arguments.selector_command)
            if not selection:
                sys.exit(0)
            entry = candidates[selection]
        if arguments.format in ("text", "text-zero"):
            print_text_entry(entry)
        elif arguments.format == "json":
            json.dump(get_dict_entry(entry), sys.stdout)
