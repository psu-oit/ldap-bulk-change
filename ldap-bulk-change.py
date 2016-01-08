#!/usr/bin/env python3

import os
import sys
import argparse
import configparser
import re

# http://pythonhosted.org/python3-ldap/
from ldap3 import Connection, Server, MODIFY_REPLACE

__author__ = 'hhauer'

# Start by setting up argparse
parser = argparse.ArgumentParser(description='Make a bulk change to users in LDAP.')
parser.add_argument('--verbose', '-v', action='count',
                    help="Set the verbosity level.")
parser.add_argument('--nossl', action="store_true",
                    help="Connect without SSL.")
parser.add_argument('--environment', '-e',
                    help="Use one of the environments defined in ~/.ldap_envs instead.")
parser.add_argument('--dry-run', '-n', action="store_true",
                    help="Do not make changes")
# TODO: Add dry-run option to show what changes would be made.
# TODO: Make verbose do something.

# Command line environment options.
parser.add_argument('--host', help="The LDAP host URL.")
parser.add_argument('--port', help="The LDAP port.", default="636")
parser.add_argument('--bind-dn', help="The DN to bind as.")
parser.add_argument('--password', help="The password for the bind DN.")
parser.add_argument('--base-dn', help="The base DN from which to search.")

# The action we actually want to take.
parser.add_argument('--filter', help="An LDAP filter to limit the DNs operated on.",
                    default="(objectClass=*)")
parser.add_argument('change_attr', help="The attribute to be changed.")
parser.add_argument('regexp', help="A regexp used to determine the new value of change_attr.")
parser.add_argument('replace', help="The value to substitute into the new value of change_attr.")

CONFIG_KEYS = ['host', 'port', 'bind_dn', 'password', 'base_dn']


def main():
    args = parser.parse_args()
    target = load_config(args)
    connection = connect(args, target)
    search_results = search(args, target, connection)
    change_set = apply_regex(args, search_results)
    commit(args, connection, change_set)
    connection.unbind()


def error(msg, *args, **kwargs):
    print(msg.format(*args, **kwargs), file=sys.stderr)


def load_config(args):
    # Load any environment configurations.
    config = configparser.ConfigParser()
    config.read(['.ldap_envs', os.path.expanduser('~/.ldap_envs')])
    # Build a record of the target environment.
    if args.environment is not None:
        try:
            target = config[args.environment].copy()
        except KeyError:
            error("Error: environment {} does not exist", args.environment)
            sys.exit(1)
    else:
        # Default all values to None
        target = dict.fromkeys(CONFIG_KEYS)

    # Overwrite default/environment config values with contents of args
    for config_key in CONFIG_KEYS:
        if getattr(args, config_key) is not None:
            target[config_key] = getattr(args, config_key)

    # Make sure we have all the necessary parameters one way or another.
    soft_fail = False
    for key, value in target.items():
        if value is None:
            error("No value for parameter: {}", key)
            soft_fail = True

    if soft_fail:
        sys.exit(1)

    return target


def connect(args, target):
    # Open a connection to the LDAP server.
    if args.nossl:
        server = Server(target['host'], port=int(target['port']))
    else:
        server = Server(target['host'], port=int(target['port']), use_ssl=True)

    return Connection(server, user=target['bind_dn'],
                      password=target['password'], auto_bind=True)


def search(args, target, connection):
    # Find our set of target DNs.
    connection.search(target['base_dn'], args.filter,
                      attributes=args.change_attr)

    results = {}
    for record in connection.response:
        results[record['dn']] = record['attributes'][args.change_attr]

    return results


def apply_regex(args, search_results):
    regexp = re.compile(args.regexp)
    change_set = {}

    for dn in search_results:
        new_values = [regexp.sub(args.replace, attr)
                      for attr in change_set[dn]]

        change_set[dn] = {
            args.change_attr: (MODIFY_REPLACE, new_values),
        }

    return change_set


def commit(args, connection, change_set):
    # Set the new values in LDAP.
    for dn in change_set:
        if not args.dry_run:
            connection.modify(dn, change_set[dn])
        print("Modify: {}: {}".format(dn, connection.result['description']))


if __name__ == "__main__":
    main()
