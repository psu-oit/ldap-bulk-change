#!/usr/bin/env python3

import os
import sys
import argparse
import configparser
import re
import logging

# http://pythonhosted.org/python3-ldap/
from ldap3 import Connection, Server, MODIFY_REPLACE

__author__ = 'hhauer'

logger = logging.getLogger(__name__)

# Start by setting up argparse
parser = argparse.ArgumentParser(description='Make a bulk change to users in LDAP.')
parser.add_argument('--verbose', '-v', action='count', default=0,
                    help="Set the verbosity level.")
parser.add_argument('--nossl', action="store_true",
                    help="Connect without SSL.")
parser.add_argument('--environment', '-e',
                    help="Use one of the environments defined in ~/.ldap_envs instead.")
parser.add_argument('--dry-run', '-n', action="store_true",
                    help="Do not make changes")
parser.add_argument('--log', '-l',
                    help="Log to file instead of stdout, overwrites file")
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
    setup_logging(args)
    if args.dry_run:
        logger.info("Dry run mode, no changes will be made")
    target = load_config(args)
    connection = connect(args, target)
    search_results = search(args, target, connection)
    change_set = apply_regex(args, search_results)
    commit(args, connection, change_set)
    disconnect(connection)


def setup_logging(args):
    levels = {
        0: logging.CRITICAL,
        1: logging.INFO,
        2: logging.DEBUG
    }
    logger.setLevel(levels.get(args.verbose, logging.DEBUG))
    if args.log:
        logger.addHandler(logging.FileHandler(args.log, mode="w"))
    else:
        logger.addHandler(logging.StreamHandler(sys.stdout))


def load_config(args):
    # Load any environment configurations.
    config = configparser.ConfigParser()
    config.read(['.ldap_envs', os.path.expanduser('~/.ldap_envs')])
    # Build a record of the target environment.
    if args.environment is not None:
        try:
            logger.debug("Reading from environment %s", args.environment)
            target = dict(config[args.environment])
        except KeyError:
            logger.critical("environment %s does not exist", args.environment)
            sys.exit(1)
    else:
        # Default all values to None
        logger.info("No environment given, reading from CLI flags")
        target = dict.fromkeys(CONFIG_KEYS)

    # Overwrite default/environment config values with contents of args
    for config_key in CONFIG_KEYS:
        if getattr(args, config_key) is not None:
            target[config_key] = getattr(args, config_key)

    # Make sure we have all the necessary parameters one way or another.
    soft_fail = False
    for key, value in target.items():
        if value is None:
            logger.critical("No value for parameter: %s", key)
            soft_fail = True

    if soft_fail:
        sys.exit(1)

    return target


def connect(args, target):
    # Open a connection to the LDAP server.
    logger.debug("Connecting to %s:%s, SSL=%r", target['host'], target['port'],
                 not args.nossl)
    if args.nossl:
        server = Server(target['host'], port=int(target['port']))
    else:
        server = Server(target['host'], port=int(target['port']), use_ssl=True)

    logger.debug("Authenticating with user=%s, password=<omitted>",
                 target['bind_dn'])
    return Connection(server, user=target['bind_dn'],
                      password=target['password'], auto_bind=True)


def search(args, target, connection):
    # Find our set of target DNs.
    connection.search(target['base_dn'], args.filter,
                      attributes=[args.change_attr])

    results = {}
    for record in connection.response:
        results[record['dn']] = record['attributes'][args.change_attr]

    logger.info("Retrieved %d records", len(results))

    return results


def apply_regex(args, search_results):
    regexp = re.compile(args.regexp)
    change_set = {}

    for dn, attributes in search_results.items():
        new_values = [regexp.sub(args.replace, attr)
                      for attr in attributes]

        change_set[dn] = {
            args.change_attr: (MODIFY_REPLACE, new_values),
        }

    return change_set


def commit(args, connection, change_set):
    # Set the new values in LDAP.
    for dn, attributes in change_set.items():
        if args.dry_run:
            logger.info("Would modify %s", dn)
        else:
            connection.modify(dn, attributes)
            logger.info("Modify: %s: %s", dn,
                        connection.result['description'])

def disconnect(connection):
    logger.debug("Disconnecting from server")
    connection.unbind()

if __name__ == "__main__":
    main()
