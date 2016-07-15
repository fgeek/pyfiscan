#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This script is used to convert email address and home directory location of
pyfiscan result files to Kapsi's format.
"""

try:
    import sys
    import csv
    import time
    import re
    from admsikteeri import *
except ImportError, e:
    sys.exit(e)


def lookup_member_email(alias):
    """Fetches member email using member Unix-account ID. Return email."""
    print('Looking alias: %s' % alias)
    id = lookup_alias(alias)
    m = get_member_details(id)
    return m.email


def removePrefix(str, prefix):
    """Removes prefix of str."""
    return str[len(prefix):] if str.startswith(prefix) else str


def csv_add(member_email, timestamp, appname, version_file, file_version, secure_version, cve):
    # ISO 8601 with hours:minutes:seconds
    name_of_logfile = 'kapsi-vulnerabilities-' + time.strftime("%Y-%m-%d") + '.csv'
    try:
        writer = csv.writer(open(name_of_logfile, "a"), delimiter='|', quotechar='|')
        logged_data = member_email, timestamp, appname, version_file, file_version, secure_version, cve
        writer.writerow(logged_data)
    except Exception, error:
        logging.debug('Exception in csv_add: %s' % error)


def read_csv(csv_file):
    """Reads data in from CSV-file."""
    with open(csv_file[0], 'rb') as f:
        reader = csv.reader(f, delimiter='|', quotechar='|')
        for row in reader:
            # row two is version file location
            version_file_stripped = re.sub(r'\/mnt\/webroots\/[0-9]', '', row[2])
            version_file_realpath = re.sub(r'\/mnt\/webroots\/[0-9]', '/var/www/userhome', row[2])
            alias = version_file_stripped.split('/')[1]
            """Data to new CSV"""
            member_email = lookup_member_email(alias)
            print('Returned: %s' % member_email)
            member_email = alias + '@kapsi.fi,' + member_email
            timestamp = row[0]
            appname = row[1]
            # version_file_realpath
            file_version = row[3]
            secure_version = row[4]
            cve = row[5]
            if member_email:
                csv_add(member_email, timestamp, appname, version_file_realpath, file_version, secure_version, cve)


read_csv(sys.argv[1:])
