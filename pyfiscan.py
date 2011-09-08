#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pyfiscan

Free web-application vulnerability and version scanner

This python program can be used to locate out-dated versions of common web-soft
ware in Unix/Linux-servers. The best example is hosting-providers keeping eye o
n their users installations to keep up with security-updates.

It supports content management systems, blogging softwares, image-galleries, ve
rsion controlling programs, wikis, admin panels and bulletin boards.

@author Henri 'fgeek' Salo <henri@nerv.fi>
@copyright Copyright (c) 2009-2011 Henri Salo
@licence BSD
"""

try:
    import sys
    import os
    import time
    import logging
    import csv
    import re
    from collections import defaultdict
    from os import listdir
    from os.path import join
    from os.path import exists
    from optparse import OptionParser
except ImportError, error:
    print('Import error: %s' % error)
    sys.exit(1)

# Initializing stats-dictionary. Lambda defaults value to zero
stats = defaultdict(lambda: 0)
# Logging levels
LEVELS = {'debug': logging.DEBUG}


def main(argv):
    """Argument handling and printing of statistics"""
    usage = "Usage: %prog [-r/--recursive <directory>] [--home <directory>] [-d/--debug]"
    parser = OptionParser(
        usage=usage,
        version="%prog beta",
        description="If you do not spesify recursive scanning predefined directories are scanned, which are: /home/user/sites/www /home/user/sites/secure-www /home/user/public_html/www /home/user/public_html/secure-www")
    parser.add_option(
        "-r", "--recursive",
        action="store",
        type="string",
        dest="directory",
        help="Scans directories recurssively.")
    parser.add_option(
        "", "--home",
        action="store",
        type="string",
        dest="home",
        help="Spesifies where the home-directories are located")
    parser.add_option(
        "-a", "--application",
        action="store",
        type="string",
        dest="appname_to_scan",
        help="Spesifies application to scan")
    parser.add_option(
        "-d", "--debug",
        action="store_true",
        dest="verbose",
        help="Put debugging mode on.")

    (opts, args) = parser.parse_args()

    """This writes log-file if debug-level is given. Logic is made to accept different levels."""
    if opts.verbose == True:
        """Hardcoded, because there is no other levels used at the moment"""
        level_name = "debug"
        level = LEVELS.get(level_name, logging.NOTSET)
        logfile = level_name + ".log"
        try:
            logging.basicConfig(filename=logfile, level=level)
        except IOError:
            print('Permission denied when writitin to file: %s' % logfile)
            sys.exit(2)
    logging.debug('Options are: %s' % opts)

    if opts.directory:
        logging.debug('Scanning recursively from path: %s' % opts.directory)
        traverse_recursive(opts.directory, opts.appname_to_scan)
    if opts.home:
        _users = opts.home
        logging.debug('Scanning predefined variables: %s' % _users)
        scan_predefined_directories(_users, opts.appname_to_scan)
    else:
        _users = '/home'
        logging.debug('Scanning predefined variables: %s' % _users)
        scan_predefined_directories(_users, opts.appname_to_scan)

    """Let's count how many applications have vulnerabilities"""
    int_not_vuln = 0
    for (appname, application) in data.iteritems():
        if stats[appname] == 0:
            int_not_vuln = int_not_vuln + 1
    """If no vulnerabilities found print message and exit. Otherwise print statistics of how many vulnerabilities found from spesific application """
    if len(stats) == int_not_vuln:
        print('No vulnerabilities found.')
        sys.exit(1)
    else:
        print('Statistics:\n')
        for (appname, application) in data.iteritems():
            if not stats[appname] == 0:
                print("%s: %i" % (appname, stats[appname]))


def grep_from_file(version_file, regexp):
    """Grepping file with predefined regexp to find a version. This returns m.group from regexp: (?P<version>foo)"""
    logging.debug('Grepping version number from file: %s using regexp: %s' % (version_file, regexp))
    version_file = open(version_file, 'r')
    source = version_file.readlines()
    version_file.close()
    prog = re.compile(regexp)

    for line in source:
        match = prog.match(line)
        try:
            found_match = match.group('version')
            logging.debug('Found match: %s' % found_match)
            return found_match
        except re.error:
            logging.debug('Not a valid regular expression: %s' % regexp)
        except AttributeError:
            pass


def detect_general(source_file, regexp):
    """Detects from file if the file has version information. Uses first regexp-match."""
    if not os.path.isfile(source_file) and not regexp:
        return
    file_version = grep_from_file(source_file, regexp[0])
    return file_version


def detect_joomla(source_file, regexp):
    """Detects from file if the file has version information of Joomla"""
    if not os.path.isfile(source_file) and not regexp:
        return
    logging.debug('Dectecting Joomla from: %s' % source_file)
    release_version = grep_from_file(source_file, regexp[0])
    dev_level_version = grep_from_file(source_file, regexp[1])
    if release_version and dev_level_version:
        file_version = release_version + "." + dev_level_version
        return file_version


def compare_versions(secure_version, file_version, appname):
    """Comparison of found version numbers. Value current_version is predefined and file_version is found from file using grep. Value appname is used to separate different version numbering syntax"""
    ver1 = secure_version.split('.')
    ver2 = file_version.split('.')
    ver1_bigger = 0

    for i in range(len(min(ver1, ver2))):
        if int(ver1[i]) == int(ver2[i]):
            pass
        elif int(ver1[i]) > int(ver2[i]):
            ver1_bigger = 1
            return ver1_bigger
        else:
            return ver1_bigger


def csv_add(appname, version_file, file_version, secure_version, cve):
    """Writes list of found vulnerabilities in CVS-format."""
    # ISO 8601 with hours:minutes:seconds
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    name_of_logfile = sys.argv[0] + '-vulnerabilities-' + time.strftime("%Y-%m-%d") + '.csv'
    try:
        writer = csv.writer(open(name_of_logfile, "a"), delimiter='|', quotechar='|')
        logged_data = timestamp, appname, version_file, file_version, secure_version, cve
        writer.writerow(logged_data)
    except Exception, error:
        logging.debug('Exception in csv_add: %s' % error)


def detect_apps(curdir, appname_to_scan):
    """Searches correct full path for vulnerable and out-dated applications. Launches the real detection."""
    logging.debug('Detecting applications (%s) from %s' % (appname_to_scan, curdir))
    if not os.path.exists(curdir):
        return
    """Loop trough all applications in fingerprint database."""
    for (appname, application) in data.iteritems():
        for location in application['location']:
            logging.debug('Location is: %s. Current directory: %s' % (location, curdir))
            directory = os.path.split(location)[0]
            if curdir.endswith(directory):
                version_file = curdir + '/' + os.path.split(location)[1]
                if os.path.exists(version_file):
                    if not application['fingerprint']:
                        """This verifies that data-dictionary has fingerprint for application in question."""
                        print('Error. No fingerprint found for %s-application.' % appname)
                        sys.exit(1)
                    logging.debug('detect_apps: finding version number from file %s with regexp %s' % (version_file, application['regexp']))
                    file_version = application["fingerprint"](version_file, application['regexp'])
                    logging.debug('detect_apps: trying to go ahead with file_version %s and data[appname] %s' % (file_version, data[appname]))
                    if file_version and data[appname]:
                        if compare_versions(application['secure'], file_version, data[appname]):
                            stats[appname] = stats[appname] + 1
                            stats['total'] = stats['total'] + 1
                            if application['secure']:
                                stats['cve'] = stats['cve'] + 1
                                print('%i: %s (#%i) with version %s from %s with vulnerability %s. This installation should be updated to at least version %s.' % (stats['total'], appname, stats[appname], file_version, version_file, application['cve'], application['secure']))
                                csv_add(appname, version_file, file_version, application['secure'], application['cve'])


def traverse_dir(path, appname_to_scan, depth=3):
    """Traverses directory spesified amount
    path = start path
    depth = ammount of directories to traverse"""
    if not os.path.exists(path):
        return
    if not os.path.isdir(path):
        return
    try:
        detect_apps(path, appname_to_scan)

        entries = listdir(path)
        if depth == 0:
            return
        depth = depth - 1
        for entry in entries:
            if os.path.isdir(join(path, entry)) and os.path.islink(join(path, entry)) == False:
                traverse_dir(join(path, entry), appname_to_scan, depth)
    except KeyboardInterrupt:
        print("Interrupting..")
        sys.exit(1)


def traverse_recursive(path, appname_to_scan):
    """Traverses directory recursively"""
    if not os.path.exists(path):
        print('Path does not exist: %s' % (path))
        logging.debug('Path does not exist: %s' % path)
        sys.exit(1)
    try:
        detect_apps(path, appname_to_scan)
        entries = listdir(path)
        for entry in entries:
            if os.path.isdir(join(path, entry)) and os.path.islink(join(path, entry)) == False:
                traverse_recursive(join(path, entry), appname_to_scan)
    except KeyboardInterrupt:
        print("Interrupting..")
        sys.exit(1)
    except OSError, errno:
        if errno == 13:
            print('Permission denied: %s' % (path))
        else:
            pass


def scan_predefined_directories(path, appname_to_scan):
    """Starts traversing in predefined directories
        sites/www/
        sites/secure-www/
        public_html/
    """
    if not exists(path):
        print('Error. No such directory: %s' % (path))
        sys.exit(1)
    try:
        _userdirs = listdir(path)
    except OSError, errno:
        print('Permission denied: %s' % (path))
        return
    for directory in _userdirs:
        sites_dir = join(path, directory, 'sites')
        pub_html_dir = join(path, directory, 'public_html')
        if exists(sites_dir):
            for site in listdir(sites_dir):
                traverse_dir(join(sites_dir, site, 'www'), appname_to_scan)
                traverse_dir(join(sites_dir, site, 'secure-www'), appname_to_scan)
        if exists(pub_html_dir):
            traverse_dir(pub_html_dir, appname_to_scan)


if __name__ == "__main__":

    """Please note that nothing goes to terminal if cve-field is not defined
    Structure of data-dictionary:

    Software/program
        Look file from this directory hierarchy
        Filename
        Secure version
        Regexp used in detection functions
        CVE-identifier and other security announcement ID's
    """

    data = {
    'joomla': {
        'location': ['/libraries/joomla/version.php', '/includes/version.php'],
        'secure': '1.5.23',
#        'vulnerabilities':
#        [{'CVE-2010-4166': '1.5.22'}],
#    {'': ''},
#    {'' }],
        'regexp': ['.*?RELEASE.*?(?P<version>[0-9.]{1,})', '.*?DEV_LEVEL.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2011-2888, CVE-2011-2889, CVE-2011-2890',
        'fingerprint': detect_joomla}}

    main(sys.argv[1:])
