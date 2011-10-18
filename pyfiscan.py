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
    import stat
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
    parser.add_option(
        "", "--check-modes",
        action="store_true",
        dest="check_modes",
        help="Check if we are allowed to traverse directories (execution bit)")

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
            print('Permission denied when writing to file: %s' % logfile)
            sys.exit(2)
    logging.debug('Options are: %s' % opts)

    if opts.directory:
        logging.debug('Scanning recursively from path: %s' % opts.directory)
        traverse_recursive(opts.directory, opts.appname_to_scan, opts.check_modes)
    if opts.home:
        _users = opts.home
        logging.debug('Scanning predefined variables: %s' % _users)
        scan_predefined_directories(_users, opts.appname_to_scan, opts.check_modes)
    else:
        _users = '/home'
        logging.debug('Scanning predefined variables: %s' % _users)
        scan_predefined_directories(_users, opts.appname_to_scan, opts.check_modes)
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
    logging.debug('compare_versions: %s %s' % (secure_version, file_version))
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


def check_dir_execution_bit(path, check_modes):
    """Check if path has execution bit to check if site is public. Defaults to false."""
    if check_modes == None:
        return True
    if not os.path.exists(path):
        return
    if not os.path.isdir(path):
        return
    """http://docs.python.org/library/stat.html#stat.S_IXOTH"""
    if stat.S_IXOTH & os.stat(path)[stat.ST_MODE]:
        logging.debug('Execution bit set for directory: %s' % path)
        return True
    else:
        logging.debug('No execution bit set for directory: %s' % path)
        return False


def traverse_dir(path, appname_to_scan, check_modes, depth=3):
    """Traverses directory spesified amount
    path = start path
    depth = ammount of directories to traverse"""
    if not os.path.exists(path):
        return
    if not os.path.isdir(path):
        return
    try:
        if check_dir_execution_bit(path, check_modes):
            logging.debug('traverse_dir: Detecting applications (%s) from %s' % (appname_to_scan, path))
            detect_apps(path, appname_to_scan)
            entries = listdir(path)
            if depth == 0:
                return
            depth = depth - 1
            for entry in entries:
                if os.path.isdir(join(path, entry)) and os.path.islink(join(path, entry)) == False:
                    traverse_dir(join(path, entry), appname_to_scan, check_modes, depth)
    except KeyboardInterrupt:
        print("Interrupting..")
        sys.exit(1)


def traverse_recursive(path, appname_to_scan, check_modes):
    """Traverses directory recursively"""
    if not os.path.exists(path):
        print('Path does not exist: %s' % (path))
        logging.debug('Path does not exist: %s' % path)
        sys.exit(1)
    try:
        if check_dir_execution_bit(path, check_modes):
            logging.debug('traverse_recursive: Detecting applications (%s) from %s' % (appname_to_scan, path))
            detect_apps(path, appname_to_scan)
            entries = listdir(path)
            for entry in entries:
                if os.path.isdir(join(path, entry)) and os.path.islink(join(path, entry)) == False:
                    traverse_recursive(join(path, entry), appname_to_scan, check_modes)
    except KeyboardInterrupt:
        print("Interrupting..")
        sys.exit(1)
    except OSError, errno:
        if errno == 13:
            print('Permission denied: %s' % (path))
        else:
            pass


def scan_predefined_directories(path, appname_to_scan, check_modes):
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
            if check_dir_execution_bit(sites_dir, check_modes):
                for site in listdir(sites_dir):
                    traverse_dir(join(sites_dir, site, 'www'), check_modes, appname_to_scan)
                    traverse_dir(join(sites_dir, site, 'secure-www'), check_modes, appname_to_scan)
        if exists(pub_html_dir):
            if check_dir_execution_bit(sites_dir, check_modes):
                traverse_dir(pub_html_dir, check_modes, appname_to_scan)


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
    
    # CVE-2005-3771 1.0.4   SA17675
    # CVE-2005-3772 1.0.4   SA17675
    # CVE-2005-3773 1.0.4   SA17675
    # CVE-2005-4650 1.0.4   SA17675
    #               1.0.7   SA18361
    # CVE-2006-0303 1.0.7   SA18513
    # CVE-2006-1047 1.0.8   SA19105
    # CVE-2006-1048 1.0.8   SA19105
    # CVE-2006-1049 1.0.8   SA19105
    # CVE-2006-1028 1.0.8   SA19105
    # CVE-2006-1030 1.0.8   SA19105
    #               1.0.10  SA20746
    # CVE-2010-1649 1.5.18  Bugtraq:40444 SA39964 OSVDB:65011 http://developer.joomla.org/security/news/314-20100501-core-xss-vulnerabilities-in-back-end.html
    # CVE-2011-2708 1.7.0   TODO: duplicate with CVE-2011-2710 and requested by me: http://www.openwall.com/lists/oss-security/2011/10/16/1
    # CVE-2011-2710 1.6.6   http://developer.joomla.org/security/news/357-20110701-xss-vulnerability.html
    #               1.7.1   http://developer.joomla.org/security/news/367-20110901-core-xss-vulnerability.html
    #               1.7.1   http://developer.joomla.org/security/news/369-20110903-core-information-disclosure.html
    data = {
    'Joomla': {
        'location': ['/libraries/joomla/version.php', '/includes/version.php'],
        'secure': '1.5.23',
#        'vulnerabilities':
#        [{'CVE-2010-4166': '1.5.22'}],
#    {'': ''},
#    {'' }],
        'regexp': ['.*?RELEASE.*?(?P<version>[0-9.]{1,})', '.*?DEV_LEVEL.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2011-2888, CVE-2011-2889, CVE-2011-2890',
        'fingerprint': detect_joomla
        },
    # TODO: Does not work with ancient 2003 versions
    # TODO: Without CVE
        # http://osvdb.org/show/osvdb/72141 http://secunia.com/advisories/44038/
        # http://secunia.com/advisories/8954/
        # http://secunia.com/advisories/23621/
        # http://secunia.com/advisories/23587/
        # http://secunia.com/advisories/24316/
        # http://secunia.com/advisories/24951/
        # http://secunia.com/advisories/28130/
        # OSBDB:72142 3.1.1
        # http://osvdb.org/show/osvdb/72097
        # http://osvdb.org/show/osvdb/72173
        # http://osvdb.org/show/osvdb/73721
    # CVE-2004-1559 1.2.1
    # CVE-2004-1584 1.2.1
    # CVE-2005-1687 1.5.1
    # CVE-2005-1688 1.5.1
    # CVE-2005-1810 1.5.1.2
    # CVE-2005-2612 1.5.2
    # CVE-2005-2107 1.5.1.3
    # CVE-2005-2108 1.5.1.3
    # CVE-2005-2109 1.5.1.3
    # CVE-2005-2110 1.5.1.3
    # CVE-2006-0985 2.0.2
    # CVE-2006-0986 2.0.2
    # CVE-2006-1012 2.0
    # CVE-2006-1796 2.0.2
    # CVE-2006-2667 2.0.3
    # CVE-2006-2702 2.0.3
    # CVE-2006-3389 2.1
    # CVE-2006-3390 2.1
    # CVE-2006-4028 2.0.4
    # CVE-2006-5705 2.0.5
    # CVE-2006-6016 2.0.5
    # CVE-2006-6017 2.0.5
    # CVE-2007-0106 2.0.6
    # CVE-2007-0539 2.1
    # CVE-2007-0540 2.1
    # CVE-2007-0541 2.1
    # CVE-2007-1049 2.1.1
    # CVE-2007-1277 2.1.2
    # CVE-2007-1622 2.0.10 / 2.1.3
    # CVE-2007-1732 N/A
    # CVE-2007-1893 2.1.3
    # CVE-2007-1894 2.1.3
    # CVE-2007-1897 2.1.3
    # CVE-2007-2921 2.2
    # CVE-2007-3140 2.2.1
    # CVE-2007-3238 N/A
    # CVE-2007-3543 2.2.1
    # CVE-2007-3544 2.2.1
    # CVE-2007-4139 2.2.2
    # CVE-2007-4893 2.2.3
    # CVE-2007-4894 2.2.3
    # CVE-2007-5710 2.3.1
    # CVE-2007-6013 2.3.2
    # CVE-2007-6318 N/A
    # CVE-2008-0664 2.3.3
    # CVE-2008-1930 2.5.1
    # CVE-2008-2068 2.5.1
    # CVE-2008-2146 2.2.3
    # CVE-2008-4106 2.6.2
    # CVE-2008-4107 2.6.2
    # CVE-2008-4769 2.5.1
    # CVE-2008-5278 2.6.5
    # CVE-2009-2762 2.8.4
    # CVE-2009-2851 2.8.2
    # CVE-2009-2853 2.8.3
    # CVE-2009-2854 2.8.3
    # CVE-2009-3622 2.8.5 
    # CVE-2009-3890 2.8.6
    # CVE-2009-3891 2.8.6
    # CVE-2010-0682 2.9.2
    # CVE-2011-3122 3.1.3
    # CVE-2011-3126 3.1.3
    # CVE-2011-3127 3.1.3
    # CVE-2011-3128 3.1.3
    # CVE-2011-3129 3.1.3
    # CVE-2011-3130 3.1.3
    'WordPress': {
        'location': ['/wp-includes/version.php'],
        'secure': '3.1.3',
        'regexp': ['\$wp_version.*?(?P<version>[0-9.]+)'],
        'cve': 'CVE-2011-3122, CVE-2011-3126, CVE-2011-3127, CVE-2011-3128, CVE-2011-3129, CVE-2011-3130',
        'fingerprint': detect_general
        },
    # TODO: SA32686 SA14001 SA11832 SA11807 SA10318
    # CVE-2007-0857 1.5.7 (SA24096)
    # CVE-2007-0901 1.5.8 (SA24138)
    # CVE-2007-2423 1.5.8 (SA24138)
    # CVE-2007-2637 1.5.8 (SA24138)
    # CVE-2008-0780 1.6.1 (SA29010)
    # CVE-2008-0781 1.6.1 (SA29010)
    # CVE-2008-0782 1.6.1 (SA29010)
    # CVE-2008-1098 1.6.1 (SA29010)
    # CVE-2008-1099 1.6.1 (SA29010)
    # CVE-2008-1937 1.6.3 (SA29894)
    # CVE-2008-3381 1.7.1 (SA31135)
    # CVE-2009-0260 1.8.2 (SA33593)
    # CVE-2009-0312 1.8.2 (SA33593)
    # CVE-2009-1482 1.8.3 (SA34821)
    # CVE-2009-4762 1.8.4 (SA35407)
    # CVE-2010-0667 1.9.1 (SA38242)
    # CVE-2010-0668 1.9.2 (SA38444)
    # CVE-2010-0669 1.9.2 (SA38444)
    # CVE-2010-0717 1.9.2 (SA38444)
    # CVE-2010-0828 1.9.3 (SA39188)
    # CVE-2010-2487 1.9.3 (SA40043)
    # CVE-2010-2969 1.9.3 (SA40043)
    # CVE-2010-2970 1.9.3 (SA40043)
    # CVE-2011-1058 1.9.3 (SA43413)
    'MoinMoin': {
        'location': ['/MoinMoin/version.py'],
        'secure': '1.9.3',
        'regexp': ['.*?release.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2011-1058 SA43413',
        'fingerprint': detect_general
        },
    #               1.0.3 (SA23582)
    # CVE-2007-2473 1.0.6 (SA25082)
    # CVE-2007-5056 1.1.4.1 (SA26928)
    # CVE-2007-5441 1.1.4.1 (SA26928)
    # CVE-2007-5442 1.1.4.1 (SA26928)
    # CVE-2007-6656 1.2.3 (SA28285)
    # CVE-2008-2267 1.2.5 (SA30208)
    # CVE-2008-5642 1.5 (SA32924) Unpatched
    #               1.6.3 (SA36255)
    # CVE-2010-1482 1.7.1
    # CVE-2010-2797 1.8.1 (SA40031)
    # CVE-2010-3882 1.8.1 (SA40031)
    # CVE-2010-3883 1.8.1 (SA40031)
    # CVE-2010-3884 1.8.1 (SA40031)
    'CMSMS' : {
        'location': ['version.php'],
        'secure': '1.8.1',
        'regexp': ['\$CMS_VERSION.*?(?P<version>[.0-9]{2,})'],
        'cve': 'CVE-2010-2797, CVE-2010-3882, CVE-2010-3883, CVE-2010-3884, SA40031',
        'fingerprint': detect_general
        },
    # CVE-2004-2261 0.615   SA11567
    #               0.615   SA9369
    #               0.616   SA11740
    #               0.616   SA11693
    #               0.616   SA10115
    # CVE-2004-2262 0.617   SA13657
    #               0.6171  SA15282
    # CVE-2005-2327 0.6172  SA16117
    #               0.6174  SA17237
    # CVE-2005-4052 0.6175  SA17890
    #               0.6175  SA18023
    #               0.6175  SA16357
    #               0.6175  SA15733
    #               0.6175  SA11696
    # CVE-2006-0682 0.7.2   SA18816
    # CVE-2006-2416 0.7.4   SA20089
    # CVE-2006-2590 0.7.5   SA20262
    # CVE-2006-2591 0.7.5   SA20262
    #               0.7.17  SA38330
    #               0.7.22  SA34169
    #               0.7.23  SA41034
    #               0.7.24  SA41494 HTB22603
    #               0.7.24  SA31394
    # CVE-2006-3259 0.7.24  SA20727
    # CVE-2006-4757 0.7.24  SA20727
    # CVE-2006-4794 0.7.24  SA20727
    # CVE-2006-5786 0.7.24  SA20727
    # CVE-2008-5320 0.7.24  SA32322
    # CVE-2008-6208 0.7.24  SA34109
    # CVE-2009-3444 0.7.24  SA36832
    # CVE-2009-4083 0.7.24  SA36832
    # CVE-2009-4084 0.7.24  SA36832
    # CVE-2009-1409 0.7.24  SA34823
    # CVE-2010-0996 0.7.20  SA39013
    # CVE-2010-0997 0.7.20  SA39013
    # CVE-2010-2098 0.7.22  SA39498
    # CVE-2010-2099 0.7.22  SA39498
    #               0.7.25  SA41597 HTB2260
    #                       SA44061
    #                       SA44968
    'e107' : {
        'location': ['/e107_admin/ver.php'],
        'secure': ' 0.7.24',
        'regexp': ['.*?e107_version.*?(?P<version>[.0-9]{2,})'],
        'cve': 'N/A',
        'fingerprint': detect_general
        },
    # CVE-2008-1766 3.0.1       SA29801
    # CVE-2008-6506 3.0.4       SA33166
    # CVE-2008-6507 3.0.4       SA33166
    # CVE-2010-1627 3.0.7PL1    SA38837
    # CVE-2010-1630 3.0.5       SA38264
    # CVE-2011-0544 3.0.8       SA42343
    'phpBB3' : {
        'location': ['/includes/constants.php'],
        'secure': '3.0.8',
        'regexp': ['.*?PHPBB_VERSION.*?(?P<version>3[0-9.]{1,})'],
        'cve': 'CVE-2011-0544, SA42343',
        'fingerprint': detect_general
        }
    }

    main(sys.argv[1:])
