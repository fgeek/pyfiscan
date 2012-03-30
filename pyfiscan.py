#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pyfiscan

Pyfiscan is free web-application vulnerability and version scanner, which is python program and can be used to locate out-dated versions of common web-software in Unix/Linux-servers. The best example is hosting-providers keeping eye on their users installations to keep up with security-updates. It supports content management systems, blogging softwares, image-galleries, version controlling programs, wikis, admin panels and bulletin boards.

@author Henri 'fgeek' Salo <henri@nerv.fi>
@copyright Copyright (c) 2009-2011 Henri Salo
@licence BSD

Known issues and/or bugs:
1) If instance is upgraded from Joomla 1.6.1 to 1.7.x by unzipping there will be both version files libraries/joomla/version.php and includes/version.php where first is the old one.
"""

try:
    import sys
    import os
    import time
    import logging
    import csv
    import re
    import stat # interpreting the results of os.[stat,fstat,lstat]
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
        traverse_recursive(opts.directory, opts.check_modes)
    elif opts.home:
        _users = opts.home
        logging.debug('Scanning predefined variables: %s' % _users)
        scan_predefined_directories(_users, opts.check_modes)
    else:
        _users = '/home'
        logging.debug('Scanning predefined variables: %s' % _users)
        scan_predefined_directories(_users, opts.check_modes)
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


def detect_apps(curdir):
    """Searches correct full path for vulnerable and out-dated applications. Launches the real detection."""
    if not os.path.exists(curdir):
        return
    """Loop trough all applications in fingerprint database."""
    for (appname, application) in data.iteritems():
        for location in application['location']:
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


def traverse_dir(path, check_modes):
    """Traverses directory spesified amount where path is start path."""
    if not os.path.exists(path):
        return
    if not os.path.isdir(path):
        return
    try:
        if check_dir_execution_bit(path, check_modes):
            detect_apps(path)
            try:
                entries = listdir(path)
            except OSError as (errno, strerror):
                print "I/O error({0}): {1} {2}".format(errno, strerror, path)
                print time.strftime("%Y-%b-%d %H:%M:%S", time.localtime())
                return
            for entry in entries:
                if os.path.isdir(join(path, entry)) and os.path.islink(join(path, entry)) == False:
                    traverse_dir(join(path, entry), check_modes)
    except KeyboardInterrupt:
        print("Interrupting..")
        sys.exit(1)


def traverse_recursive(path, check_modes):
    """Traverses directory recursively"""
    if not os.path.exists(path):
        print('Path does not exist: %s' % (path))
        logging.debug('Path does not exist: %s' % path)
        sys.exit(1)
    try:
        if check_dir_execution_bit(path, check_modes):
            detect_apps(path)
            entries = listdir(path)
            for entry in entries:
                if os.path.isdir(join(path, entry)) and os.path.islink(join(path, entry)) == False:
                    traverse_recursive(join(path, entry), check_modes)
    except KeyboardInterrupt:
        print("Interrupting..")
        sys.exit(1)
    except OSError, errno:
        if errno == 13:
            print('Permission denied: %s' % (path))
        else:
            pass


def scan_predefined_directories(path, check_modes):
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
                    traverse_dir(join(sites_dir, site, 'www'), check_modes)
                    traverse_dir(join(sites_dir, site, 'secure-www'), check_modes)
        if exists(pub_html_dir):
            if check_dir_execution_bit(sites_dir, check_modes):
                traverse_dir(pub_html_dir, check_modes)


if __name__ == "__main__":
    """Please note that nothing goes to terminal if cve-field is not defined
    Structure of data-dictionary:

    - Software/program
        - Look file from this directory hierarchy
        - Filename
        - Secure version
        - Regexp used in detection functions
        - CVE-identifier and other security announcement ID's

    To-be schema:
    'vulnerabilities':
        [{'CVE-2010-4166': '1.5.22'}], {'': ''}, {'' }],

    Data should include at least following:
    - CVSS2
    - OSVDB
    - Secunia
    - Publication date
    - Fixed date
    - ISS X-Force ID
    - SecurityTracker Alert ID:
    - Vendor URL
    """

    data = {
    # CVE-2006-0303 1.0.7   OSVDB:22531,22532,22533,2253422535 SA18513
    # CVE-2006-1047 1.0.8   OSBDB:31287 SA19105
    # CVE-2006-1048 1.0.8   OSVDB:23822 SA19105
    # CVE-2006-1049 1.0.8   OSVDB:23819 SA19105
    # CVE-2006-1028 1.0.8   OSVDB:23817 SA19105
    # CVE-2006-1030 1.0.8   OSVDB:23818 SA19105
    # CVE-2006-7247 1.0.10  OSVDB:26626 SA20746
    # CVE-2006-3480 1.0.10  OSVDB:26913,26917,26918
    # CVE-2006-4468 1.0.11  OSVDB:28339,28343 http://www.joomla.org/content/view/1841/78/ http://www.joomla.org/content/view/1843/74/
    # CVE-2006-4471 1.0.11  OSVDB:28353 SA21666 http://www.joomla.org/content/view/1841/78/ http://www.joomla.org/content/view/1843/74/
    # CVE-2006-4472 1.0.11  OSVDB:28347 SA21666 http://www.joomla.org/content/view/1841/78/ http://www.joomla.org/content/view/1843/74/
    # CVE-2006-4474 1.0.11  OSVDB:28348,28349,28350,28351 SA21666 http://www.joomla.org/content/view/1841/78/ http://www.joomla.org/content/view/1843/74/
    # CVE-2006-4476 1.0.11  OSVDB:28352,28355,28354,28357,28358 SA21666 http://www.joomla.org/content/view/1841/78/ http://www.joomla.org/content/view/1843/74/
    # CVE-2006-6832 1.0.12  OSVDB:32519 SA23563
    # CVE-2006-6833 1.0.12  OSVDB:32521 SA23563
    # CVE-2006-6834 1.0.12  OSVDB:32536 SA23563
    # CVE-2007-0374 1.0.12  OSVDB:32520 SA23563
    # CVE-2007-4188 1.0.13  OSVDB:38758 SA26239
    # CVE-2007-4189 1.0.13  OSVDB:38755,38756,38757 SA26239
    # CVE-2007-4190 1.0.13  OSVDB:38739 SA26239
    # CVE-2007-5577 1.0.13  OSVDB:37173 SA25804
    # CVE-2007-5427 1.0.14  OSVDB:37709 SA27196
    # CVE-2008-5671 1.0.15  OSVDB:42123 SA29106 http://www.joomla.org/announcements/release-news/4609-joomla-1015-released.html
    # CVE-2007-6642 1.5 RC4 OSVDB:41263 SA28219
    # CVE-2007-6643 1.5 RC4 OSVDB:39979 SA29257 
    # CVE-2008-1533 1.5.1   OSVDB:42894 SA28861 http://www.joomla.org/announcements/release-news/4560-joomla-1-5-1-released.html
    # CVE-2008-3225 1.5.4   OSVDB:46810 SA30974 http://www.joomla.org/announcements/release-news/5180-joomla-154-released.html
    # CVE-2008-3226 1.5.4   OSVDB:46811 SA30974 http://www.joomla.org/announcements/release-news/5180-joomla-154-released.html
    # CVE-2008-3227 1.5.4   OSVDB:46812 SA30974 http://www.joomla.org/announcements/release-news/5180-joomla-154-released.html
    # CVE-2008-3681 1.5.6   OSVDB:47476 SA31457 http://developer.joomla.org/security/news/241-20080801-core-password-remind-functionality.html
    # CVE-2008-4102 1.5.7   OSVDB:48226 SA31789 http://developer.joomla.org/security/news/272-20080902-core-random-number-generation-flaw.html
    # CVE-2008-4103 1.5.7   OSVDB:48227 SA31789 http://developer.joomla.org/security/news/273-20080903-core-commailto-spam.html
    # CVE-2008-4104 1.5.7   OSVDB:48228 SA31789 http://developer.joomla.org/security/news/274-20080904-core-redirect-spam.html
    # CVE-2008-4105 1.5.7   OSVDB:48225 SA31789 http://developer.joomla.org/security/news/271-20080901-core-jrequest-variable-injection.html
    # CVE-2008-6299 1.5.8   OSVDB:49801,49802 SA32622
    # CVE-2009-0113 1.5.9   OSVDB:51172 SA33377
    # CVE-2009-1279 1.5.10  OSVDB:53582,53583,53584 SA34551
    #               1.5.13              SA35899
    # CVE-2011-4912 1.5.14  OSVDB:56714 SA36097 http://developer.joomla.org/security/news/303-20090723-core-com-mailto-timeout-issue.html
    # CVE-2009-3945 1.5.15  OSVDB:59801 SA37262 http://developer.joomla.org/security/news/305-20091103-core-front-end-editor-issue-.html
    # CVE-2009-3946 1.5.15  OSVDB:59800 SA37262 http://developer.joomla.org/security/news/306-20091103-core-xml-file-read-issue.html
    # CVE-2010-1432 1.5.16  OSVDB:78012 SA39616 http://developer.joomla.org/security/news/311-20100423-core-negative-values-for-limit-and-offset.html
    # CVE-2010-1433 1.5.16  OSVDB:78011 SA39616 http://developer.joomla.org/security/news/310-20100423-core-installer-migration-script.html
    # CVE-2010-1434 1.5.16  OSVDB:64168 SA39616 http://developer.joomla.org/security/news/309-20100423-core-sessation-fixation.html
    # CVE-2010-1435 1.5.16  OSVDB:64167 SA39616 http://developer.joomla.org/security/news/308-20100423-core-password-reset-tokens.html
    # CVE-2010-1649 1.5.18  OSVDB:65011 Bugtraq:40444 SA39964 http://developer.joomla.org/security/news/314-20100501-core-xss-vulnerabilities-in-back-end.html
    # CVE-2010-2535 1.5.20  OSVDB:66394 SA40644 http://developer.joomla.org/security/news/315-20100701-core-sql-injection-internal-path-exposure.html http://developer.joomla.org/security/news/316-20100702-core-xss-vulnerabillitis-in-back-end.html http://developer.joomla.org/security/news/317-20100703-core-xss-vulnerabillitis-in-back-end.html http://developer.joomla.org/security/news/318-20100704-core-xss-vulnerabillitis-in-back-end.html
    # CVE-2010-3712 1.5.21  OSVDB:68625 SA41772 http://developer.joomla.org/security/news/322-20101001-core-xss-vulnerabilities.html
    # CVE-2010-4166 1.5.22  OSVDB:69026 SA42133 http://developer.joomla.org/security/news/323-20101101-core-sqli-info-disclosurevulnerabilities.html
    # CVE-2011-0005 1.5.22  OSVDB:70369
    # CVE-2011-2488 1.5.23
    # CVE-2011-2889 1.5.23
    # CVE-2011-2890 1.5.23
    #               1.5.24  http://developer.joomla.org/security/news/372-20111003-core-information-disclosure
    # CVE-2011-4321 1.5.25
    # CVE-2012-1598 1.5.26  http://developer.joomla.org/security/news/396-20120305-core-password-change
    # CVE-2012-1599 1.5.26  http://developer.joomla.org/security/news/397-20120306-core-information-disclosure
    'Joomla 1.5': {
        'location': ['/libraries/joomla/version.php', '/includes/version.php'],
        'secure': '1.5.26',
        'regexp': ['.*?\$RELEASE.*?(?P<version>1.[0,5])', '.*?DEV_LEVEL.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2012-1598 http://developer.joomla.org/security/news/396-20120305-core-password-change CVE-2012-1599 http://developer.joomla.org/security/news/397-20120306-core-information-disclosure',
        'fingerprint': detect_joomla
        },
    # CVE-2011-1151 1.6.1   OSVDB:75355 http://developer.joomla.org/security/news/328-20110201-core-sql-injection-path-disclosure.html
    # CVE-2010-4696 1.6.1   OSVDB:69026 SA42133 http://developer.joomla.org/security/news/328-20110201-core-sql-injection-path-disclosure.html http://yehg.net/lab/pr0js/advisories/joomla/core/[joomla_1.6.0]_sql_injection
    # CVE-2011-2509 1.6.4   OSVDB:73491 http://developer.joomla.org/security/news/352-20110604-xss-vulnerability.html
    # CVE-2011-4332 1.6.4   OSVDB:73487 http://developer.joomla.org/security/news/349-20110601-xss-vulnerabilities.html
    # CVE-2011-2710 1.6.6   http://developer.joomla.org/security/news/357-20110701-xss-vulnerability.html
    #               1.7.1   http://developer.joomla.org/security/news/367-20110901-core-xss-vulnerability.html
    # CVE-2011-3595 1.7.1   http://developer.joomla.org/security/news/368-20110902-core-xss-vulnerability
    #               1.7.1   http://developer.joomla.org/security/news/369-20110903-core-information-disclosure.html
    # CVE-2011-3629 1.7.2   OSVDB:76720,76721 SA46421 http://developer.joomla.org/security/news/370-20111001-core-information-disclosure.html
    #               1.7.2   http://developer.joomla.org/security/news/371-20111002-core-information-disclosure.html
    # CVE-2012-0819 1.7.4   http://developer.joomla.org/security/news/382-20120101-core-information-disclosure.html # TODO
    # CVE-2012-0820 1.7.4   http://developer.joomla.org/security/news/383-20120102-core-xss-vulnerability.html # TODO
    # CVE-2012-0821 1.7.4   http://developer.joomla.org/security/news/384-20120103-core-information-disclosure.html # TODO
    # CVE-2012-0822 1.7.4   http://developer.joomla.org/security/news/385-20120104-core-xss-vulnerability.html # TODO
    'Joomla 1.7': {
        'location': ['/libraries/joomla/version.php', '/includes/version.php'],
        'secure': '1.7.2',
        'regexp': ['.*?RELEASE.*?(?P<version>1.[7,6])', '.*?DEV_LEVEL.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2011-3629 http://developer.joomla.org/security/news/370-20111001-core-information-disclosure.html',
        'fingerprint': detect_joomla
        },
    # CVE-2012-0835 2.5.1   OSVDB:78824 http://developer.joomla.org/security/news/387-20120201-core-information-disclosure.html
    # CVE-2012-0836 2.5.1   OSVDB:78825 http://developer.joomla.org/security/news/388-20120202-core-information-disclosure.html
    # CVE-2012-0837 2.5.1   OSVDB:78826 http://developer.joomla.org/security/news/389-20120203-core-information-disclosure.html
    # CVE-2012-1116 2.5.2   OSVDB:79837 http://developer.joomla.org/security/news/391-20120301-core-sql-injection.html
    # CVE-2012-1117 2.5.2   OSVDB:79836 http://developer.joomla.org/security/news/392-20120302-core-xss-vulnerability.html
    # CVE-2012-1562 2.5.3   http://developer.joomla.org/security/news/394-20120304-core-password-change.html
    # CVE-2012-1563 2.5.3   http://developer.joomla.org/security/news/395-20120303-core-privilege-escalation.html
#    'Joomla 2.5': {
#        'location:': TODO
#        'secure': '2.5.3',
#        'regexp': TODO
#        'cve': 'CVE-2012-1562 http://developer.joomla.org/security/news/394-20120304-core-password-change.html CVE-2012-1563 http://developer.joomla.org/security/news/395-20120303-core-privilege-escalation.html',
#        'fingerprint': TODO. Needs new
#        },
    # TODO: Does not work with ancient 2003 versions
        # http://secunia.com/advisories/23621/
        # http://secunia.com/advisories/23587/
        # http://secunia.com/advisories/24316/
        # http://secunia.com/advisories/24951/
        # http://secunia.com/advisories/28130/
        # OSBDB:72142 3.1.1
        # http://osvdb.org/show/osvdb/72097
        # http://osvdb.org/show/osvdb/73721
    # Not valid:
    #   OSVDB:72173
    #               0.71    SA8954
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
    # CVE-2011-0700 3.0.5   OSVDB:72763,72764 SA43238 http://wordpress.org/news/2011/02/wordpress-3-0-5/
    # CVE-2011-0701 3.0.5   OSVDB:72765 SA43238 http://wordpress.org/news/2011/02/wordpress-3-0-5/
    #               3.1.1   OSVDB:72141 SA44038 http://wordpress.org/news/2011/04/wordpress-3-1-1/ # TODO: No CVE
    # CVE-2011-1762 3.1.2   OSVDB:72097 SA44372 SA44542 http://wordpress.org/news/2011/04/wordpress-3-1-2/ http://core.trac.wordpress.org/changeset/17710 http://lists.fedoraproject.org/pipermail/package-announce/2011-May/059968.html http://lists.fedoraproject.org/pipermail/package-announce/2011-May/059986.html 
    # CVE-2011-3122 3.1.3
    # CVE-2011-3126 3.1.3
    # CVE-2011-3127 3.1.3
    # CVE-2011-3128 3.1.3
    # CVE-2011-3129 3.1.3
    # CVE-2011-3130 3.1.3
    # CVE-2012-0287 3.3.1   OSVDB:78123 http://wordpress.org/news/2012/01/wordpress-3-3-1/ https://wordpress.org/news/2012/01/wordpress-3-3-1/ IE only
    # CVE-2011-4898 3.3.1   OSVDB:78707 https://www.trustwave.com/spiderlabs/advisories/TWSL2012-002.txt # Not fixed
    # CVE-2011-4899 3.3.1   OSVDB:78708 https://www.trustwave.com/spiderlabs/advisories/TWSL2012-002.txt # Not fixed
    # CVE-2012-0782 3.3.1   OSVDB:78709 https://www.trustwave.com/spiderlabs/advisories/TWSL2012-002.txt # Not fixed
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
    # CVE-2010-4663 1.9.1 http://forum.cmsmadesimple.org/viewtopic.php?t=49245
    # CVE-2011-4310 1.9.4.3
    'CMSMS': {
        'location': ['version.php'],
        'secure': '1.9.4.3',
        'regexp': ['\$CMS_VERSION.*?(?P<version>[.0-9]{2,})'],
        'cve': 'CVE-2011-4310 http://www.cmsmadesimple.org/2011/08/Announcing-CMSMS-1-9-4-3---Security-Release/',
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
    # CVE-2010-4757 0.7.23  OSVDB:67367 SA41034
    # CVE-2010-5084 0.7.23  OSVDB:67368 SA41034
    # CVE-2011-0457 0.7.23  OSVDB:67367 SA41034
    # CVE-2011-1513 0.7.24  BugtraqID:50339 OSVD:77042
    #               0.7.25  SA41597 HTB2260
    #               0.7.25  SA44061
    # CVE-2011-4946 0.7.26  OSVDB:73120 SA44968 HTB23004
    #   http://e107.svn.sourceforge.net/viewvc/e107/trunk/e107_0.7/e107_admin/users_extended.php?revision=12306&view=markup
    #   http://e107.svn.sourceforge.net/viewvc/e107/trunk/e107_0.7/e107_admin/users_extended.php?r1=12225&r2=12306
    #   http://e107.org/news.php?extend.884.2
    #   http://wiki.e107.org/index.php?title=Release_Notes_0.7.26
    # CVE-2011-4947 0.7.26  HTB23004
    #               0.7.26  This is not fixed yet. SVN revision 12376 is fix
    # CVE-2011-4920 1.0.0   OSVDB:78047-78049 SA46707
    # CVE-2011-4921 1.0.0   OSVDB:78050
    'e107': {
        'location': ['/e107_admin/ver.php'],
        'secure': '1.0.0',
        'regexp': ['.*?e107_version.*?(?P<version>[.0-9]{2,})'],
        'cve': 'CVE-2011-4920 CVE-2011-4921 OSVDB:78047-78050 SA46706',
        'fingerprint': detect_general
        },
    # CVE-2008-1766 3.0.1       SA29801
    # CVE-2008-6506 3.0.4       SA33166
    # CVE-2008-6507 3.0.4       SA33166
    # CVE-2010-1627 3.0.7PL1    SA38837
    # CVE-2010-1630 3.0.5       SA38264
    # CVE-2011-0544 3.0.8       SA42343
    'phpBB3': {
        'location': ['/includes/constants.php'],
        'secure': '3.0.8',
        'regexp': ['.*?PHPBB_VERSION.*?(?P<version>3[0-9.]{1,})'],
        'cve': 'CVE-2011-0544, SA42343',
        'fingerprint': detect_general
        },
    # CVE-2010-1189 1.15.2      OSVDB:62798 SA38856
    # CVE-2010-1190 1.15.2      OSVDB:62799 SA38856
    # CVE-2010-1150 1.15.3      OSVDB:63570 SA39333
    # CVE-2011-1578 1.16.5      OSVDB:74619 SA44142
    # CVE-2011-1579 1.16.3      OSVDB:74620 SA44142
    # CVE-2011-1580 1.16.3      OSVDB:74621 SA44142
    # CVE-2011-1587 1.16.5      OSVDB:74619 SA44142
    # CVE-2011-1765 1.16.5      OSVDB:74619 SA44142
    # CVE-2011-1766 1.16.5      OSVDB:74613 SA44142
    # CVE-2011-4360 1.17.1      OSVDB:77364 SA47029 http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-November/000104.html
    # CVE-2011-4361 1.17.1      OSVDB:77365 SA47029 http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-November/000104.html
    # CVE-2012-0046 1.17.2      OSVDB:78260 SA47547 http://svn.wikimedia.org/svnroot/mediawiki/tags/REL1_17_2/phase3/RELEASE-NOTES http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-January/000106.html http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-January/000107.html
    'MediaWiki': {
        'location': ['/includes/DefaultSettings.php'],
        'secure': '1.17.2',
        'regexp': ['\$wgVersion.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2012-0046 http://svn.wikimedia.org/svnroot/mediawiki/tags/REL1_17_2/phase3/RELEASE-NOTES',
        'fingerprint': detect_general
        }
    # CVE-2011-4448 1.3.2-p2    OSVDB:77390
    # CVE-2011-4449 1.3.2-p2    OSVDB:77391
    # CVE-2011-4450 1.3.2-p2    OSVDB:77392
    # CVE-2011-4451 1.3.2-p2    OSVDB:77393
    # CVE-2011-4452 1.3.2-p2    OSVDB:77394
    # 'WikkaWiki'
    # CVE-2011-4453 2.2.35      OSVDB:77261 http://www.pmwiki.org/wiki/PITS/01271
    # 'PmWiki'
    # CVE-2011-4558 8.2         OSVDB:78013 http://dev.tiki.org/item4059
    #'TikiWiki': {
    #    'location': ['/lib/setup/twversion.class.php'],
    #    'secure': '8.3', # Not fixed yet
    #    'regexp': ['.*?\$this->version.*?(?P<version>[0-9.]{1,})'],
    #    'cve': 'CVE-2011-4558',
    #    'fingerprint': detect_general
    #    }
    # CVE-2005-2007 0.8.4 SA15752
    # CVE-2005-2147 0.8.4 SA15752
    # CVE-2005-3980 0.9.1 SA17836
    # CVE-2005-4065 0.9.2 SA17894
    # CVE-2005-4305 0.9.3 SA18048
    # CVE-2005-4644 0.9.3 SA18465
    # CVE-2006-2106 0.9.5 SA19870
    # CVE-2006-3695 0.9.6 SA20958
    # CVE-2006-5878 0.10.1 SA22789
    # CVE-2006-5848 0.10.1 SA22789
    # CVE-2007-1405 0.10.3.1 SA24470
    # CVE-2008-3328 0.10.5 SA31231
    # CVE-2008-5646 0.11.2 SA32652
    # CVE-2008-5647 0.11.2 SA32652
    # CVE-2009-4405 0.11.6 SA37807
    #'trac': {
        #'location': ['/Trac.egg-info/PKG-INFO'],
        #'secure': '0.11.6',
        #'regexp': ['Version.*?(?P<version>[.0-9]{2,})'],
        #'cve': 'CVE-2009-4405',
        #'fingerprint': detect_general
        #}
    }

    main(sys.argv[1:])
