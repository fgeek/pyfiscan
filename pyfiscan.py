#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Pyfiscan is free web-application vulnerability and version scanner and can be used to locate out-dated versions of common web-applications in Unixi- and Linux-servers. Example usa case is hosting-providers keeping eye on their users installations to keep up with security-updates. Supports content management systems, blogging softwares, image-galleries, version controlling programs, wikis, admin panels and bulletin boards.

@author Henri 'fgeek' Salo <henri@nerv.fi>
@copyright Copyright (c) 2009-2012 Henri Salo
@licence BSD

Known issues and/or bugs:
1: If instance is upgraded from Joomla 1.6.1 to 1.7.x by unzipping there will be both version files libraries/joomla/version.php and includes/version.php where first is the old one.

TODO: Usage does not include available logging levels. Does list those in case user inputs invalid level
TODO: Should be a feature to run commands in detected installation directory e.g. if /home/example/public_html/ directory contains file php5.fcgi
TODO: Fingerprints to YAML and use decorators in functions. References: http://www.artima.com/weblogs/viewpost.jsp?thread=240808 http://www.python.org/dev/peps/pep-0318/ http://wiki.python.org/moin/PythonDecorators http://wiki.python.org/moin/PythonDecoratorLibrary
TODO: https://github.com/halst/docopt/blob/master/docopt.py
TODO: Argument --strip-output, which should remove homedir/startdir and location from output (stdin, csv and log)
TODO: If one fingerprint finds a match the process should finish and not be scanned with other fingerprints
TODO: There should be argument for looking specific programs in for example: -s joomla,smf
TODO: Add unittests
TODO: Add support to continue interrupted session (Tuomo Komulainen requested). Could be implemented using http://docs.python.org/library/atexit.html with knowledge of current working directory and queues

Application specific TODO:
    SMF:
        - 1.1.x is still supported. 1.0.x is not. Promised to fix
    Joomla 2.5:
        - Needs support for configuration specific parser and MySQL queries
    WordPress:
        - Haven't been tested with 2003 versions
        - http://core.trac.wordpress.org/changeset/16803 this does not seem to have a CVE-identifier. Debian lists this as TEMP-0606657-A0D78A
    MoinMoin:
        - Fingerprint list is not full. Check OSVDB.
        - 1.0 OSVDB:2878 SA10318 no CVE
        - 1.1 OSVDB:2911 no CVE
        - 1.2.2 OSVDB:6704 SA11807 no CVE
        - 1.2.3 OSVDB:8194,8195 SA11832 no CVE
        - 1.3.3 OSVDB:13184 SA14001 no CVE
        - OSVDB:49752 SA32686 no CVE
    SMF:
        - 1.0.5 OSVDB:17458 SA15784 no CVE
    PmWiki:
        - CVE-2010-1481 XSS OSVDB:64456, CVE-2011-4453 Remote PHP Code Execution OSVDB: 77261, CVE-2010-4748 XSS OSVDB:69940
"""

try:
    import sys
    import time
    import re
    import logging
    import csv
    import traceback
    import os
    import stat  # Interpreting the results of os.[stat,fstat,lstat]
    import inspect  # To get current function name for logging
    from collections import defaultdict
    from optparse import OptionParser
    from multiprocessing import Process, Queue, Value, Pool
    from multiprocessing.util import log_to_stderr

    from database import Database
except ImportError, error:
    print('Import error: %s' % error)
    sys.exit(1)

queue = Queue()
# Initializing stats-dictionary. Lambda defaults value to zero
stats = defaultdict(lambda: 0)
# Available logging levels
levels = {'info': logging.INFO, 'debug': logging.DEBUG}


class PopulateScanQueue:
    def __init__(self, status):
        status.value = 1

    def filenames(self, directory):
        return (os.path.join(root, basename) for root, dirs, files in os.walk(directory) for basename in files)

    def populate(self, startpath, checkmodes=False):
        def put(filename, appname):
            try:
                to_queue = [filename, appname]
                queue.put(to_queue)
            except Exception, e:
                print(traceback.format_exc())

        try:
            logger = logging.getLogger(return_func_name())
            logger.debug('Type of startpath: %s' % type(startpath))
            """Generate a list of directories from startpath."""
            directories = []
            if type(startpath) == list:
                for dir in startpath:
                    directories.append(dir)
            if type(startpath) == str:
                directories.append(startpath)
            """Use list of directories in loop to check if locations in data dictionary exists."""
            for directory in directories:
                if not os.path.isdir(directory):
                    continue
                if os.path.islink(directory):
                    continue
                if check_dir_execution_bit(directory, checkmodes):
                    logger.debug('Populating: %s' % directory)
                    for (appname, issue) in data.iteritems():
                        for filename in self.filenames(directory):
                            for loc in database.locations(appname, with_lists=False):
                                if filename.endswith(loc):
                                    put(filename, appname)
            status.value = 0
        except OSError as (errno, strerror):  # Error number 116 is at least important to catch
            logging.debug(traceback.format_exc())
            sys.exit(traceback.format_exc())
        except Exception, e:
            logging.debug(traceback.format_exc())

    def populate_predefined(self, startdir, checkmodes):
        if not type(startdir) == str:
            sys.exit('Error in populate_predefined value startdir not a string. Value is: "%s" with type %s.' % (startdir, type(startdir)[0]))
        try:
            logger = logging.getLogger(return_func_name())
            logger.debug('Populating predefined directories: %s' % startdir)
            predefined_locations = ['/www', '/secure_www']
            locations = []
            userdirs = []
            for userdir in os.listdir(startdir):
                userdir_location = startdir + '/' + userdir
                if not os.path.isdir(userdir_location):
                    continue
                if os.path.islink(userdir_location):
                    continue
                if check_dir_execution_bit(userdir_location, checkmodes):
                    userdirs.append(userdir_location)

                public_html_location = startdir + '/' + userdir + '/public_html'
                if not os.path.isdir(public_html_location):
                    continue
                if os.path.islink(public_html_location):
                    continue
                if check_dir_execution_bit(public_html_location, checkmodes):
                    logger.debug('Appending to locations: %s' % os.path.abspath(public_html_location))
                    locations.append(os.path.abspath(public_html_location))

            for directory in userdirs:
                sites_location = directory + '/sites'
                if not os.path.isdir(sites_location):
                    continue
                if os.path.islink(sites_location):
                    continue
                if check_dir_execution_bit(sites_location, checkmodes):
                    for sitesdir in os.listdir(sites_location):
                        for predefined_directory in predefined_locations:
                            if not check_dir_execution_bit(sites_location + '/' + sitesdir, checkmodes):
                                continue
                            sites_location_last = sites_location + '/' + sitesdir + '/' + predefined_directory
                            if not os.path.isdir(sites_location_last):
                                continue
                            if os.path.islink(sites_location_last):
                                continue
                            if check_dir_execution_bit(sites_location_last, checkmodes):
                                logger.debug('Appending to locations: %s' % os.path.abspath(sites_location_last))
                                locations.append(os.path.abspath(sites_location_last))
            logging.debug('Total amount of locations: %s' % len(locations))
            self.populate(locations, checkmodes)
        except Exception, e:
            logger.debug(traceback.format_exc())


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
        help="Specifies where the home-directories are located")
    parser.add_option(
        "", "--check-modes",
        action="store_true",
        dest="checkmodes",
        help="Check if we are allowed to traverse directories (execution bit)")
    parser.add_option(
        "-l", "--loglevel",
        action="store",
        type="string",
        dest="level_name",
        help="Specifies logging level")

    (opts, args) = parser.parse_args()
    # Starttime is used to measure program runtime
    starttime = time.time()
    if opts.level_name:
        level_name = opts.level_name
    else:
        level_name = str('info')
    if not level_name in levels:
        print('No such log level. Available levels are: %s' % levels.keys())
        sys.exit(1)
    level = levels.get(level_name, logging.NOTSET)
    logfile = 'pyfiscan.log'

    if os.path.islink(logfile):  # We do not want to continue in case logfile is a symlink
        sys.exit('Logfile %s is a symlink. Exiting..' % logfile)

    try:
        logging.basicConfig(filename=logfile, level=level, format='%(asctime)s %(levelname)s %(name)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        os.chmod(logfile, 0600)
    except IOError as (errno, strerror):
        if errno == int('13'):
            sys.exit('Error while writing to logfile: %s' % strerror)
    try:
        logger = logging.getLogger(return_func_name())
        # stderr to /dev/null
        devnull_fd = open(os.devnull, "w")
        sys.stderr = devnull_fd
        log_to_stderr()
        """Starts the asynchronous workers. Amount of workers is the same as cores in server.
        http://docs.python.org/library/multiprocessing.html#multiprocessing.pool.multiprocessing.Pool
        """
        pool = Pool()
        pool.apply_async(SpawnWorker)
        """Starts the actual populator daemon to get possible locations, which will be verified by workers.
        http://docs.python.org/library/multiprocessing.html#multiprocessing.Process
        """
        p = PopulateScanQueue(status)
        p.daemon = True
        if opts.directory:
            logger.debug('Scanning recursively from path: %s' % opts.directory)
            populator = Process(target=p.populate, args=(opts.directory,))
            populator.start()
        elif opts.home:
            logger.debug('Scanning predefined variables: %s' % opts.home)
            populator = Process(target=p.populate_predefined(opts.home, opts.checkmodes,))
            populator.start()
        else:
            _users = '/home'
            logger.debug('Scanning predefined variables: %s' % _users)
            populator = Process(target=p.populate_predefined(_users, opts.checkmodes,))
            populator.start()
        """This will loop as long as populating possible locations is done and the queue is empty (workers have finished)"""
        while not status.value == int('0') and queue.empty():
            time.sleep(5)
        else:
            """Prevents any more tasks from being submitted to the pool. Once all the tasks have been completed the worker processes will exit.
            http://docs.python.org/library/multiprocessing.html#multiprocessing.pool.multiprocessing.Pool.close
            """
            pool.close()
            runtime = time.time() - starttime
            logger.info('Scanning ended, which took %s seconds' % runtime)
    except KeyboardInterrupt:
        logger.debug('Received keyboard interrupt. Exiting..')
        pool.join()
        populator.join()
        runtime = time.time() - starttime
        logger.info('Scanning ended, which took %s seconds' % runtime)
    except Exception, e:
        logger.debug(traceback.format_exc())


def return_func_name():
    """Returns name of calling function."""
    return inspect.stack()[1][3]

# TODO: Document kludge :)
yaml_fn_dict = {}

def yaml_visible(fn):
    yaml_fn_dict[fn.func_name] = fn
    return fn


def check_dir_execution_bit(path, checkmodes):
    """Check if path has execution bit to check if site is public. Defaults to false."""
    try:
        logger = logging.getLogger(return_func_name())
        if checkmodes == None:
            return True
        if not os.path.exists(path):
            return
        if not os.path.isdir(path):
            return
        """http://docs.python.org/library/stat.html#stat.S_IXOTH"""
        if stat.S_IXOTH & os.stat(path)[stat.ST_MODE]:
            #logger.debug('Execution bit set for directory: %s' % path)
            return True
        else:
            #logger.debug('No execution bit set for directory: %s' % path)
            return False
    except Exception, e:
        loggin.debug(traceback.format_exc())


def compare_versions(secure_version, file_version, appname=None):
    """Comparison of found version numbers. Value current_version is predefined and file_version is found from file using grep. Value appname is used to separate different version numbering syntax"""
    if appname == 'WikkaWiki':  # Replace -p → .
        ver1 = secure_version.split('-')
        ver2 = file_version.split('-')
        secure_version = ver1[0] + '.' + ver1[1].lstrip('p')
        file_version = ver2[0] + '.' + ver2[1].lstrip('p')
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


def get_timestamp():
    """Returns string ISO 8601 with hours:minutes:seconds"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    return timestamp


def csv_add(appname, item, file_version, secure_version, cve):
    """Creates CVS-file and writes found vulnerabilities per line. CSV-file can't be symlink.
    
    TODO: Should check that all needed arguments are available.
    """
    logger = logging.getLogger(return_func_name())
    timestamp = get_timestamp()
    csvfile = 'pyfiscan-vulnerabilities-' + time.strftime("%Y-%m-%d") + '.csv'
    if os.path.islink(csvfile):
        exit('CSV-file %s is a symlink. Exiting..' % csvfile)
    if os.path.isdir(csvfile):
        exit('CSV-file %s is a not a file. Exiting..' % csvfile)
    try:
        writer = csv.writer(open(csvfile, "a"), delimiter='|', quotechar='|')
        logged_data = timestamp, appname, item, file_version, secure_version, cve
        writer.writerow(logged_data)
        os.chmod(csvfile, 0600)
    except Exception, e:
        logger.debug('Exception in csv_add: %s' % e)


def handle_results(appname, file_version, item_location, application_cve, application_secure):
    try:
        logger = logging.getLogger(return_func_name())
        logger.debug('%s with version %s from %s with vulnerability %s. This installation should be updated to at least version %s.' % (appname, file_version, item_location, application_cve, application_secure))
        print('%s Found: %s %s -> %s (%s)' % (get_timestamp(), item_location, file_version, application_secure, appname))
        csv_add(appname, item_location, file_version, application_secure, application_cve)
    except Exception, e:
        print(traceback.format_exc())


def SpawnWorker():
    """This is the actual worker which calls smaller functions in case of
    correct directory/file match is found.
        
        - Takes and removes item from queue
        - Detection in case of correct directory/file match is found
        - Compares found version against secure version in YAML
        - Calls logger

    Every worker runs in a loop.

    """
    while 1:
        try:
            logger = logging.getLogger(return_func_name())
            item = None
            item = queue.get()
            logger.info('processing: %s (%s)' % (item[0], item[1]))
            for (appname, issues) in data.iteritems():
                if not appname == item[1]:
                    continue
                for location in database.locations(appname, with_lists=False):
                    item_location = item[0]
                    if item_location.endswith(location):
                        for issue in issues:
                            logger.debug('Processing item %s with location %s with with appname %s issue %s' % (item_location, location, appname, issue))
                            fn = yaml_fn_dict[issues[issue]['fingerprint']]
                            file_version = fn(item_location, issues[issue]['regexp'])
                            # Makes sure we don't go forward without version number from the file
                            if file_version is None:
                                continue
                            # Tests that version from file is smaller than secure version with application fingerprint-function
                            logger.debug('Comparing versions %s with type %s %s with type %s' % (issues[issue]['secure_version'], type(issues[issue]['secure_version']), file_version, type(file_version)))
                            if not compare_versions(issues[issue]['secure_version'], file_version, appname):
                                continue
                            # Calls result handler (goes to CSV and log)
                            handle_results(appname, file_version, item_location, issues[issue]['cve'], issues[issue]['secure_version'])
        except Exception:
            print(traceback.format_exc())


def grep_from_file(version_file, regexp):
    """Grepping file with predefined regexp to find a version. This returns m.group from regexp: (?P<version>foo)"""
    version_file = open(version_file, 'r')
    source = version_file.readlines()
    version_file.close()
    prog = re.compile(regexp)

    for line in source:
        match = prog.match(line)
        try:
            found_match = match.group('version')
            return found_match
        except re.error:
            print('Not a valid regular expression: %s' % regexp)
        except AttributeError:
            pass


def detect_general(source_file, regexp):
    """Detects from source file if it contains version information. Uses first regexp-match"""
    if not os.path.isfile(source_file):
        return
    if not regexp:
        return
    file_version = grep_from_file(source_file, regexp[0])
    return file_version


@yaml_visible
def detect_joomla(source_file, regexp):
    """Detects from source file if it contains version information of Joomla"""
    logger = logging.getLogger(return_func_name())
    if not os.path.isfile(source_file):
        return
    if not regexp:
        return
    logger.debug('Dectecting Joomla from: %s' % source_file)

    release_version = grep_from_file(source_file, regexp[0])
    if not release_version:
        logger.debug('Could not find release version from: %s' % source_file)
        return
    logger.debug('Release version: %s' % release_version)
    dev_level_version = grep_from_file(source_file, regexp[1])
    if not dev_level_version:
        logger.debug('Could not find development version from: %s' % source_file)
        return
    logger.debug('Development level version: %s' % dev_level_version)

    file_version = release_version + "." + dev_level_version
    return file_version


def detect_wikkawiki(source_file, regexp):
    """Detects from file if the file has version information of WikkaWiki.

    Wikka-1.3.2-p7/version.php:
    $svn_version = '1.3.2';
    if (!defined('WAKKA_VERSION')) define('WAKKA_VERSION', $svn_version);
    if(!defined('WIKKA_PATCH_LEVEL')) define('WIKKA_PATCH_LEVEL', '7');
    """
    logger = logging.getLogger(return_func_name())
    if not os.path.isfile(source_file):
        return
    if not regexp:
        return
    logger.debug('Dectecting WikkaWiki from: %s' % source_file)
    version = grep_from_file(source_file, regexp[0])
    if not version:
        logger.debug('Could not find version from: %s' % source_file)
        return
    logger.debug('Version: %s' % version)
    patch_level = grep_from_file(source_file, regexp[1])
    if not patch_level:
        logger.debug('Could not find patch level from: %s' % patch_level)
        return
    logger.debug('Patch level: %s' % patch_level)
    if version and patch_level:
        file_version = version + "-p" + patch_level
        return file_version


if __name__ == "__main__":
    """Structure of data-dictionary:

    - Software/program
        - Uses this directory hierarchy and filename to get current version of installation
        - Secure version
        - Regexp used in detection functions
        - CVE-identifier and other references

    To-be schema:
    'vulnerabilities':
        [{'CVE-2010-4166': '1.5.22'}], {'': ''}, {'' }],

    Data should include at least following:
    - CVE
    - CVSS2
    - OSVDB
    - Secunia
    - Publication date
    - Fixed date
    - ISS X-Force ID
    - SecurityTracker Alert ID:
    - Vendor URL
    """

    yamldir = 'yamls/'
    database = Database(yamldir)
    data = database.generate(yamldir)
 
    """
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
    # CVE-2011-4310 1.9.4.3 http://www.cmsmadesimple.org/2011/08/Announcing-CMSMS-1-9-4-3---Security-Release/
    'CMSMS': {
        'location': ['version.php'],
        'secure': '1.9.4.3',
        'regexp': ['\$CMS_VERSION.*?(?P<version>[.0-9]{2,})'],
        'cve': 'CVE-2011-4310 http://www.cmsmadesimple.org/2011/08/Announcing-CMSMS-1-9-4-3---Security-Release/',
        'fingerprint': detect_general},
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
    # CVE-2011-4947 0.7.25  OSVDB:80992 SA44968 HTB23004
    #               0.7.26  This is not fixed yet. SVN revision 12375 is fix
    # CVE-2011-4920 1.0.0   OSVDB:78047-78049 SA46706
    # CVE-2011-4921 1.0.0   OSVDB:78050
    'e107': {
        'location': ['/e107_admin/ver.php'],
        'secure': '1.0.0',
        'regexp': ['.*?e107_version.*?(?P<version>[.0-9]{2,})'],
        'cve': 'CVE-2011-4920 CVE-2011-4921 OSVDB:78047-78050 SA46706',
        'fingerprint': detect_general},
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
        'fingerprint': detect_general},
    # CVE-2010-1189 1.15.2      OSVDB:62798 SA38856
    # CVE-2010-1190 1.15.2      OSVDB:62799 SA38856
    # CVE-2010-1150 1.15.3      OSVDB:63570 SA39333
    # CVE-2011-0537 1.16.2      OSVDB:70798,70799
    # CVE-2011-1578 1.16.5      OSVDB:74619 SA44142
    # CVE-2011-1579 1.16.3      OSVDB:74620 SA44142
    # CVE-2011-1580 1.16.3      OSVDB:74621 SA44142
    # CVE-2011-1587 1.16.5      OSVDB:74619 SA44142
    # CVE-2011-1765 1.16.5      OSVDB:74619 SA44142
    # CVE-2011-1766 1.16.5      OSVDB:74613 SA44142
    # CVE-2011-4360 1.17.1      OSVDB:77364 SA47029 http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-November/000104.html
    # CVE-2011-4361 1.17.1      OSVDB:77365 SA47029 http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-November/000104.html
    # CVE-2012-0046 1.17.2      OSVDB:78260 SA47547 http://svn.wikimedia.org/svnroot/mediawiki/tags/REL1_17_2/phase3/RELEASE-NOTES http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-January/000106.html http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-January/000107.html
    # CVE-2012-1578 1.17.3 or 1.18.2 OSVDB:80361 http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000109.html http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000110.html
    # CVE-2012-1579 1.17.3 or 1.18.2 OSVDB:80362 http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000109.html http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000110.html
    # CVE-2012-1580 1.17.3 or 1.18.2 OSVDB:80364 http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000109.html http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000110.html
    # CVE-2012-1581 1.17.3 or 1.18.2 OSVDB:80365 http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000109.html http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000110.html
    # CVE-2012-1582 1.17.3 or 1.18.2 OSVDB:80363 http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000109.html http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000110.html
    'MediaWiki': {
        'location': ['/includes/DefaultSettings.php'],
        'secure': '1.17.3',
        'regexp': ['\$wgVersion.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2012-1578 CVE-2012-1579 CVE-2012-1580 CVE-2012-1581 CVE-2012-1582 OSVDB:80361,80362,80363,80364,80365 http://lists.wikimedia.org/pipermail/mediawiki-announce/2012-March/000109.html',
        'fingerprint': detect_general},
    # N/A           1.1.3.5     OSVDB:26537
    # N/A           1.1.3.8     OSVDB:26538
    # N/A           1.1.5.0     OSVDB:26539
    # N/A           1.1.6.0     OSVDB:26540
    # CVE-2005-4255 1.1.6.1     OSVDB:21698 SA18015
    # N/A           1.1.6.2     OSVDB:26545
    # N/A           1.1.6.2     OSVDB:26541
    # N/A           1.1.6.2     OSVDB:26542
    # CVE-2006-7050 1.1.6.2     OSVDB:37339
    # N/A           1.1.6.2     OSVDB:26544
    # CVE-2006-7049 1.1.6.2     OSVDB:26543 SA20628
    # CVE-2007-2551 1.1.6.3     OSVDB:35828 SA25181
    # CVE-2007-2552 1.1.6.3     OSVDB:35827
    # CVE-2007-2612 1.1.6.3     OSVDB:35826
    # CVE-2007-2613 1.1.6.3     OSVDB:35825 SA25181
    # N/A           1.1.6.6     OSVDB:51942 SA33956
    # N/A           1.1.6.6     OSVDB:53706 SA34321
    # N/A           1.1.6.7     OSVDB:53705 SA34321
    # N/A           1.1.6.7     OSVDB:53707 SA34321
    # CVE-2011-4448 1.3.2-p7    OSVDB:77390 http://blog.wikkawiki.org/2011/12/04/security-updates-for-1-3-11-3-2/
    # CVE-2011-4449 1.3.2-p7    OSVDB:77391 http://blog.wikkawiki.org/2011/12/04/security-updates-for-1-3-11-3-2/
    # CVE-2011-4450 1.3.2-p7    OSVDB:77392 http://blog.wikkawiki.org/2011/12/04/security-updates-for-1-3-11-3-2/
    # CVE-2011-4451 1.3.2-p7    OSVDB:77393 http://blog.wikkawiki.org/2011/12/04/security-updates-for-1-3-11-3-2/
    # CVE-2011-4452 1.3.2-p7    OSVDB:77394 http://blog.wikkawiki.org/2011/12/04/security-updates-for-1-3-11-3-2/
    'WikkaWiki': {
        'location': ['version.php'],
        'secure': '1.3.2-p7',
        'regexp': ['\$svn_version.*?(?P<version>[0-9.]{1,})', '.*?WIKKA_PATCH_LEVEL.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2011-4448/CVE-2011-4449/CVE-2011-4450/CVE-2011-4451/CVE-2011-4452 OSVDB:77390,77391,77392,77393,7739477394 http://blog.wikkawiki.org/2011/12/04/security-updates-for-1-3-11-3-2/',
        'fingerprint': detect_wikkawiki},
    # CVE-2005-0200             OSVDB:13119 BugtraqID:12328
    # CVE-2010-4239             http://www.openwall.com/lists/oss-security/2010/11/22/9
    # CVE-2010-4240             http://www.openwall.com/lists/oss-security/2010/11/22/9
    # CVE-2010-4241             http://www.openwall.com/lists/oss-security/2010/11/22/9
    # CVE-2011-4453 2.2.35      OSVDB:77261 http://www.pmwiki.org/wiki/PITS/01271
    # CVE-2011-4336 7.1/6.4     OSVDB:74039 SA45256 SA45283 HTB23027
    # CVE-2011-4454 8.1         OSVDB:77155 SA46740
    # CVE-2011-4455 8.1         OSVDB:77156 SA46740
    # N/A           8.2/6.5     OSVDB:77965 SA47278 # TODO: Missing CVE-identifier
    # CVE-2011-4551 8.2/6.5     OSVDB:77966 SA47278 http://info.tiki.org/article183-Tiki-Wiki-CMS-Groupware-8-2-and-6-5LTS-Security-Patches-Available 
    # CVE-2011-4558 8.3/6.6     OSVDB:78013 SA47320 http://dev.tiki.org/item4059 http://info.tiki.org/article185-Tiki-Security-Patches-Available-for-8-3-and-6-6-LTS
    'TikiWiki': {
        'location': ['/lib/setup/twversion.class.php'],
        'secure': '8.3',
        'regexp': ['.*?\$this->version.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2011-4558 http://osvdb.org/78013',
        'fingerprint': detect_general},
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
    # CVE-2008-5646 0.11.2  OSVDB:49847 SA32652
    # CVE-2008-5647 0.11.2  OSVDB:49846 SA32652
    # CVE-2009-4405 0.11.6  OSVDB:61244 SA37807
    # N/A           0.11.7  OSVDB:63317 SA39123
    'Trac': {
        'location': ['/Trac.egg-info/PKG-INFO'],
        'secure': '0.11.7',
        'regexp': ['Version.*?(?P<version>[.0-9]{2,})'],
        'cve': 'OSVDB:63317',
        'fingerprint': detect_general},
    # CVE-2011-4806
    # CVE-2011-4807
    'phpAlbum': {
        'location': ['main.php'],
        'secure': '0.4.1.16',
        'regexp': ['\$phpalbum_version.*?(?P<version>[0-9.]{1,})'],
        'cve': 'CVE-2011-4806 CVE-2011-4807 OSVDB:74980 OSVDB:21410',
        'fingerprint': detect_general},
    # CVE-2010-5096 1.6.1 OSVDB:70013,70014
    #'MyBB': {
    #    'location': ['/inc/class_core.php'],
    #    'secure': '1.6.1',
    #    'regexp': ['.*?public \$version.*?(?P<version>[0-9.]{1,})'],
    #    'cve': '',
    #    'fingerprint': detect_general},
    # CVE-2004-1996 "last vulnerable 1.0 Beta 5" OSVDB:16898
    # CVE-2005-2817 "last vulnerable 1.0.5" OSVDB:19120 SA16646
    # CVE-2005-4159 1.1 RC1 OSVDB:21722
    # CVE-2006-0896 1.0.7 OSVDB:23480 SA19004 EV0086
    # CVE-2006-7013 "last vulnerable 1.0.7" OSVDB:35706
    # CVE-2006-4467 1.0.8 OSVDB:30715
    # CVE-2006-4564 1.0.9 OSVDB:28457 SA21740
    # N/A           1.0.9 OSVDB:77413 SA21740
    # CVE-2006-5503 "last vulnerable 1.1 RC2" OSVDB:31070
    # CVE-2006-6375 1.1.1 OSVDB:31731 SA23175
    # CVE-2007-0399 1.1.1/1.1 RC3 OSVDB:32606
    # CVE-2007-3309 "last vulnerable 1.1.2" OSVDB:40433
    # CVE-2007-3308 "last vulnerable 1.1.2" OSVDB:40617
    # CVE-2007-2546 1.1.3 OSVDB:35705 SA25139
    # CVE-2007-3942 "last vulnerable 1.1.3" DISPUTED
    # CVE-2007-5646 1.1.4/1.0.12 OSVDB:38070 SA27346
    # CVE-2008-0284 "last vulnerable 1.1.4" OSVDB:42934,42935
    # CVE-2008-2019 "last vulnerable 1.1.4" OSVDB:44981 (insufficient fix for CVE-2007-3308)
    # CVE-2008-6544 "last vulnerable 1.1.4" OSVDB:51301
    # CVE-2008-6741 "last vulnerable 1.1.4" OSVDB:53974
    # CVE-2008-3072 1.1.5/1.0.13 OSVDB:47003 SA30955
    # CVE-2008-3073 1.1.5/1.0.13 OSVDB:47002 SA30955
    # CVE-2008-6971 1.1.6 OSVDB:47945 SA31750
    # CVE-2008-6657 1.1.7/1.0.15 OSVDB:50071 SA32516
    # CVE-2008-6658 1.1.7/1.0.15 OSVDB:50070 SA32516
    # CVE-2008-6659 1.1.7/1.0.15 OSVDB:50072 SA32516
    # N/A           1.1.8 OSVDB:51735 SA33790
    # N/A           1.1.9 OSVDB:51646 SA33670
    # N/A           1.1.11 SA37557
    # N/A           1.1.19 OSVDB:54773 SA35267
    # CVE-2011-1127 1.1.13 OSVDB:71009 SA43436
    # CVE-2011-1128 1.1.13 OSVDB:75235
    # CVE-2011-1129 1.1.13 OSVDB:74321
    # CVE-2011-1130 1.1.13 OSVDB:75233,75234
    # CVE-2011-1131 1.1.13 OSVDB:74121
    # N/A           1.1.15 OSVDB:77727 http://www.simplemachines.org/community/index.php?topic=466218.0
    # CVE-2011-3615 2.0.1/1.1.15 OSVDB:76822 SA46386
    # CVE-2011-4173 2.0.1 OSVDB:76317 SA46386
    # N/A           2.0.1/1.1.15 OSVDB:76318 SA46386
    # Unknown:
    #   OSVDB:32605 too little information
    #   CVE-2007-5943 OSVDB:39961 myth/fake
    #   OSVDB:80766 Am!r XSS SMF 2.0.2 needs verification and vendor URL
    #'SMF': {
    #    'location': ['index.php'],
    #    'secure': '2.0.1',
    #    'regexp': ['\$forum_version.*?(?P<version>[0-9.]{1,})'],
    #    'cve': 'CVE-2011-3615, CVE-2011-4173, OSVDB:76317,76318,76822 SA46386',
    #    'fingerprint': detect_general
    #    }
    # Unknown: OSVDB:57146,51178
    # N/A           0.1-beta OSVDB:57138 "Attachment Upload Handling Unspecified Issue"
    # N/A           0.1-beta OSBDB:57137 "Address Book / Identities Unspecified XSS
    # N/A           0.1-rc1 OSBDB:57140
    # N/A           0.1-rc1 OSBDB:57141
    # N/A           0.1-rc1 OSBDB:57144
    # N/A           0.1-rc1 OSVDB:57145 "Emoticon Path Attachment Unspecified Issue"
    # N/A           0.1-rc1 OSVDB:57147 "Submitted Host Value Unspecified Issue"
    # N/A           0.1-rc2 OSVDB:57148 "Unspecified Cross-site AJAX Request Disclosure"
    # CVE-2007-6321 N/A     OSVDB:44117 SA30734,SA30735 http://trac.roundcube.net/ticket/1484701
    # N/A           0.1-stable OSVDB:57149 http://freshmeat.net/projects/roundcubemail/?branch_id=59740&release_id=272982
    # CVE-2008-5619 Affected 0.2-beta OSVDB:50694 SA33169
    # CVE-2008-5620 Affected 0.2-beta OSVDB:50879 SA33169
    # N/A           0.2.1 OSVDB:57150 "Vcard Export Unspecified Issue"
    # CVE-2009-0413 0.2.1 OSVDB:51505
    # CVE-2009-4076 0.3 OSVDB:59661 SA37235,SA37559
    # CVE-2009-4077 0.3 OSVDB:60567 SA37235,SA37559
    # CVE-2010-0464 0.4-beta OSVDB:62104
    # CVE-2011-1491 0.5.1 OSVDB:73871 SA44050
    # CVE-2011-1492 0.5.1 OSVDB:73870 SA44050
    # CVE-2011-2937 0.5.4 OSVDB:74567
    # CVE-2011-4078 0.5.4 OSVDB:77047 http://openwall.com/lists/oss-security/2011/10/26/6 http://trac.roundcube.net/ticket/1488086
    #'Roundcube': {
    #    'location': ['index.php'],
    #    'secure': '0.5.4',
    #    'regexp': ['', ''], # "Roundcube Webmail IMAP Client" "Version 0.7.2"
    #    'cve': '',
    #    'fingerprint': detect_roundcube # Needs new detection model. Must have one string before version is checked
    #    }
    }
    """

    status = Value('i', 1)
    main(sys.argv[1:])
