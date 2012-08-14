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
TODO: http://docs.python.org/library/functions.html#isinstance

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
    from detect import *
    from helpers import return_func_name
except ImportError, error:
    print('Import error: %s' % error)
    sys.exit(1)

logfile = 'pyfiscan.log'
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
            logger = logging.getLogger(return_func_name())
            try:
                to_queue = [filename, appname]
                queue.put(to_queue)
            except Exception, e:
                logger.debug(traceback.format_exc())

        try:
            logger = logging.getLogger(return_func_name())
            """Generate a list of directories from startpath."""
            directories = []
            if type(startpath) == list:
                for dir in startpath:
                    directories.append(dir)
            if type(startpath) == str:
                directories.append(startpath)
            """Use list of directories in loop to check if locations in data dictionary exists."""
            for directory in directories:
                if not directory_check(directory, checkmodes):
                    continue
                # TODO: This should be done by workers as pyfiscanner will use lots of time in big directory structures with lots of files
                logger.debug('Populating: %s' % directory)
                for (appname, issue) in data.iteritems():
                    for loc in database.locations(data, appname, with_lists=False):
                        for filename in self.filenames(directory):
                            if filename.endswith(loc):
                                put(filename, appname)
            status.value = 0
        except OSError as (errno, strerror):  # Error number 116 is at least important to catch
            logger.debug(traceback.format_exc())
            sys.exit(traceback.format_exc())
        except Exception, e:
            logger.debug(traceback.format_exc())

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
                if not directory_check(userdir_location, checkmodes):
                    continue
                userdirs.append(userdir_location)

                public_html_location = startdir + '/' + userdir + '/public_html'
                if not directory_check(public_html_location, checkmodes):
                    continue
                logger.debug('Appending to locations: %s' % os.path.abspath(public_html_location))
                locations.append(os.path.abspath(public_html_location))

            for directory in userdirs:
                sites_location = directory + '/sites'
                if not directory_check(sites_location, checkmodes):
                    continue
                for sitesdir in os.listdir(sites_location):
                    for predefined_directory in predefined_locations:
                        if not check_dir_execution_bit(sites_location + '/' + sitesdir, checkmodes):
                            continue
                        sites_location_last = sites_location + '/' + sitesdir + '/' + predefined_directory
                        if not directory_check(sites_location_last, checkmodes):
                            continue
                        if check_dir_execution_bit(sites_location_last, checkmodes):
                            logger.debug('Appending to locations: %s' % os.path.abspath(sites_location_last))
                            locations.append(os.path.abspath(sites_location_last))
            logger.debug('Total amount of locations: %s' % len(locations))
            self.populate(locations, checkmodes)
        except Exception, e:
            logger.debug(traceback.format_exc())


def directory_check(path, checkmodes):
    """Check if path is directory and it is not a symlink"""
    logger = logging.getLogger(return_func_name())
    if not type(path) == str:
        logger.debug('got path which was not a string. Exiting..')
        sys.exit('directory_check got path which was not a string')
    if not os.path.isdir(path):
        return False
    if os.path.islink(path):
        return False
    if not check_dir_execution_bit(path, checkmodes):
        return False
    return True


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
        logger.debug(traceback.format_exc())


def compare_versions(secure_version, file_version, appname=None):
    """Comparison of found version numbers. Value current_version is predefined and file_version is found from file using grep. Value appname is used to separate different version numbering syntax"""
    logger = logging.getLogger(return_func_name())
    try:
        if not type(secure_version) == str:
            logger.debug('Secure version must be a string when comparing: %s' % secure_version)
        if not type(file_version) == str:
            logger.debug('Version from file must be a string when comparing: %s' % file_version)

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
    except Exception, e:
        logger.debug(traceback.format_exc())


def get_timestamp():
    """Returns string ISO 8601 with hours:minutes:seconds"""
    return time.strftime("%Y-%m-%d %H:%M:%S")


def csv_add(appname, item, file_version, secure_version, cve):
    """Creates CVS-file and writes found vulnerabilities per line. CSV-file can't be symlink.
    
    TODO: Should check that all needed arguments are available.
    TODO: We are doing open and chmod in every csv_add()
    TODO: Should we have exception csv.Error
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
        logger.debug(traceback.format_exc())


def Worker():
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
            logger.info('Processing: %s (%s)' % (item[0], item[1]))
            for (appname, issues) in data.iteritems():
                # We only continue to check versions with correct applications fingerprint
                if not appname == item[1]:
                    continue
                for location in database.locations(data, appname, with_lists=False):
                    item_location = item[0]
                    if not item_location.endswith(location):
                        continue
                    for issue in issues:
                        logger.debug('Processing item %s with location %s with with appname %s issue %s' % (item_location, location, appname, issue))
                        fn = yaml_fn_dict[issues[issue]['fingerprint']]
                        file_version = fn(item_location, issues[issue]['regexp'])
                        # Makes sure we don't go forward without version number from the file
                        if file_version is None:
                            logger.debug('No version found from item: %s with regexp %s' % (item_location, issues[issue]['regexp']))
                            continue
                        # Tests that version from file is smaller than secure version with application fingerprint-function
                        logger.debug('Comparing versions %s:%s for item %s' % (issues[issue]['secure_version'], file_version, item_location))
                        if not compare_versions(issues[issue]['secure_version'], file_version, appname):
                            continue
                        # Calls result handler (goes to CSV and log)
                        handle_results(appname, file_version, item_location, issues[issue]['cve'], issues[issue]['secure_version'])
        except Exception:
            logger.debug(traceback.format_exc())


if __name__ == "__main__":
    """Data in YAML-files could include following:
    CVE, CVSS2, OSVDB, Secunia
    Publication date, Fixed date
    CPE, ISS X-Force ID
    SecurityTracker Alert ID, Vendor URL"""

    yamldir = 'yamls/'
    database = Database()
    # Returns dictionary of all fingerprint data from YAML-files
    data = database.generate(yamldir)
    status = Value('i', 1)
    # Argument handling
    usage = "Usage: %prog [-r/--recursive <directory>] [--home <directory>] [-d/--debug]"
    parser = OptionParser(
        usage=usage,
        version="%prog beta",
        description="If you do not spesify recursive scanning predefined directories are scanned, which are: /home/user/sites/www /home/user/sites/secure-www /home/user/public_html /home/user/public_html")
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
    # Exit in case logfile is symlink
    if os.path.islink(logfile):
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
        logger.debug('Starting workers.')
        pool = Pool()
        pool.apply_async(Worker)
        """Starts the actual populator daemon to get possible locations, which will be verified by workers.
        http://docs.python.org/library/multiprocessing.html#multiprocessing.Process
        """
        logger.debug('Starting scan queue populator.')
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
            logger.debug('Scanning predefined variables: /home')
            populator = Process(target=p.populate_predefined('/home', opts.checkmodes,))
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
        # This will make sure all child processes are dead
        #p = psutil.Process(os.getpid())
        #for children in p.get_children():
        #    os.kill(children.pid)
    except Exception, e:
        logger.debug(traceback.format_exc())
