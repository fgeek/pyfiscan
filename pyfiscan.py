#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Pyfiscan is free web-application vulnerability and version scanner and can be used to locate out-dated versions of common web-applications in Linux-servers. Example usa case is hosting-providers keeping eye on their users installations to keep up with security-updates. Supports content management systems, blogging softwares, image-galleries, version controlling programs, wikis, admin panels and bulletin boards. Fingerprints are easy to create and modify as user can write those in YAML-syntax.

@author Henri 'fgeek' Salo <henri@nerv.fi>
@copyright Copyright (c) 2009-2012 Henri Salo
@licence BSD

Known issues and/or bugs:
1: If instance is upgraded from Joomla 1.6.1 to 1.7.x by unzipping there will be both version files libraries/joomla/version.php and includes/version.php where first is the old one.

TODO: Should be a feature to run commands in detected installation directory e.g. if /home/example/public_html/ directory contains file php5.fcgi
TODO: Fingerprints to YAML and use decorators in functions. References: http://www.artima.com/weblogs/viewpost.jsp?thread=240808 http://www.python.org/dev/peps/pep-0318/ http://wiki.python.org/moin/PythonDecorators http://wiki.python.org/moin/PythonDecoratorLibrary
TODO: https://github.com/halst/docopt/blob/master/docopt.py
TODO: Argument --strip-output, which should remove homedir/startdir and location from output (stdin, csv and log)
TODO: If one fingerprint finds a match the process should finish and not be scanned with other fingerprints
TODO: There should be argument for looking specific programs in for example: -s joomla,smf
TODO: Add unittests
TODO: Add support to continue interrupted session (Tuomo Komulainen requested). Could be implemented using http://docs.python.org/library/atexit.html with knowledge of current working directory and queues
TODO: http://docs.python.org/library/functions.html#isinstance

Data in YAML-files could include following:
    CVE, CVSS2, OSVDB, Secunia
    Publication date, Fixed date
    CPE, ISS X-Force ID
    SecurityTracker Alert ID, Vendor URL
"""

try:
    import sys
    import time
    import logging
    import traceback
    import os
    from optparse import OptionParser
    from multiprocessing import Process, Queue, Pool
    from multiprocessing.util import log_to_stderr

    from database import Database
    from detect import yaml_fn_dict
    from file_helpers import \
        filepaths_in_dir, validate_directory, check_dir_execution_bit

    from issuereport import IssueReport, get_timestamp
except ImportError, error:
    print('Import error: %s' % error)
    sys.exit(1)

queue = Queue()
database = Database('yamls/')

def populate_directory(fargs):
    directory, checkmodes = fargs

    start_time = time.time()
    try:
        if not validate_directory(directory, checkmodes):
            return time.time() - start_time

        logging.debug('Populating: %s', directory)
        for filename in filepaths_in_dir(directory):
            for appname in database.issues:
                for loc in database.locations(appname, with_lists=False):
                    if filename.endswith(loc):
                        queue.put((filename, loc, appname))
    except Exception:
        logging.error(traceback.format_exc())

    return time.time() - start_time

def populate_userdir(fargs):
    predefined_locations = ['www', 'secure_www']
    userdir, checkmodes = fargs
    locations = []

    try:
        userdir = os.path.abspath(userdir)
        if not validate_directory(userdir, checkmodes):
            return locations

        public_html_location = userdir + '/public_html'
        if validate_directory(public_html_location, checkmodes):
            logging.debug('Appending to locations: %s', public_html_location)
            locations.append(public_html_location)

        sites_location = userdir + '/sites'
        if validate_directory(sites_location, checkmodes):
            for site in os.listdir(sites_location):
                sitedir = sites_location + '/' + site
                if checkmodes:
                    if not check_dir_execution_bit(sitedir):
                        continue

                for predefined_directory in predefined_locations:
                    sites_location_last = sitedir + '/' + predefined_directory
                    if validate_directory(sites_location_last, checkmodes):
                        logging.debug('Appending to locations: %s', sites_location_last)
                        locations.append(sites_location_last)
    except Exception:
        logging.error(traceback.format_exc())

    return locations

class PopulateScanQueue:
    def populate(self, directories, checkmodes=False):
        """ Populates worker queue for further scanning. Takes list of
            directories to be scanned and checkmodes boolean if execution bit should be
            taken into account. """
        try:
            """Use list of directories in loop to check if locations in data dictionary exists."""

            starttime = time.time()

            p = Pool()
            dirs = ((d, checkmodes) for d in directories)
            p.map(populate_directory, dirs, chunksize=200)

            # all done
            queue.put(None)

            logging.info('Scanning for locations finished. Elapsed time: %.4f', \
                         time.time() - starttime)

        except OSError:
            logging.error(traceback.format_exc())
            sys.exit(traceback.format_exc())
        except Exception:
            logging.error(traceback.format_exc())

    def populate_predefined(self, startdir, checkmodes):
        if not type(startdir) == str:
            sys.exit('Error in populate_predefined value startdir not a string. Value is: "%s" with type %s.' % (startdir, type(startdir)[0]))
        try:
            logging.debug('Populating predefined directories: %s', startdir)
            starttime = time.time()

            p = Pool()
            dirs = (startdir + '/' + d for d in os.listdir(startdir))
            udirs = p.imap_unordered(populate_userdir, \
                                     ((d, checkmodes) for d in dirs), \
                                     chunksize=200)
            p.close()
            locations = [item for sublist in udirs for item in sublist]

            logging.info('Total amount of locations: %s, time elapsed: %.4f', \
                         len(locations), time.time() - starttime)

            self.populate(locations, checkmodes)
        except Exception:
            logging.error(traceback.format_exc())

def compare_versions(secure_version, file_version, appname=None):
    """Comparison of found version numbers. Value current_version is predefined
       and file_version is found from file using grep. Value appname is used to
       separate different version numbering syntax"""
    try:
        if not type(secure_version) == str:
            logging.debug('Secure version must be a string when comparing: %s', \
                          secure_version)

        if not type(file_version) == str:
            logging.debug('Version from file must be a string when comparing: %s', \
                          file_version)

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
    except Exception:
        logging.error(traceback.format_exc())

def handle_results(report, appname, file_version, item_location, application_cve, \
                   application_secure):
    try:
        logging.debug('%s with version %s from %s with vulnerability %s. This installation should be updated to at least version %s.', appname, file_version, item_location, application_cve, application_secure)
        print('%s Found: %s %s -> %s (%s)' % (get_timestamp(), item_location, file_version, application_secure, appname))
        report.add(appname, item_location, file_version, application_secure, application_cve)
    except Exception:
        logging.error(traceback.format_exc())

def Worker():
    """This is the actual worker which calls smaller functions in case of
    correct directory/file match is found.

        - Takes and removes item from queue
        - Detection in case of correct directory/file match is found
        - Compares found version against secure version in YAML
        - Calls logging

    Every worker runs in a loop.

    """
    try:
        report = IssueReport()
    except Exception:
        report.close()
        logging.error(traceback.format_exc())
        return

    while 1:
        try:
            item = queue.get()
            if not item:
                break

            item_location, location, appname = item
            logging.info('Processing: %s (%s)', appname, item_location)

            for issue in database.issues[appname].itervalues():
                logging.debug('Processing item %s with location %s with with appname %s issue %s', \
                              item_location, location, appname, issue)

                fn = yaml_fn_dict[issue['fingerprint']]
                file_version = fn(item_location, issue['regexp'])

                # Makes sure we don't go forward without version number from the file
                if file_version:
                    # Tests that version from file is smaller than secure version
                    # with application fingerprint-function
                    logging.debug('Comparing versions %s:%s for item %s', \
                                  issue['secure_version'], file_version, item_location)

                    if compare_versions(issue['secure_version'], file_version, appname):
                        # item_location is stripped from application location so that
                        # we get cleaner output and actual installation directory
                        install_dir = item_location[:item_location.find(location)]

                        # Calls result handler (goes to CSV and log)
                        handle_results(report, appname, file_version, install_dir, \
                                       issue['cve'], issue['secure_version'])
                else:
                    logging.debug('No version found from item: %s with regexp %s', \
                                  item_location, issue['regexp'])
        except Exception:
            logging.error(traceback.format_exc())
    report.close()

def main():
    logfile = 'pyfiscan.log'

    # Available logging levels, which are also hardcoded to usage
    levels = {'info': logging.INFO, 'debug': logging.DEBUG}

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
        help="Specifies logging level: info, debug")

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
        logging.basicConfig(filename=logfile, level=level, format='%(asctime)s %(levelname)s %(funcName)s:%(lineno)d %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        os.chmod(logfile, 0600)
    except IOError as (errno, strerror):
        if errno == int('13'):
            sys.exit('Error while writing to logfile: %s' % strerror)
    try:
        # stderr to /dev/null
        devnull_fd = open(os.devnull, "w")
        sys.stderr = devnull_fd
        log_to_stderr()

        # Starts the asynchronous workers. Amount of workers is the same as cores in server.
        # http://docs.python.org/library/multiprocessing.html#multiprocessing.pool.multiprocessing.Pool
        logging.debug('Starting workers.')
        pool = Pool()
        pool.apply_async(Worker)

        # Starts the actual populator daemon to get possible locations, which will be verified by workers.
        # http://docs.python.org/library/multiprocessing.html#multiprocessing.Process
        logging.debug('Starting scan queue populator.')
        p = PopulateScanQueue()
        if opts.directory:
            logging.debug('Scanning recursively from path: %s', opts.directory)
            populator = Process(target=p.populate, args=([opts.directory],))
        elif opts.home:
            logging.debug('Scanning predefined variables: %s', opts.home)
            populator = Process(target=p.populate_predefined, args=(opts.home, opts.checkmodes,))
        else:
            logging.debug('Scanning predefined variables: /home')
            populator = Process(target=p.populate_predefined, args=('/home', opts.checkmodes,))

        populator.start()
        """Prevents any more tasks from being submitted to the pool. Once all the tasks have been completed the worker processes exit using kill-signal None
        http://docs.python.org/library/multiprocessing.html#multiprocessing.pool.multiprocessing.Pool.close
        """
        populator.join()
        pool.close()
        pool.join()
        runtime = time.time() - starttime
        logging.info('Scanning ended, which took %s seconds', runtime)
    except KeyboardInterrupt:
        logging.info('Received keyboard interrupt. Exiting..')
        pool.join()
        populator.join()
        runtime = time.time() - starttime
        logging.info('Scanning ended, which took %s seconds', runtime)
    except Exception:
        logging.error(traceback.format_exc())

if __name__ == "__main__":
    main()
