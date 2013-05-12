#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Pyfiscan is free web-application vulnerability and version scanner and can be
used to locate out-dated versions of common web-applications in Linux-servers.
Example use case is hosting-providers keeping eye on their users installations
to keep up with security-updates. Fingerprints are easy to create and modify as
user can write those in YAML-syntax.

@author Henri 'fgeek' Salo <henri@nerv.fi>
@copyright Copyright (c) 2009-2013 Henri Salo
@licence BSD
"""

try:
    import logging
    import os
    import sys
    import time
    import traceback
    from docopt import docopt
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
        for filename in filepaths_in_dir(directory, checkmodes):
            for appname in database.issues:
                for loc in database.locations(appname, with_lists=False):
                    if filename.endswith(loc):
                        queue.put((filename, loc, appname))
    except Exception:
        logging.error(traceback.format_exc())
    return time.time() - start_time


def populate_userdir(fargs):
    predefined_locations = ['www', 'secure-www']
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
                    if not check_dir_execution_bit(sitedir, checkmodes):
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
        if not isinstance(startdir, str):
            logging.debug('populate_predefined: value startdir not a string. "%s" with type %s' % (startdir, type(startdir)))
            sys.exit('populate_predefined: value startdir not a string. "%s" with type %s' % (startdir, type(startdir)))
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


def is_not_secure(secure_version, file_version, appname=None):
    """Comparison of version numbers.

    secure_version: predefined value from YAML-files
    file_version: found from file using grep
    appname: used to separate different version numbering syntax

    True when file_version      <   secure_version
    False when file_version     >=  secure_version
    """
    try:
        if not all(isinstance(x, str) for x in (secure_version, file_version)):
            raise TypeError('is_not_secure: input must be str when comparing. secure_version %s, file_version %s', \
                            type(secure_version), type(file_version))
        if appname == 'WikkaWiki':
            # Replace -p → .
            # Example version number: 1.3.2-p7
            secure_version = secure_version.replace('-p', '.')
            file_version = file_version.replace('-p', '.')
        return map(int, secure_version.split('.')) > map(int, file_version.split('.'))
    except Exception:
        logging.error(traceback.format_exc())


def handle_results(report, appname, file_version, item_location, application_cve, \
                   application_secure):
    """Main handler for all results found. Report is instance of IssueReport,
    which handles .csv output.
    """
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

                    if is_not_secure(issue['secure_version'], file_version, appname):
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

    usage = """
    Usage:
      pyfiscan.py [--check-modes] [-l LEVEL]
      pyfiscan.py -r <directory> [-l LEVEL]
      pyfiscan.py --home <directory> [--check-modes] [-l LEVEL]
      pyfiscan.py [-h|--help]
      pyfiscan.py --version

    Options:
      -r DIR            Scans directories recurssively.
      --home DIR        Specifies where the home-directories are located.
      --check-modes     Check using execution bit if we are allowed to traverse directories.
      -l LEVEL          Specifies logging level: info, debug

      If you do not spesify recursive-option predefined directories are scanned, which are:
        /home/user/sites/www
        /home/user/sites/secure-www
        /home/user/public_html

    """
    arguments = docopt(usage, version='pyfiscan 0.9')
    starttime = time.time()  # used to measure program runtime
    if arguments['-l']:
        level_name = arguments['-l']
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
        if arguments['-r']:
            logging.debug('Scanning recursively from path: %s', arguments['-r'])
            populator = Process(target=p.populate, args=([arguments['-r']],))
        elif arguments['--home']:
            logging.debug('Scanning predefined variables: %s', arguments['--home'])
            populator = Process(target=p.populate_predefined, args=(arguments['--home'], arguments['--check-modes'],))
        else:
            logging.debug('Scanning predefined variables: /home')
            populator = Process(target=p.populate_predefined, args=('/home', arguments['--check-modes'],))

        populator.start()
        # Prevents any more tasks from being submitted to the pool. Once all the tasks have been completed the worker processes exit using kill-signal None
        # http://docs.python.org/library/multiprocessing.html#multiprocessing.pool.multiprocessing.Pool.close
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
