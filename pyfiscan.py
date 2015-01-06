#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Pyfiscan is free web-application vulnerability and version scanner and can be
used to locate out-dated versions of common web-applications in Linux-servers.
Example use case is hosting-providers keeping eye on their users installations
to keep up with security-updates. Fingerprints are easy to create and modify as
user can write those in YAML-syntax.

@author Henri Salo <henri@nerv.fi>
@copyright Copyright (c) 2009-2015 Henri Salo
@license BSD
"""

from __future__ import division
import sys
try:
    import csv
    import logging
    import os
    import scandir
    import time
    import traceback
    from docopt import docopt
    from multiprocessing import Process, Queue, Pool
    from multiprocessing.util import log_to_stderr
    # internal imports
    from database import Database
    from detect import yaml_fn_dict
    from file_helpers import \
        filepaths_in_dir, validate_directory, check_dir_execution_bit, \
        postprocess_php5fcgi

    from issuereport import IssueReport, get_timestamp
except ImportError, error:
    print('Import error: %s' % error)
    sys.exit(1)

queue = Queue()


def populate_directory(fargs):
    """
    Populates queue for workers. Consumes lots of disk I/O.

    """
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

def populate_file(fargs):
    """
    Populates queue for works based on list of filenames from file.
    """
    logging.debug('Entering populate_file')
    filelist, checkmodes = fargs
    start_time = time.time()
    try:
        if not os.path.isfile(filelist):
            logging.debug('Empty file: %s', filelist)
            return time.time() - start_time
        logging.debug('Parsing filelist inside populate_file: %s', filelist)
        with open(filelist) as f:
            for file in f:
                filename = file.strip()
                logging.debug('Found file: $s', filename)
                for appname in database.issues:
                    for loc in database.locations(appname, with_lists=False):
                        if filename.endswith(loc):
                            logging.debug('Found: %s %s %s',filename,loc,appname)
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
            for site in scandir.scandir(sites_location):
                site = site.name
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
            # Use list of directories in loop to check if locations in data dictionary exists.
            starttime = time.time()
            p = Pool()
            dirs = ((d, checkmodes) for d in directories)
            p.map(populate_directory, dirs, chunksize=200)
            queue.put(None)  # All done. Sending kill signal.
            p.close()
            p.join()
            logging.info('Scanning for locations finished. Elapsed time: %.4f', \
                         time.time() - starttime)
        except OSError:
            logging.error(traceback.format_exc())
            sys.exit(traceback.format_exc())
        except Exception:
            logging.error(traceback.format_exc())

    def populate_filelist(self, filelist, checkmodes=False):
        try:
            # Loop through and pass the files to the worker function
            starttime = time.time()
            logging.debug('Entered populate_filelist')
            p = Pool()
            files = ((f,checkmodes) for f in filelist)
            p.map(populate_file, files, chunksize=200)
            queue.put(None)  # All done. Sending kill signal.
            p.close()
            p.join()
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
            dirs = (startdir + '/' + d.name for d in scandir.scandir(startdir))
            udirs = p.imap_unordered(populate_userdir, \
                                     ((d, checkmodes) for d in dirs), \
                                     chunksize=200)
            p.close()
            p.join()
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
    if secure_version == 'N/A':
        return True
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
        print('%s Found: %s %s → %s (%s)' % (get_timestamp(), item_location, file_version, application_secure, appname))
        report.add(appname, item_location, file_version, application_secure, application_cve)
    except Exception:
        logging.error(traceback.format_exc())


def check_old_results(csv_file):
    """Handles old CSV result files and detects if applications have been
    updated or not.

    """
    report = IssueReport()
    # Exit in case csv_file is symlink
    if os.path.islink(csv_file):
        sys.exit('CSV file %s is a symlink. Exiting..' % csv_file)
    reader = csv.reader(open(csv_file, 'rb'), delimiter='|', quotechar='|')
    # Opens database handle
    database = Database('yamls/', includes=None)
    total = 0
    notfixed = 0
    fixed = 0
    for line in reader:
        total += 1
        appname = line[1]
        file_location = line[2]
        try:
            for issue in database.issues[appname].itervalues():
                for location in issue['location']:
                    # Loads fingerprint function from YAML file and checks for
                    # version from detected location
                    fn = yaml_fn_dict[issue['fingerprint']]
                    item_location = os.path.abspath(file_location + '/' + location)
                    if not os.path.exists(item_location):
                        fixed += 1
                        break
                    if not os.path.isfile(item_location):
                        break
                    print('Checking version from: %s' % (item_location))
                    file_version = fn(item_location, issue['regexp'])
                    if not file_version:
                        break
                    # item_location is stripped from application location so that
                    # we get cleaner output and actual installation directory
                    install_dir = item_location[:item_location.find(location)]
                    if is_not_secure(issue['secure_version'], file_version, appname):
                        # Calls result handler (goes to CSV and log)
                        handle_results(report, appname, file_version, file_location, issue['cve'], issue['secure_version'])
                        print('NOT FIXED: %s (%s)' % (install_dir, appname))
                        notfixed += 1
                    else:
                        print('FIXED: %s (%s)' % (install_dir, appname))
                        fixed += 1
        except KeyError:
            print traceback.format_exc()
            pass
        except TypeError:
            print traceback.format_exc()
            pass
    if total == 0:
        sys.exit('No lines in CSV file. Exiting..')
    pers = fixed / total * 100
    print '{0} of {1} have upgraded, which is {2:.2f}%.'.format(fixed, total, pers)
    report.close()


def Worker(home_location, post_process):
    """This is the actual worker which calls smaller functions in case of
    correct directory/file match is found.

        - Takes and removes item from queue
        - Detection in case of correct directory/file match is found
        - Compares found version against secure version in YAML
        - Calls logging

    Every worker runs in a loop.

    """
    # Opens file handle to CSV
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
                # Loads fingerprint function from YAML file and checks for
                # version from detected location
                fn = yaml_fn_dict[issue['fingerprint']]
                file_version = fn(item_location, issue['regexp'])
                # Makes sure we don't go forward without version number from the file
                if file_version:
                    # Tests that version from file is smaller than secure version
                    # with fingerprint function
                    logging.debug('Comparing versions %s:%s for item %s', \
                                  issue['secure_version'], file_version, item_location)
                    if is_not_secure(issue['secure_version'], file_version, appname):
                        # Executes post processing. Does not do anything in case
                        # post_processing is not defined in yaml fingerprint.

                        # Do not do php5.fcgi check for public_html
                        if not home_location:
                            home_location = '/home'
                        if item_location[len(os.path.abspath(home_location)):].split('/')[:5][2] == 'public_html':
                            public_html_used = True
                        else:
                            public_html_used = False

                        if post_process and not public_html_used:
                            try:
                                if issue['post_processing'][0] == 'php5.fcgi':
                                    if not postprocess_php5fcgi(home_location, item_location):
                                        break
                            except KeyError:
                                pass
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


if __name__ == "__main__":
    logfile = 'pyfiscan.log'
    usage = """
    Usage:
      pyfiscan.py [--check-modes] [-p] [-l LEVEL] [-a NAME]
      pyfiscan.py -r <directory> [-l LEVEL] [-a NAME]
      pyfiscan.py --home <directory> [--check-modes] [-p] [-l LEVEL] [-a NAME]
      pyfiscan.py --check <FILE>
      pyfiscan.py --file <FILE> [-l LEVEL] [-a NAME]
      pyfiscan.py [-h|--help]
      pyfiscan.py --version

    Options:
      -r DIR            Scans directories recursively.
      -p                Enable post process for php5.fcgi file checks.
      --home DIR        Specifies where the home-directories are located.
      --check FILE      Rechecks entries in old CSV files.
      --file            Scan using list of filename/paths in FILE (e.g. locate output)
      --check-modes     Check using execution bit if we are allowed to traverse directories.
      -l LEVEL          Specifies logging level: info, debug.
      -a NAME           Scans only specific applications. Delimiter: ,

      If you do not spesify recursive-option predefined directories are scanned, which are:
        /home/user/sites/vhost/www
        /home/user/sites/vhost/secure-www
        /home/user/public_html

    """
    arguments = docopt(usage, version='pyfiscan 0.9')
    starttime = time.time()  # used to measure program runtime
    # If enabled only checks status using old result file
    # Check argument must be handled first so that we don't open handle to
    # logfile. Maybe we add some kind of logging to checker in the future
    if arguments['--check']:
        check_old_results(arguments['--check'])
        sys.exit(1)
    # Available logging levels, which are also hardcoded to usage
    levels = {'info': logging.INFO, 'debug': logging.DEBUG}
    if arguments['-l']:
        level_name = arguments['-l']
    else:
        level_name = str('info')
    if not level_name in levels:
        print('No such log level. Available levels are: %s' % levels.keys())
        sys.exit(1)
    level = levels.get(level_name, logging.NOTSET)
    # Post process is used for checking if file exists in installation
    # directory. For example config files and PHP fcgi-file.
    post_process = None
    if arguments['-p']:
        post_process = True
    # Includes is used to scan only specific applications.
    includes = None
    if arguments['-a']:
        includes = arguments['-a']
        includes = includes.split(',')
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
        database = Database('yamls/', includes)
        if len(database.issues) == 0:
            sys.exit('Empty database. Exiting..')
        # stderr to /dev/null
        devnull_fd = open(os.devnull, "w")
        sys.stderr = devnull_fd
        log_to_stderr()
        # Starts the asynchronous workers. Amount of workers is the same as cores in server.
        # http://docs.python.org/library/multiprocessing.html#multiprocessing.pool.multiprocessing.Pool
        logging.debug('Starting workers.')
        pool = Pool()
        pool.apply_async(Worker, [arguments['--home'], post_process])
        # Starts the actual populator daemon to get possible locations, which will be verified by workers.
        # http://docs.python.org/library/multiprocessing.html#multiprocessing.Process
        p = PopulateScanQueue()
        if arguments['-r']:
            logging.debug('Scanning recursively from path: %s', arguments['-r'])
            populator = Process(target=p.populate, args=([arguments['-r']],))
        elif arguments['--home']:
            logging.debug('Scanning predefined variables: %s', arguments['--home'])
            populator = Process(target=p.populate_predefined, args=(arguments['--home'], arguments['--check-modes'],))
        elif arguments['--file']:
            logging.debug('Scanning using file : %s', arguments['--file'])
            populator = Process(target=p.populate_filelist, args=([arguments['--file']],))
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
        print('Received keyboard interrupt. Exiting..')
        runtime = time.time() - starttime
        logging.info('Scanning ended, which took %s seconds', runtime)
        print('Scanning ended, which took %s seconds', runtime)
    except Exception:
        logging.error(traceback.format_exc())
