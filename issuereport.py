import csv
import time
import os

def get_timestamp():
    """Returns string ISO 8601 with hours:minutes:seconds"""
    return time.strftime("%Y-%m-%d %H:%M:%S")

def csv_add(appname, item, file_version, secure_version, cve):
    """Creates CVS-file and writes found vulnerabilities per line. CSV-file can't be symlink.
    
    TODO: Should check that all needed arguments are available.
    TODO: We are doing open and chmod in every csv_add()
    TODO: Should we have exception csv.Error
    """
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
        logging.error('Exception in csv_add: %s' % e)


