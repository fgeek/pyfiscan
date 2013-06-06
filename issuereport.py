"""Handles listing issues to CSV result file."""
import csv
import time
import os
import sys


def get_timestamp():
    """Returns string ISO 8601 with hours:minutes:seconds"""
    return time.strftime("%Y-%m-%d %H:%M:%S")


class IssueReport(object):
    """Handles file operations for CSV result file."""
    def __init__(self):
        """Opens, chmods and creates CSV file handle."""
        filename = 'pyfiscan-vulnerabilities-' + time.strftime("%Y-%m-%d") + '.csv'
        if os.path.islink(filename):
            sys.exit('CSV-file %s is a symlink. Exiting..' % filename)
        if not os.path.isfile(filename):
            sys.exit('CSV-file %s is a not a file. Exiting..' % filename)
        self.csvfile = open(filename, "a")
        os.chmod(filename, 0600)
        self.writer = csv.writer(self.csvfile, delimiter='|', quotechar='|')

    def close(self):
        """Closes CSV file handle."""
        if self.csvfile:
            self.csvfile.close()

    def add(self, appname, item, file_version, secure_version, cve):
        """Writes data to CSV file handle."""
        self.writer.writerow((get_timestamp(), appname, item, file_version, secure_version, cve))
