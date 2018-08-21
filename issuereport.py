"""Handles listing issues to CSV result file."""
import csv
import time
import os
import sys
import stat

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
        self.csvfile = open(filename, "a")
        os.chmod(filename, stat.S_IREAD|stat.S_IWRITE)
        self.writer = csv.writer(self.csvfile, delimiter='|', quotechar='|')

    def close(self):
        """Closes CSV file handle."""
        if self.csvfile:
            self.csvfile.close()

    def add(self, appname, item, file_version, secure_version, cve):
        """Writes data to CSV file handle."""
        self.writer.writerow((get_timestamp(), appname, item, file_version, secure_version, cve))
