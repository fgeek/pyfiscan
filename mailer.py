#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Mailer utility for pyfiscan tool result CSV-files.

@author Henri 'fgeek' Salo <henri@nerv.fi>
@copyright Copyright (c) 2009-2013 Henri Salo
@licence BSD
"""

try:
    import sys 
    import csv
    import getpass
    import os.path
    import smtplib
    import sqlite3
    import traceback
    from email.mime.text import MIMEText
    from jinja2 import Environment, FileSystemLoader
except ImportError, e:
    sys.exit('Import error: %s' % e)


from_address = 'example@example.org'
smtp_server = 'example.org'
smtp_port = 465

# Let's check that we are using at least Python 2.7 or SMTP_SSL does not work.
# We don't need to take care the micro-version
version_major = sys.version_info[0]
version_minor = sys.version_info[1]
if version_major < int(1):
    sys.exit('Python major version needs to be two or higher.\nSMTP_SSL only works with Python 2.7')
if version_minor < int(6):
    sys.exit('Python minor version needs to be seven or higher.\nSMTP_SSL only works with Python 2.7')


def send_email(user, vulnerabilities):
    """Calls template engine and sends email to SMTP server."""
    template_file = os.path.abspath(sys.argv[2])
    templateLoader = FileSystemLoader(searchpath='/')
    templateEnv = Environment(loader=templateLoader)
    template = templateEnv.get_template(template_file)
    msg = MIMEText(template.render(vulnerabilities=vulnerabilities), _charset='utf-8')
    try:
        receivers = user.split(',')
        s = smtplib.SMTP_SSL(smtp_server, smtp_port)  # SMTP_SSL only works with Python 2.7
        username = getpass.getuser()
        password = getpass.getpass()
        s.login(username, password)
        s.ehlo_or_helo_if_needed()
        s.set_debuglevel(1)
        msg['Subject'] = 'Tietoturva-aukollinen sovellus löydetty sivuiltasi'
        msg['From'] = from_address
        msg['To'] = ", ".join(receivers)
        print msg
        s.sendmail(from_address, receivers, msg.as_string())
        s.quit()
    except smtplib.SMTPAuthenticationError:
        sys.exit('Authentication error when connecting to SMTP server.')
    except Exception:
        sys.exit(traceback.format_exc())


def process_csv(csv_file):
    """Imports data from CSV to sqlite3 database in memory. This will use
    send_email so that user receives only one email.

    http://packages.debian.org/libsqlite3-mod-csvtable should be used in the
    future in here.

    conn.enable_load_extension(True)
    conn.load_extension(library_location)
    CREATE VIRTUAL TABLE example USING csvtable('vulnerabilities.csv');
    
    """
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (user TEXT, timestamp TEXT, appname TEXT, version_file TEXT, file_version TEXT, secure_version TEXT, cve TEXT)''')
    conn.commit()
    reader = csv.reader(open(csv_file, 'rb'), delimiter='|', quotechar='|')
    for line in reader:
        user = line[0]
        timestamp = line[1]
        appname = line[2]
        version_file = line[3]
        file_version = line[4]
        secure_version = line[5]
        cve = line[6]
        data = (user, timestamp, appname, version_file, file_version, secure_version, cve)
        c.execute('INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?)', data)
        conn.commit()
    c.execute('SELECT DISTINCT user FROM vulnerabilities')  # unique user
    users = c.fetchall()
    for user in users:
        t = (user[0],)
        vulnerabilities = []
        for vulnerability in c.execute('SELECT timestamp, appname, version_file, file_version, secure_version, cve FROM vulnerabilities WHERE user=?', t):
            vulnerabilities.append(vulnerability)
        send_email(user[0], vulnerabilities)


if __name__ == "__main__":
    print('Please note that it is required to add email| to start of each line in CSV.')
    csv_file = sys.argv[1]
    if os.path.islink(csv_file):
        sys.exit('CSV file %s is a symlink. Exiting..' % csv_file)
    if not os.path.isfile(csv_file):
        sys.exit('Input %s is not a file. Exiting..' % csv_file)
    process_csv(csv_file)
