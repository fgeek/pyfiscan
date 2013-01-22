#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    import sys
    import smtplib
    import csv
    import getpass
    from email.mime.text import MIMEText
except ImportError, error:
    sys.exit('Import error: %s' % error)


from_address = 'example@example.org'
smtp_server = 'example.org'
smtp_port = 465

# Let's check that we are using at least Python 2.7 or SMTP_SSL does not work
version_major = sys.version_info[0]
version_minor = sys.version_info[1]
# We don't need to take care the micro-version
if version_major < int(1):
    sys.exit('Python major version needs to be two or higher.\nSMTP_SSL only works with Python 2.7')
if version_minor < int(6):
    sys.exit('Python minor version needs to be seven or higher.\nSMTP_SSL only works with Python 2.7')


def send_email(user, timestamp, appname, version_file, file_version, secure_version, cve, from_address, smtp_server, smtp_port):
    """This will handle email sending to SMTP-server."""
    msg = MIMEText('Hei, olemme huomanneet, että käytössäsi on ' + appname + '-sovellus, jonka versio on haavoittuvainen. Voit korjata tilanteen päivittämällä asennuksen vähintään versioon ' + secure_version + '. Apua sovelluksen päivittämiseen saat vastaamalla tähän sähköpostiin.\n\nTietoturva-aukollinen sovellus löytyy hakemistostasi: ' + version_file + '\n\nLisätietoja: ' + cve + '\n\nTähän sähköpostiin ei tarvitse vastata mikäli sinulla ei ole ongelmia päivityksessä.\n\nTerveisin,\n   Henri Salo', _charset='utf-8')

    to_address = user
    try:
        s = smtplib.SMTP_SSL(smtp_server, smtp_port)  # SMTP_SSL only works with Python 2.7
        s.login(getpass.getuser(), getpass.getpass())
        s.ehlo_or_helo_if_needed()
        s.set_debuglevel(1)
        msg['Subject'] = 'Tietoturva-aukollinen sovellus löydetty sivuiltasi'
        msg['From'] = from_address
        msg['To'] = to_address
        print msg
        s.sendmail(from_address, [to_address], msg.as_string())
        s.quit()
    except Exception, error:
        sys.exit('Exception: %s' % error)


def read_csv(csv_file, from_address):
    """Reads data in from CSV-file."""
    reader = csv.reader(open(csv_file, 'rb'), delimiter='|', quotechar='|')
    counter = 0
    for line in reader:
        user = line[0]
        timestamp = line[1]
        appname = line[2]
        version_file = line[3]
        file_version = line[4]
        secure_version = line[5]
        cve = line[6]
        counter = counter + 1
        if user and timestamp and appname and version_file and file_version and  secure_version and cve:
            print('[*] Processing %i line..' % counter)
            send_email(user, timestamp, appname, version_file, file_version, secure_version, cve, from_address, smtp_server, smtp_port)

    print('\n[*] Processed %i notifications. Happy customer is a happy customer!' % counter)


print('Please note that it is required to add email| to start of each line in CSV.')
read_csv(sys.argv[1], from_address, smtp_server, smtp_port)
