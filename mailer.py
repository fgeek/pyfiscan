#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Mailer utility for pyfiscan tool result CSV-files.

@author Henri 'fgeek' Salo <henri@nerv.fi>
@copyright Copyright (c) 2009-2013 Henri Salo
@licence BSD
"""

try:
    import csv
    import getpass
    import smtplib
    import sys
    import traceback
    from email.mime.text import MIMEText
except ImportError, e:
    sys.exit('Import error: %s' % e)


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


def send_email(user, appname, version_file, file_version, secure_version, cve):
    """This will handle email sending to SMTP-server."""
#    msg = MIMEText('Hei, olemme huomanneet, että käytössäsi on ' + appname + '-sovellus, jonka versio ' + file_version + ' on haavoittuvainen. Voit korjata tilanteen päivittämällä asennuksen vähintään versioon ' + secure_version +'. Apua sovelluksen päivittämiseen saat vastaamalla tähän sähköpostiin sekä tästä ohjeesta: http://www.kapsi.fi/ohjeet/www-paivitys.html\n\nHaavoittuva sovellus löytyy hakemistostasi: ' + version_file + '\n\nLisätietoja: ' + cve + '\n\nTähän sähköpostiin ei tarvitse vastata mikäli sinulla ei ole ongelmia päivityksessä. Huomaathan, että myös htaccessin takana olevat sivut suositellaan päivittämään ja keskeneräiset asennukset on asennettava loppuun tai poistettava. Mikäli verkkotunnuksesi on siirretty voit ajaa komennon "chmod 0200 hakemisto", jolloin emme lähetä sinulle enää muistutuksia.\n\nTerveisin,\n   Henri Salo\n   Kapsin ylläpito\n   yllapito@tuki.kapsi.fi\n\n   Kapsi Internet-käyttäjät ry\n   http://www.kapsi.fi/\n   http://tuki.kapsi.fi/', _charset='utf-8')
    msg = MIMEText('Hei, olemme huomanneet, että käytössäsi on ' + appname + '-sovellus, jonka versio ' + file_version + ' on haavoittuvainen. Voit korjata tilanteen päivittämällä asennuksen vähintään versioon ' + secure_version + '. Apua sovelluksen päivittämiseen saat vastaamalla tähän sähköpostiin.\n\nTietoturva-aukollinen sovellus löytyy hakemistostasi: ' + version_file + '\n\nLisätietoja: ' + cve + '\n\nTähän sähköpostiin ei tarvitse vastata mikäli sinulla ei ole ongelmia päivityksessä.\n\nTerveisin,\n   Henri Salo', _charset='utf-8')
    to_address = user
    try:
        s = smtplib.SMTP_SSL(smtp_server, smtp_port)  # SMTP_SSL only works with Python 2.7
        username = getpass.getuser()
        password = getpass.getpass()
        s.login(username, password)
        s.ehlo_or_helo_if_needed()
        s.set_debuglevel(1)
        msg['Subject'] = 'Tietoturva-aukollinen sovellus löydetty sivuiltasi'
        msg['From'] = from_address
        msg['To'] = to_address
        print msg
        s.sendmail(from_address, [to_address], msg.as_string())
        s.quit()
    except Exception:
        sys.exit(traceback.format_exc())


def read_csv(csv_file):
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
            send_email(user, appname, version_file, file_version, secure_version, cve)
    print('\n[*] Processed %i notifications. Happy customer is a happy customer!' % counter)


print('Please note that it is required to add email| to start of each line in CSV.')
read_csv(sys.argv[1])
