pyfiscan
========

About
-----

Pyfiscan is free web-application vulnerability and version scanner and can be
used to locate out-dated versions of common web-applications in Linux-servers.
Example use case is hosting-providers keeping eye on their users installations
to keep up with security-updates. Fingerprints are easy to create and modify as
user can write those in YAML-syntax. Pyfiscan also contains tool to create
email alerts using templates.

Requirements
------------

* Python 2.7
* Python modules PyYAML docopt
* GNU/Linux web server

Testing is done mainly with [GNU/Linux Debian](http://www.debian.org/) stable.
Windows is not currently supported.

Detects following software
--------------------------

* CMSMS: [CVE-2011-4310](http://www.cmsmadesimple.org/2011/08/Announcing-CMSMS-1-9-4-3---Security-Release/)
* Coppermine: [Vendor security advisory](http://forum.coppermine-gallery.net/index.php/topic,74682.0.html) CVE-2012-1613, CVE-2012-1614, http://osvdb.org/80731 http://osvdb.org/80732 http://osvdb.org/80733 http://osvdb.org/80734 http://osvdb.org/80735
* Cotonti: CVE-2013-4789 http://osvdb.org/95842 http://www.cotonti.com/news/announce/siena_0914_released
* Dolibarr: CVE-2013-2091 CVE-2013-2092 CVE-2013-2093
* Drupal: CVE-2013-0316 [OSVDB 90517](http://osvdb.org/90517) [Drupal security advisory SA-CORE-2013-002](http://drupal.org/SA-CORE-2013-002)
* Foswiki: CVE-2013-1666 [OSVDB 90345](http://osvdb.org/90345) [Foswiki security advisory](http://foswiki.org/Support/SecurityAlert-CVE-2013-1666)
* Gallery: CVE-2013-2138 [security advisory](http://galleryproject.org/gallery_3_0_8)
* Joomla 1.5: 1.5 is end-of-life since 2012-04-30
* Joomla 1.6: 1.6 is end-of-life since [2011-08-19](http://www.joomla.org/announcements/release-news/5380-joomla-170-released.html). 1.6.x should be upgraded to 1.6.6 before moving to 1.7.x
* Joomla 1.7: 1.7 is end-of-life since [2012-02-24](http://www.joomla.org/announcements/release-news/5411-joomla-175-released.html)
* Joomla 2.5: CVE-2013-5576 [OSVDB:95933](http://osvdb.org/95933) [Security advisory](http://developer.joomla.org/security/563-20130801-core-unauthorised-uploads.html)
* Joomla 3: CVE-2013-5576 [OSVDB:95933](http://osvdb.org/95933) [Security advisory](http://developer.joomla.org/security/563-20130801-core-unauthorised-uploads.html)
* Magnolia: CVE-2013-4621
* MantisBT: CVE-2013-4460
* MediaWiki: CVE-2013-4301 http://osvdb.org/96913, CVE-2013-4302 http://osvdb.org/96912, CVE-2013-4303 http://osvdb.org/96911, http://secunia.com/advisories/54715/
* Microweber: [CVE-2013-5984](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-5984) [OSVDB:97809](http://osvdb.org/97809) [HTB23175](https://www.htbridge.com/advisory/HTB23175)
* MoinMoin: CVE-2011-1058 [OSVDB 71025](http://osvdb.org/71025)
* MyBB: http://osvdb.org/92683 http://osvdb.org/92684 http://osvdb.org/92686 http://osvdb.org/92687 http://osvdb.org/92688 http://osvdb.org/92689
* Roundcube: CVE-2013-5646 [OSVDB 96722](http://osvdb.org/96722)
* SMF 1: [SMF advisory](http://www.simplemachines.org/community/index.php?topic=496403)
* SMF 2: [OSVDB 76822](http://osvdb.org/76822) [SMF advisory](http://www.simplemachines.org/community/index.php?topic=509417)
* Serendipity: CVE-2013-5670 [Serendipity release advisory](http://blog.s9y.org/archives/250-Serendipity-1.7.3-released.html)
* TestLink: CVE-2012-2275 http://osvdb.org/84712 http://osvdb.org/84711 http://osvdb.org/84713
* TikiWiki: CVE-2012-0911 OSVDB:83534, CVE-2012-3996 [OSVDB 83533](http://osvdb.org/83533)
* Tiny Tiny RSS: SA43424 [OSVDB:70934](http://osvdb.org/70934)
* TinyTinyRSS: http://osvdb.org/70934 http://secunia.com/advisories/43424/
* Trac: CVE-2010-5108 [OSVDB 63317](http://osvdb.org/63317)
* WikkaWiki: CVE-2013-5586 [SA54790](http://secunia.com/advisories/54790/)
* WordPress: CVE-2013-4338, CVE-2013-4339, CVE-2013-4340
* Zenphoto: http://www.waraxe.us/content-96.html http://osvdb.org/87015
* e107: CVE-2012-6434 [OSVDB 88908](http://osvdb.org/88908)
* osDate: http://osvdb.org/63005 http://osvdb.org/63006
* phpAlbum: CVE-2011-4806, CVE-2011-4807, OSVDB:74980, OSVDB 21410
* phpBB3: CVE-2011-0544 SA42343
* phpMyAdmin: CVE-2013-5029 http://osvdb.org/95999

Installation
------------

    git clone https://github.com/fgeek/pyfiscan.git && cd pyfiscan
    pip install -r requirements.lst

Notes
-----

* WordPress
  * [Announcing a secure SWFUpload fork](http://make.wordpress.org/core/2013/06/21/secure-swfupload/)
* Joomla
  * Upgrade should be done using "Extension manager -> Upgrade" in version 1.6.6 and later
  * [Release and support cycle](http://docs.joomla.org/Release_and_support_cycle)
  * [Setup Security checklist](http://docs.joomla.org/Security_Checklist_4_-_Joomla_Setup)
  * [Upgrading and migrating Joomla](http://docs.joomla.org/Upgrading_and_Migrating_Joomla)
  * Joomla 2.x creates random SQL table prefix
  * Joomla 3.x informs and shows user a button to remove installation-directory
  * Creates ./configuration.php in installation
  * Creates robots.txt, which contains word "Joomla"
* SMF
  * [End of life of SMF 1.0](http://www.simplemachines.org/community/index.php?P=e9a84908ee7f5c03d14c5ece4b58406e&topic=472913.0)
  * Installer requests users with button to delete install.php
* TikiWiki
  * [End of life of TikiWiki 7.x](http://info.tiki.org/article182-Tiki-8-1-Now-Available-End-of-Life-for-Tiki-7-x)
  * [8.4 is last release of TikiWiki 8.x](http://info.tiki.org/article191-Tiki-Releases-8-4)
  * [End of life of TikiWiki 8.x](http://info.tiki.org/article195-Tiki-Releases-9-0)
* MediaWiki
  * [End of Life of 1.18.x](http://www.mediawiki.org/wiki/Version_lifecycle)
* Gallery
  * Not installed when config.php is missing.
  * Upgrade using:
      http://example.org/gallery3/index.php/upgrade
      php index.php upgrade
* phpBB (version unknown)
  * Open installation is not a vulnerability since web-interface requests user to authenticate by inserting random data to file.
* Coppermine
  * Not installed when include/config.inc.php is missing.
* Owncloud:
  * status.php outputs: {"installed":"true","version":"5.0.6","versionstring":"5.0.5","edition":""}


Thanks to
---------

* Tuomo Komulainen for big patches and ideas
* Partly the idea and first lines of (re-written) code came from Atte H. (guaqua)
* Juhamatti Niemelä for database updates
* Ari-Martti Hopiavuori for database feedback
