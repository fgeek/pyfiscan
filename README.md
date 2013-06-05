pyfiscan
========

About
-----

Pyfiscan is free web-application vulnerability and version scanner and can be
used to locate out-dated versions of common web-applications in Linux-servers.
Example use case is hosting-providers keeping eye on their users installations
to keep up with security-updates. Fingerprints are easy to create and modify as
user can write those in YAML-syntax.

Requirements
------------

* Python 2.7
* Python modules PyYAML docopt
* GNU/Linux web server

Testing is done mainly with [GNU/Linux Debian](http://www.debian.org/) stable.
Windows is not currently supported.

Detects following software
--------------------------

* Joomla 1.5: [CVE-2012-1598](http://developer.joomla.org/security/news/396-20120305-core-password-change advisory), [CVE-2012-1599](ttp://developer.joomla.org/security/news/397-20120306-core-information-disclosure advisory)
* Joomla 1.7: CVE-2012-0819, CVE-2012-0820, CVE-2012-0821, CVE-2012-0822
* WordPress: CVE-2013-0235, CVE-2013-0236, CVE-2013-0237 [WordPress News](https://wordpress.org/news/2013/01/wordpress-3-5-1/)
* MoinMoin: CVE-2011-1058 [OSVDB 71025](http://osvdb.org/71025)
* CMSMS: [CVE-2011-4310](http://www.cmsmadesimple.org/2011/08/Announcing-CMSMS-1-9-4-3---Security-Release/)
* e107: CVE-2012-6434 [OSVDB 88908](http://osvdb.org/88908)
* phpBB3: CVE-2011-0544 SA42343
* MediaWiki: CVE-2013-2114 [OSVDB 93629](http://osvdb.org/93629)
* WikkaWiki: CVE-2011-4448, CVE-2011-4449, CVE-2011-4450, CVE-2011-4451, CVE-2011-4452 OSVDB 77390-77394 [WikkaWiki security advisory](http://blog.wikkawiki.org/2011/12/04/security-updates-for-1-3-11-3-2/) 
* TikiWiki: CVE-2012-0911 OSVDB:83534, CVE-2012-3996 [OSVDB 83533](http://osvdb.org/83533)
* phpAlbum: CVE-2011-4806, CVE-2011-4807, OSVDB:74980, OSVDB 21410
* SMF: CVE-2011-3615, CVE-2011-4173, OSVDB:76317,76318,76822 SA46386
* Roundcube: CVE-2012-3508, OSVDB:90175,90177
* Drupal: CVE-2013-0316 [OSVDB 90517](http://osvdb.org/90517) [Drupal security advisory SA-CORE-2013-002](http://drupal.org/SA-CORE-2013-002)
* MantisBT: CVE-2013-1883
* Foswiki: CVE-2013-1666 [OSVDB 90345](http://osvdb.org/90345) [Foswiki security advisory](http://foswiki.org/Support/SecurityAlert-CVE-2013-1666)
* Trac: CVE-2010-5108 [OSVDB 63317](http://osvdb.org/63317)
* Gallery: CVE-2013-2138 [security advisory](http://galleryproject.org/gallery_3_0_8)

Notes
-----

* Joomla
  * 1.5 is end-of-life since 2012-04-30
  * 1.6 is end-of-life since [2011-08-19](http://www.joomla.org/announcements/release-news/5380-joomla-170-released.html)
  * 1.6.x should be upgraded to 1.6.6 before moving to 1.7.x
  * 1.7 is end-of-life since [2012-02-24](http://www.joomla.org/announcements/release-news/5411-joomla-175-released.html)
  * Upgrade should be done using "Extension manager -> Upgrade" in version 1.6.6 and later
  * [Release and support cycle](http://docs.joomla.org/Release_and_support_cycle)
  * [Setup Security checklist](http://docs.joomla.org/Security_Checklist_4_-_Joomla_Setup)
  * [Upgrading and migrating Joomla](http://docs.joomla.org/Upgrading_and_Migrating_Joomla)
* SMF
  * [End of life of SMF 1.0](http://www.simplemachines.org/community/index.php?P=e9a84908ee7f5c03d14c5ece4b58406e&topic=472913.0)
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

Thanks to
---------

* Tuomo Komulainen for big patches and ideas
* Partly the idea and first lines of (re-written) code came from Atte H. (guaqua)
