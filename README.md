# pyfiscan ![Build status](https://travis-ci.org/fgeek/pyfiscan.svg?branch=master "Build status")

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

* Python 3
* Python modules PyYAML docopt chardet
* GNU/Linux web server

Testing is done mainly with [GNU/Linux Debian](http://www.debian.org/) stable.
Windows is not currently supported.

Detects following software
--------------------------

* Abantecart
* ATutor
* b2evolution
* BigTree CMS
* Bugzilla
* Centreon
* Claroline
* ClipperCMS
* CMSimple
* CMSMS
* Collabtive
* Concrete5
* Coppermine
* Cotonti
* Croogo
* CubeCart
* Dolibarr
* Dotclear
* Drupal
* e107
* Elefant CMS
* EspoCRM
* Etherpad
* flatCore CMS
* FluxBB
* Foswiki
* FUEL CMS
* Gallery
* Gollum
* HelpDEZk
* HumHub
* ImpressCMS
* ImpressPages
* Jamroom
* Joomla
* Kanboard
* KCFinder
* LiteCart
* Magnolia
* Mahara
* MantisBT
* MediaWiki
* Microweber
* MiniBB
* MODX Revolution
* MoinMoin
* MyBB
* Nibbleblog
* Open Source Social Network
* OpenCart (recommends not to use this software)
* osDate
* ownCloud
* Oxwall
* PBBoard
* phpBB3
* PhpGedView
* phpLiteAdmin
* phpMyAdmin
* Piwigo
* Piwik
* PmWiki
* Postfix Admin
* Redaxo
* Roundcube
* SaurusCMS
* Serendipity
* Shaarli
* Shopware
* SMF
* Spina CMS
* SPIP
* SQLiteManager
* SquirrelMail
* TestLink
* TikiWiki
* Trac
* Vanilla Forums
* WikkaWiki
* WordPress
* Zenphoto
* Zikula

Detects following end-of-life software:
---------------------------------------

* Bugzilla 4.2 is end-of-life since [2015-11-30](https://bugzillaupdate.wordpress.com/2015/07/29/bugzilla-4-2-will-be-eol-on-20151130/)
* Drupal 6 is end-of-life since [2016-02-24](https://www.drupal.org/drupal-6-eol)
* Gallery 1
* Joomla 1.5 is end-of-life since 2012-04-30
* Joomla 1.6 is end-of-life since [2011-08-19](http://www.joomla.org/announcements/release-news/5380-joomla-170-released.html). 1.6.x should be upgraded to 1.6.6 before moving to 1.7.x
* Joomla 1.7 is end-of-life since [2012-02-24](http://www.joomla.org/announcements/release-news/5411-joomla-175-released.html)
* Joomla 2.5
* MediaWiki 1.18
* MediaWiki 1.19 is end-of-life since [2015-04-25](https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-May/000177.html)
* MediaWiki 1.20
* MediaWiki 1.21 is end-of-life since [2014-06-25](http://lists.wikimedia.org/pipermail/mediawiki-announce/2014-June/000153.html)
* MediaWiki 1.22
* MediaWiki 1.23 is end-of-life since [2017-05-31](https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-May/000210.html)
* MediaWiki 1.24
* MediaWiki 1.25
* MediaWiki 1.26 is end-of-life since [2016-11-20](https://lists.wikimedia.org/pipermail/mediawiki-announce/2016-November/000204.html)
* MediaWiki 1.27 is end-of-life since [2019-06-06](https://lists.wikimedia.org/pipermail/mediawiki-announce/2019-June/000231.html)
* MediaWiki 1.28 is end-of-life since [2017-11-01](https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-November/000214.html)
* MediaWiki 1.29 is end-of-life since [2018-06](https://lists.wikimedia.org/pipermail/mediawiki-announce/2018-September/000223.html)
* MediaWiki 1.30 is end-of-life since [2019-06-06](https://lists.wikimedia.org/pipermail/mediawiki-announce/2019-June/000231.html)
* MediaWiki 1.32 is end-of-life since [2020-01-23](https://lists.wikimedia.org/pipermail/mediawiki-announce/2020-January/000245.html)
* MediaWiki 1.33 is end-of-life since [2020-06-24](https://lists.wikimedia.org/pipermail/mediawiki-announce/2020-June/000253.html)
* MediaWiki 1.34 is end-of-life since [2020-11-30](https://lists.wikimedia.org/pipermail/mediawiki-announce/2020-November/000266.html)
* ownCloud 4
* ownCloud 5
* ownCloud 6
* ownCloud 7
* ownCloud 8.0
* ownCloud 8.1
* ownCloud 8.2
* SaurusCMS

Installation
------------

    sudo apt install python3 python3-pip git virtualenv
    git clone https://github.com/fgeek/pyfiscan.git && cd pyfiscan
    virtualenv -p python3 venv
    source ./venv/bin/activate
    pip3 install -r requirements.lst

or you can use [BlackArch Linux](http://www.blackarch.org/).

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
  * http://codex.galleryproject.org/Gallery2:Security
  * Upgrade using:
      http://example.org/gallery3/index.php/upgrade
      php index.php upgrade
* phpBB (version unknown)
  * Open installation is not a vulnerability since web-interface requests user to authenticate by inserting random data to file.
* Coppermine
  * Not installed when include/config.inc.php is missing.
* Owncloud
  * status.php outputs: {"installed":"true","version":"5.0.6","versionstring":"5.0.5","edition":""}
* Piwigo
  * Not installed if local/config/database.inc.php is missing.
* Claroline
  * Not installed when platform/conf/claro_main.conf.php is missing.
  * Installation pages request user to remove claroline/install/ directory.

Happy users
-----------

* DevNet Oy
* Kapsi Internet-käyttäjät ry
* Shellit.org
* Loopia.se

Contributors
------------

* aapa
* Ari-Martti Hopiavuori
* Atte H. "guaqua"
* Janne Cederberg
* Joonas Kuorilehto
* Juhamatti Niemelä
* Linus Fogelholk
* motikan2010
* Olli Pekkola
* Paul Grant
* Tuomo Komulainen
