import os
import logging
import re
import chardet

yaml_fn_dict = {}


def yaml_visible(fn):
    """Decorator, which allows us to point to function names in YAML-files.
    Example: fingerprint: detect_general
    
    """
    yaml_fn_dict[fn.__name__] = fn
    return fn


def grep_from_file(version_file, regexp):
    """Grepping file with predefined regexp to find a version. This returns
    m.group from regexp: (?P<version>foo)
    
    """
    with open(version_file, 'r') as version_file:
        try:
            source = version_file.readlines()
        except UnicodeDecodeError:
            res = chardet.detect(open(version_file.name, 'rb').read())
            version_file = open(version_file.name, 'r', encoding=res['encoding'])
            source = version_file.readlines()
    prog = re.compile(regexp)

    for line in source:
        match = prog.match(line)
        try:
            found_match = match.group('version')
            return found_match
        except re.error:
            logging.error('Invalid regular expression: %s', regexp)
        except AttributeError:
            pass


@yaml_visible
def detect_general(source_file, regexp):
    """Detects from source file if it contains version information. Uses first
    regexp-match.
    
    """
    if not (os.path.isfile(source_file) and regexp):
        return
    return grep_from_file(source_file, regexp[0])


@yaml_visible
def detect_joomla(source_file, regexp):
    """Detects from source file if it contains version information of Joomla"""
    if not (os.path.isfile(source_file) and regexp):
        return
    logging.debug('Dectecting Joomla from: %s', source_file)
    release_version = grep_from_file(source_file, regexp[0])
    if not release_version:
        logging.debug('Could not find release version from: %s', source_file)
        return
    logging.debug('Release version: %s', release_version)
    dev_level_version = grep_from_file(source_file, regexp[1])
    if not dev_level_version:
        logging.debug('Could not find development version from: %s', source_file)
        return
    logging.debug('Development level version: %s', dev_level_version)
    return release_version + "." + dev_level_version


@yaml_visible
def detect_wikkawiki(source_file, regexp):
    """Detects from file if the file has version information of WikkaWiki.

    Wikka-1.3.2-p7/version.php:
    $svn_version = '1.3.2';
    if (!defined('WAKKA_VERSION')) define('WAKKA_VERSION', $svn_version);
    if(!defined('WIKKA_PATCH_LEVEL')) define('WIKKA_PATCH_LEVEL', '7');

    """
    if not (os.path.isfile(source_file) and regexp):
        return
    logging.debug('Dectecting WikkaWiki from: %s', source_file)
    version = grep_from_file(source_file, regexp[0])
    if not version:
        logging.debug('Could not find version from: %s', source_file)
        return
    logging.debug('Version: %s', version)
    patch_level = grep_from_file(source_file, regexp[1])
    if not patch_level:
        logging.debug('Could not find patch level from: %s', patch_level)
        return
    logging.debug('Patch level: %s', patch_level)
    if version and patch_level:
        return version + "-p" + patch_level


@yaml_visible
def detect_gallery(source_file, regexp):
    """Detects from source file if it contains version information of Gallery.
    Also ignores Git-versions.
    
    """
    if not (os.path.isfile(source_file) and regexp):
        return
    logging.debug('Dectecting Gallery from: %s', source_file)
    version = grep_from_file(source_file, regexp[0])
    if not version:
        logging.debug('Could not find version from: %s', source_file)
        return
    logging.debug('Gallery version %s %s' % (version, source_file))
    git_version = grep_from_file(source_file, 
    '.*?const.*?RELEASE_CHANNEL.*?(?P<version>(git))')
    if git_version:
        logging.debug('Not reporting Gallery Git-version %s', source_file)
        return
    else:
        return version


@yaml_visible
def detect_withoutnewlines(source_file, regexp):
    """Stripts newlines from source file."""
    if not (os.path.isfile(source_file) and regexp):
        return
    with open(source_file, 'r') as f:
        source = f.read().replace('\n', '')
    try:
        return re.compile(regexp[0]).match(source).group('version')
    except re.error:
        logging.error('Invalid regular expression: %s', regexp)
    except AttributeError:
        pass
