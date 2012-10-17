import os
import logging
import re

from helpers import return_func_name

yaml_fn_dict = {}

def yaml_visible(fn):
    """Decorator, which allows us to point to function names in YAML-files. Example: fingerprint: detect_general"""
    yaml_fn_dict[fn.func_name] = fn
    return fn


def grep_from_file(version_file, regexp):
    """Grepping file with predefined regexp to find a version. This returns m.group from regexp: (?P<version>foo)"""
    logger = logging.getLogger(return_func_name())
    version_file = open(version_file, 'r')
    source = version_file.readlines()
    version_file.close()
    prog = re.compile(regexp)

    for line in source:
        match = prog.match(line)
        try:
            found_match = match.group('version')
            return found_match
        except re.error:
            logger.error('Not a valid regular expression: %s' % regexp)
        except AttributeError:
            pass


@yaml_visible
def detect_general(source_file, regexp):
    """Detects from source file if it contains version information. Uses first regexp-match"""
    if not os.path.isfile(source_file):
        return
    if not regexp:
        return
    file_version = grep_from_file(source_file, regexp[0])
    return file_version


@yaml_visible
def detect_joomla(source_file, regexp):
    """Detects from source file if it contains version information of Joomla"""
    logger = logging.getLogger(return_func_name())
    if not os.path.isfile(source_file):
        return
    if not regexp:
        return
    logger.debug('Dectecting Joomla from: %s' % source_file)

    release_version = grep_from_file(source_file, regexp[0])
    if not release_version:
        logger.debug('Could not find release version from: %s' % source_file)
        return
    logger.debug('Release version: %s' % release_version)
    dev_level_version = grep_from_file(source_file, regexp[1])
    if not dev_level_version:
        logger.debug('Could not find development version from: %s' % source_file)
        return
    logger.debug('Development level version: %s' % dev_level_version)

    file_version = release_version + "." + dev_level_version
    return file_version


@yaml_visible
def detect_wikkawiki(source_file, regexp):
    """Detects from file if the file has version information of WikkaWiki.

    Wikka-1.3.2-p7/version.php:
    $svn_version = '1.3.2';
    if (!defined('WAKKA_VERSION')) define('WAKKA_VERSION', $svn_version);
    if(!defined('WIKKA_PATCH_LEVEL')) define('WIKKA_PATCH_LEVEL', '7');
    """
    logger = logging.getLogger(return_func_name())
    if not os.path.isfile(source_file):
        return
    if not regexp:
        return
    logger.debug('Dectecting WikkaWiki from: %s' % source_file)
    version = grep_from_file(source_file, regexp[0])
    if not version:
        logger.debug('Could not find version from: %s' % source_file)
        return
    logger.debug('Version: %s' % version)
    patch_level = grep_from_file(source_file, regexp[1])
    if not patch_level:
        logger.debug('Could not find patch level from: %s' % patch_level)
        return
    logger.debug('Patch level: %s' % patch_level)
    if version and patch_level:
        file_version = version + "-p" + patch_level
        return file_version
