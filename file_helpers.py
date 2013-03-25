import os
import logging
import sys
import stat  # Interpreting the results of os.[stat,fstat,lstat]
import traceback


def filepaths_in_dir(directory):
    return (os.path.join(root, basename) for root, dirs, files in os.walk(directory) for basename in files)


def validate_directory(path, checkmodes):
    """Checks that path is a directory, not a symlink and that directory has execution bit"""
    if not type(path) == str:
        logging.debug('got path which is not a string. Exiting..')
        sys.exit('Function validate_directory got path which is not a string.')
    if not os.path.isdir(path):
        logging.debug('Returning false in validate_directory/os.path.isdir for directory: %s' % path)
        return False
    if os.path.islink(path):
        logging.debug('Returning false in validate_directory/os.path.islink for directory: %s' % path)
        return False
    if checkmodes:
        return check_dir_execution_bit(path, checkmodes)
    return True


def check_dir_execution_bit(path, checkmodes):
    """Check if path has execution bit to check if site is public.
    Defaults to false. False means no execution bit is set."""
    try:
        if not os.path.isdir(path):
            logging.debug('Returning false in check_dir_execution_bit/os.path.isdir for directory: %s' % path)
            return False
        # http://docs.python.org/library/stat.html#stat.S_IXOTH
        if stat.S_IXOTH & os.stat(path)[stat.ST_MODE]:
            logging.debug('Returning true in check_dir_execution_bit/stat for directory: %s' % path)
            return True
        else:
            logging.debug('Returning false in check_dir_execution_bit/stat for directory: %s' % path)
            return False
    except Exception:
        logging.error(traceback.format_exc())
