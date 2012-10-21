import os
import logging
import sys
import stat  # Interpreting the results of os.[stat,fstat,lstat]
import traceback

def filepaths_in_dir(directory):
    return (os.path.join(root, basename) for root, dirs, files in os.walk(directory) for basename in files)

def validate_directory(path, checkmodes):
    """Check if path is directory and it is not a symlink"""
    if not type(path) == str:
        logging.debug('got path which was not a string. Exiting..')
        sys.exit('validate_directory got path which was not a string')
    if not os.path.isdir(path):
        return False
    if os.path.islink(path):
        return False
    if not check_dir_execution_bit(path, checkmodes):
        return False
    return True


def check_dir_execution_bit(path, checkmodes):
    """Check if path has execution bit to check if site is public.
    Defaults to false. False means no execution bit is set."""
    try:
        if checkmodes == None:
            return True
        if not os.path.exists(path):
            return
        if not os.path.isdir(path):
            return
        # http://docs.python.org/library/stat.html#stat.S_IXOTH
        if stat.S_IXOTH & os.stat(path)[stat.ST_MODE]:
            return True
        else:
            return False
    except Exception:
        logging.error(traceback.format_exc())

