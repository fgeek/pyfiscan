import os
import logging
import sys
import stat  # Interpreting the results of os.[stat,fstat,lstat]
import traceback


def filepaths_in_dir(directory, checkmodes):
    """Yields full to path files with validate_directory"""
    for root, dirs, files in os.walk(directory):
        dirs[:] = [os.path.join(root, d) for d in dirs]
        dirs[:] = [d for d in dirs if validate_directory(d, checkmodes)]
        for basename in files:
            yield os.path.join(root, basename)


def validate_directory(path, checkmodes):
    """Checks that path is a directory, not a symlink and that directory has
    execution bit
    
    """
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
        return check_dir_execution_bit(path)
    return True


def check_dir_execution_bit(path):
    """Check if path has execution bit to check if site is public. Defaults to
    false. False means no execution bit is set.
    
    """
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


def postprocess_php5fcgi(home_location, item_location):
    """Checks if installation directory contains php5.fcgi-file. In some
    environemnts this is used to tell web-server backends to execute PHP in the
    directory. Otherwise the server responds with 500 code and would lead to
    false positives.
    
    """
    # So that we always have start path, which we will delete because we don't
    # know if the hiararchy is bigger than x items in some environments
    if not home_location:
        home_location = '/home'
    # Removing start path
    public_dir = item_location[len(os.path.abspath(home_location)):].split('/')[:5]
    # Joining items together to get real path
    public_dir = '/'.join(str(elem) for elem in public_dir)
    public_dir = os.path.abspath(home_location + public_dir)
    if os.path.exists(os.path.abspath(public_dir + '/php5.fcgi')):
        return True
    else:
        return False
