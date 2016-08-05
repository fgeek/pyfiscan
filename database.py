# -*- coding: utf-8 -*-

"""Provides interface for pyfiscan to YAML-files."""

try:
    import os
    import scandir
    import sys
    import yaml
except ImportError, error:
    print('Import error: %s' % error)
    sys.exit(1)


def gen_yamlfile_locations(yamldir, includes):
    """File handle generator for YAML-files. Only used by database class."""
    if os.path.islink(yamldir):
        sys.exit('Location for YAML-files can not be a symlink: %s' % yamldir)
    if not os.path.isdir(yamldir):
        sys.exit('Location for YAML-files is not a directory: %s' % yamldir)
    for filename in scandir.scandir(yamldir):
        filename = filename.name
        if filename.startswith('.'):  # skip Vim swap files
            continue
        if os.path.islink(yamldir + filename):
            continue
        if not os.path.isfile(yamldir + filename):
            continue
        if not includes:
            yield open(yamldir + filename, 'r')
        else:
            for item in includes:
                if filename == item + '.yml':
                    yield open(yamldir + filename, 'r')


def generate(yamldir, includes):
    """Generates data dictionary of definitions from YAML files. Only used by
    database class.
    
    """
    data = {}
    for yamlfile in gen_yamlfile_locations(yamldir, includes):
        try:
            result = yaml.safe_load(yamlfile.read())
            data = dict(data.items() + result.items())
            yamlfile.close()
        except AttributeError:  # empty file
            print('No data found inside: %s' % yamlfile)
        except yaml.scanner.ScannerError, e:  # syntax error
            sys.exit('Error while loading YAML-file: %s' % e)
    return data


class Database:
    """Reads YAML files and generates a data dictionary of the contents"""
    def __init__(self, yamldir, includes=None):
        self.issues = generate(yamldir, includes)

    def locations(self, application, with_lists=True):
        """Returns list of locations by appname."""
        locations = []
        for issue in self.issues[application].itervalues():
            location = issue['location']
            if with_lists is True:
                locations.append(location)
            else:
                if type(location) == str:
                    locations.append(location)
                elif type(location) == list:
                    locations.extend(location)
        return locations
