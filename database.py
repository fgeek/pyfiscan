# -*- coding: utf-8 -*-

# TODO: http://docs.python.org/library/glob.html

try:
    import sys
    import os
    import yaml
except ImportError, error:
    print('Import error: %s' % error)
    sys.exit(1)


class Database:

    def __init__(self, yamldir):
        self.issues = self.generate(yamldir)

    """Reads YAML files and generates a data dictionary of the contents"""
    def gen_yamlfile_locations(self, yamldir):
        """File handle generator for YAML-files"""
        if os.path.islink(yamldir):
            sys.exit('Location for YAML-files can not be a symlink: %s' % yamldir)
        if not os.path.isdir(yamldir):
            sys.exit('Location for YAML-files is not a directory: %s' % yamldir)
        for filename in os.listdir(yamldir):
            if not filename.endswith('.yaml'):
                continue
            if os.path.islink(yamldir + filename):
                continue
            if not os.path.isfile(yamldir + filename):
                continue 
            file = open(yamldir + filename, 'r')
            yield file

    def generate(self, yamldir):
        """Generates data dictionary of definitions from YAML files"""
        data = {}
        for file in self.gen_yamlfile_locations(yamldir):
            try:
                result = yaml.safe_load(file.read())
                data = dict(data.items() + result.items())
            except AttributeError, e:  # empty file
                print('No data found inside: %s' % file)
            except yaml.scanner.ScannerError, e:  # syntax error
                print('Error while loading YAML-file: %s' % file)
        return data

    def locations(self, application, with_lists=True):
        """Returns list of locations by appname."""
        locations = []
        for issue_id, issue in self.issues[application].iteritems():
            if with_lists is True:
                locations.append(issue['location'])
            else:
                if type(issue['location']) == str:
                    locations.append(issue['location'])
                if type(issue['location']) == list:
                    i = 0
                    while i < len(issue['location']):
                        locations.append(issue['location'][i])
                        i += 1
        return locations
