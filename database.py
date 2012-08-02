# -*- coding: utf-8 -*-

try:
    import sys
    import os
    import yaml
except ImportError, error:
    print('Import error: %s' % error)
    sys.exit(1)


class Database:
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

    def locations(self, data, application, with_lists=True):
        """Returns list of locations by appname."""
        locations = []
        for (appname, issues) in data.iteritems():
            if not appname == application:
                continue
            for issue in issues.iteritems():
                if with_lists is True:
                    locations.append(issue[1]['location'])
                else:
                    if type(issue[1]['location']) == str:
                        locations.append(issue[1]['location'])
                    if type(issue[1]['location']) == list:
                        i = 0
                        while i < len(issue[1]['location']):
                            locations.append(issue[1]['location'][i])
                            i += 1
        return locations
