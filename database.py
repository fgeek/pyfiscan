# -*- coding: utf-8 -*-

import yaml
import os
import os.path
import sys

class Database():
    def __init__(self, yamldir):
        self.data = self.generate(yamldir)

    def gen_yamlfile_locations(self, yamldir):
        if os.path.islink(yamldir):
            # TODO: logging
            sys.exit('Location for YAML-files can not be a symlink: %s' % yamldir)
        if not os.path.isdir(yamldir):
            # TODO: logging
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
        data = {}
        for file in self.gen_yamlfile_locations(yamldir):
            try:
                result = yaml.safe_load(file.read())
                data = dict(data.items() + result.items())
            except yaml.scanner.ScannerError, e:
                print('Error while loading YAML-file: %s' % filename)
        return data

    def locations(self, application, with_lists=True):
        """Returns list of locations by appname."""
        locations = []
        for (appname, issues) in self.data.iteritems():
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
