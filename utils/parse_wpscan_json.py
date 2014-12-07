#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This tool migrates WPScan plugin vulnerability database to pyfiscan from JSON to
YML. Only vulnerabilities with fixed-in version are processed.

TODO:
- Add all references to "cve", which should be renamed in pyfiscan.

@author Henri Salo <henri@nerv.fi>
@copyright Copyright (c) 2014 Henri Salo
@license BSD
"""

import json

vuln_values = [
    'created_at',
    'cve',
    'exploitdb',
    'fixed_in',
    'id',
    'metasploit',
    'osvdb',
    'secunia',
    'title',
    'updated_at',
    'url',
    'vuln_type'
    ]

with open('plugin_vulns.json', 'r') as plugin_vulns_file:
    for plugin in json.loads(plugin_vulns_file.read()):
        for plugin_name, plugin_vulns in plugin.items():
            vuln_count = 0
            for vuln in plugin_vulns.get('vulnerabilities'):
                if vuln.get('fixed_in'):
                    vuln_count += 1
                    print('WordPress plugin %s:' % plugin_name)
                    print('  %d:' % vuln_count)
                    print("    location: ['/wp-content/plugins/%s/readme.txt']" % plugin_name)
                    print("    secure_version: '%s'" % vuln.get('fixed_in'))
                    print("    regexp: ['Stable tag: (?P<version>[0-9.]+)']")
                    cve = vuln.get('cve')
                    if cve is not None:
                        print("    cve: 'CVE-%s'" % cve[0])
                    else:
                        print("    cve: 'TODO'")
                    print("    fingerprint: detect_general")
                    print("    post_processing: ['php5.fcgi']")
