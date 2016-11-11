import sys
import os
import re
import unittest
from pyfiscan import is_not_secure
from database import Database

class CompareVersions(unittest.TestCase):
    def test_version_comparison(self):
        """Version comparison."""
        self.assertTrue(is_not_secure('2.1', '2.0.2'))
        self.assertTrue(is_not_secure('2.0.1', '2.0'))
        self.assertTrue(is_not_secure('2.0.1', '2.0.0'))
        self.assertFalse(is_not_secure('2.0.2', '2.0.2'))
        self.assertFalse(is_not_secure('2.0.1', '2.0.2'))
        self.assertFalse(is_not_secure('2.0', '2.0.2'))
        self.assertTrue(is_not_secure('2.0', '1.9.9'))
        self.assertTrue(is_not_secure('2015.0514', '2015.0426'))
        self.assertTrue(is_not_secure('1.06', '1.05'))
        self.assertTrue(is_not_secure('1.10', '1.06'))


class DatabaseHandlers(unittest.TestCase):
    def test_load_database(self):
        """Loads fingerprint data from YAML files."""
        database = Database('yamls/')
        if len(database.issues) == 0:
            self.assertEqual(1, 0, 'Empty database.')
        self.assertTrue(isinstance(database, Database))


class UnwantedStrings(unittest.TestCase):
    def test_search_unwanted_strings(self):
        """No unwanted strings in files."""
        for root, dirs, filenames in os.walk('.'):
            for f in filenames:
                    filepath = os.path.join(root, f)
                    if filepath.endswith('.pyc'):
                        continue
                    file = open(filepath, 'r')
                    for line in file:
                        if re.match('osvdb', line):
                            self.fail('OSVDB string found from: %s' % filepath)


if __name__ == '__main__':
    suite1 = unittest.TestLoader().loadTestsFromTestCase(CompareVersions)
    suite2 = unittest.TestLoader().loadTestsFromTestCase(DatabaseHandlers)
    suite3 = unittest.TestLoader().loadTestsFromTestCase(UnwantedStrings)
    alltests = unittest.TestSuite([suite1, suite2, suite3])
    unittest.TextTestRunner(verbosity=2).run(alltests)
