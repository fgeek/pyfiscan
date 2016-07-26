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


class DatabaseHandlers(unittest.TestCase):
    def test_load_database(self):
        """Loads fingerprint data from YAML files."""
        database = Database('yamls/')
        if len(database.issues) == 0:
            self.assertEqual(1, 0, 'Empty database.')
        self.assertTrue(isinstance(database, Database))

if __name__ == '__main__':
    suite1 = unittest.TestLoader().loadTestsFromTestCase(CompareVersions)
    suite2 = unittest.TestLoader().loadTestsFromTestCase(DatabaseHandlers)
    alltests = unittest.TestSuite([suite1, suite2])
    unittest.TextTestRunner(verbosity=2).run(alltests)
