import unittest
from pyfiscan import is_not_secure
from database import Database

class CompareVersions(unittest.TestCase):
    """Testing that comparison of version numbers are correct."""
    def test_version_pairs_1(self):
        self.assertTrue(is_not_secure('2.1', '2.0.2'))

    def test_version_pairs_2(self):
        self.assertTrue(is_not_secure('2.0.1', '2.0'))

    def test_version_pairs_3(self):
        self.assertTrue(is_not_secure('2.0.1', '2.0.0'))

    def test_version_pairs_4(self):
        self.assertFalse(is_not_secure('2.0.2', '2.0.2'))

    def test_version_pairs_5(self):
        self.assertFalse(is_not_secure('2.0.1', '2.0.2'))

    def test_version_pairs_6(self):
        self.assertFalse(is_not_secure('2.0', '2.0.2'))

    def test_version_pairs_7(self):
        self.assertTrue(is_not_secure('2.0', '1.9.9'))


class DatabaseHandlers(unittest.TestCase):
    def test_can_load_issues_from_yaml(self):
        """Can load fingerprint data from YAML files."""
        database = Database('yamls/')
        if len(database.issues) == 0:
            self.assertEqual(1, 0, 'Empty database.')
        self.assertTrue(isinstance(database, Database))

if __name__ == '__main__':
    suite1 = unittest.TestLoader().loadTestsFromTestCase(CompareVersions)
    suite2 = unittest.TestLoader().loadTestsFromTestCase(DatabaseHandlers)
    alltests = unittest.TestSuite([suite1, suite2])
    unittest.TextTestRunner(verbosity=2).run(alltests)
