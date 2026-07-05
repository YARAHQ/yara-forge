"""
Tests for hash meta data alignment in rule processing.
"""
import unittest

from main.rule_processors import align_yara_rule_hashes


class TestAlignYaraRuleHashes(unittest.TestCase):
    """
    Test that align_yara_rule_hashes normalizes the many hash key variants
    documented in https://github.com/YARAHQ/yara-forge/issues/74 to 'hash'.
    """

    def test_indexed_and_patterned_hash_keys_are_aligned(self):
        """
        Indexed hash keys (hash1, hash_1, md5_1, sha256_1, hash1_sha256, ...) and
        other documented variants should all collapse to the 'hash' key.
        """
        rule_meta_data = [
            {'Hash1': 'aaaa000000000000000000000000000000000000000000000000000000000001'},
            {'hash_1': 'aaaa000000000000000000000000000000000000000000000000000000000002'},
            {'MD5_1': 'aaaa000000000000000000000000000000000000000000000000000000000003'},
            {'SHA256_1': 'aaaa000000000000000000000000000000000000000000000000000000000004'},
            {'hash1_sha256': 'aaaa000000000000000000000000000000000000000000000000000000000005'},
            {'thumbprint2': 'aaaa000000000000000000000000000000000000000000000000000000000006'},
            {'sample_md5': 'aaaa000000000000000000000000000000000000000000000000000000000007'},
            {'parent_hash': 'aaaa000000000000000000000000000000000000000000000000000000000008'},
            {'description': 'not a hash, should be left alone'},
        ]

        result = align_yara_rule_hashes(rule_meta_data)

        hash_values = [list(m.values())[0] for m in result if 'hash' in m]
        self.assertEqual(len(hash_values), 8)
        self.assertIn('description', [k for m in result for k in m if k != 'hash'])

    def test_internal_and_provenance_hash_fields_are_left_alone(self):
        """
        Fields that look hash-adjacent but aren't a raw sample hash value
        (an internal dedup key or a third-party reference field) must not
        be swept into 'hash'.
        """
        rule_meta_data = [
            {'logic_hash': 'internal-dedup-key'},
            {'malpedia_hash': 'some-upstream-reference'},
            {'hash': 'aaaa000000000000000000000000000000000000000000000000000000000009'},
        ]

        result = align_yara_rule_hashes(rule_meta_data)

        keys = [k for m in result for k in m]
        self.assertIn('logic_hash', keys)
        self.assertIn('malpedia_hash', keys)
        self.assertEqual(keys.count('hash'), 1)


if __name__ == '__main__':
    unittest.main()
