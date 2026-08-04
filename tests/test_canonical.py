from __future__ import annotations

import unittest

from fl_forensics.canonical import CanonicalizationError, canonical_json_bytes, digest_object


class CanonicalTests(unittest.TestCase):
    def test_key_order_does_not_change_digest(self) -> None:
        left = {"b": 2, "a": [True, None, "è"]}
        right = {"a": [True, None, "è"], "b": 2}
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))
        self.assertEqual(digest_object(left), digest_object(right))

    def test_signed_manifest_profile_rejects_float(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({"metric": 0.1})


if __name__ == "__main__":
    unittest.main()

