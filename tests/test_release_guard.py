"""Standard-library tests for release integrity and tampering."""
import json
import tempfile
import unittest
from pathlib import Path

from sentinelforge.release_guard import FILES, MANIFEST, create_manifest, verify_manifest, main


class ReleaseGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        for i, name in enumerate(FILES):
            (self.folder / name).write_bytes((b'fixture-binary-%d' % i) * 10)

    def test_valid_manifest(self):
        manifest = create_manifest(self.folder)
        verify_manifest(self.folder, manifest)
        self.assertEqual(set(manifest['artifacts']), set(FILES))

    def test_tampered_binary_is_rejected(self):
        manifest = create_manifest(self.folder)
        (self.folder / FILES[0]).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'Integrity failure'):
            verify_manifest(self.folder, manifest)

    def test_missing_binary_rejected(self):
        manifest = create_manifest(self.folder)
        (self.folder / FILES[1]).unlink()
        with self.assertRaises(ValueError):
            verify_manifest(self.folder, manifest)

    def test_manifest_cannot_add_or_remove_artifacts(self):
        manifest = create_manifest(self.folder)
        manifest['artifacts']['bonus.exe'] = manifest['artifacts'][FILES[0]]
        with self.assertRaisesRegex(ValueError, 'Unexpected artifact set'):
            verify_manifest(self.folder, manifest)

    def test_bad_hash_rejected(self):
        manifest = create_manifest(self.folder)
        manifest['artifacts'][FILES[0]]['sha256'] = 'g' * 64
        with self.assertRaises(ValueError):
            verify_manifest(self.folder, manifest)

    def test_boolean_size_rejected(self):
        manifest = create_manifest(self.folder)
        manifest['artifacts'][FILES[0]]['size'] = True
        with self.assertRaises(ValueError):
            verify_manifest(self.folder, manifest)

    def test_create_verify_cli(self):
        self.assertEqual(main(['create', '--folder', str(self.folder)]), 0)
        self.assertTrue((self.folder / MANIFEST).is_file())
        self.assertEqual(main(['verify', '--folder', str(self.folder)]), 0)

    def test_invalid_json_cli_fails(self):
        (self.folder / MANIFEST).write_text('{', encoding='utf-8')
        self.assertEqual(main(['verify', '--folder', str(self.folder)]), 2)

    def test_symlink_binary_rejected(self):
        binary = self.folder / FILES[0]
        binary.unlink()
        try:
            binary.symlink_to(self.folder / FILES[1])
        except (NotImplementedError, OSError):
            self.skipTest('Symlink creation unavailable')
        with self.assertRaises(ValueError):
            create_manifest(self.folder)


if __name__ == '__main__':
    unittest.main()
