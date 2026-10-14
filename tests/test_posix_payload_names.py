"""Literal POSIX names survive verified export and offline staging."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from zog.host_install import InstallError
from zog.host_install.artifact import extract, stage, verify_tree


class PosixPayloadNames(unittest.TestCase):
    def test_real_export_staging_preserves_literal_names(self):
        try:
            from zog.image_build import ImageBuild
            from zog.image_build.host_export import export
        except ImportError:
            self.skipTest('reviewed image-build source required')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base/'root'
            unit = r'usr/lib/systemd/system/system-systemd\x2dmute\x2dconsole.slice'
            (root/unit).parent.mkdir(parents=True)
            (root/unit).write_bytes(b'original test fixture\n')
            literal = r'usr/lib/systemd/system/..\literal'
            (root/literal).write_bytes(b'not traversal\n')
            link = r'usr/lib/systemd/system/alias\x2dunit.slice'
            (root/link).symlink_to(Path(unit).name)
            builder = ImageBuild(package_dir=base/'recipes', state_dir=base/'state')
            generation = builder.import_bootstrap(root, {'fixture': True})
            manifest = export(generation.root.parent, base/'bundle', {'packages': [], 'acceptance': []})
            result = stage(base/'bundle', manifest['artifact_id'], base/'staged')
            self.assertEqual(result['status'], 'staged-for-offline-tests')
            self.assertFalse(result['installable'])
            self.assertFalse(result['device_writes_enabled'])
            self.assertEqual((base/'staged/rootfs'/unit).read_bytes(), b'original test fixture\n')
            self.assertEqual((base/'staged/rootfs'/literal).read_bytes(), b'not traversal\n')
            self.assertEqual((base/'staged/rootfs'/link).readlink(), Path(Path(unit).name))
            self.assertFalse((base/'staged/rootfs'/unit.replace(r'\x2d', '-')).exists())
            verify_tree(base/'bundle/rootfs.tar', base/'staged/rootfs')

    def test_unsafe_paths_rejected_before_writes(self):
        attacks = ['.', '../outside', '/outside', r'a\name/../outside',
                   'a/./b', 'a//b']
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in attacks:
                with self.subTest(name=name):
                    with tarfile.open(base/'bad.tar', 'w', format=tarfile.USTAR_FORMAT) as archive:
                        member = tarfile.TarInfo(name)
                        member.size = 1
                        archive.addfile(member, io.BytesIO(b'x'))
                    with self.assertRaises(InstallError):
                        extract(base/'bad.tar', base/'out', 1024)
                    self.assertFalse((base/'out').exists())

    def test_literal_symlink_parent_and_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for attack in ('duplicate', 'symlink-parent'):
                with self.subTest(attack=attack):
                    with tarfile.open(base/'bad.tar', 'w', format=tarfile.USTAR_FORMAT) as archive:
                        member = tarfile.TarInfo(r'name\x2descape')
                        if attack == 'symlink-parent':
                            member.type = tarfile.SYMTYPE
                            member.linkname = '/tmp'
                        archive.addfile(member)
                        archive.addfile(member if attack == 'duplicate' else
                                        tarfile.TarInfo(member.name+'/outside'))
                    with self.assertRaises(InstallError):
                        extract(base/'bad.tar', base/'out', 1024)
                    self.assertFalse((base/'out').exists())
