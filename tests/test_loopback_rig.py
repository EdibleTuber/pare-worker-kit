"""Smoke tests for the loopback rig that carries the drive-state tests.

The spec (§8) is explicit that the rig is a loopback filesystem, not a
temp directory: you cannot produce ENOSPC, EROFS, or an unmounted root on
a tmpdir, and a mocked ENOSPC proves nothing about whether the temporary
survives -- which is the entire assertion. The rig therefore does the
real thing (truncate, losetup, mkfs.ext4, mount at a fixed path), and
these four smoke tests pin the rig's own contract before the walk's
suite is built on it:

S1 -- the mounted rw state yields a writable ext4 root, and
      free_bytes() reports a plausible amount of free space;
S2 -- remount-ro makes the root refuse a write with a genuine EROFS
      (asserted by errno, never by message), and remount-rw restores
      writing;
S3 -- the unmounted state is an empty ordinary directory at the same
      fixed path -- no mount, no sentinel, the fstab-nofail boot state;
S4 -- teardown leaves no loop device attached to the image and removes
      the image, on a clean exit, on an exception in the body, and on a
      double close.

Nothing in this module -- and nothing anywhere in tests/ -- carries a
skip marker for a rig that cannot be built. That absence is the
fail-loud contract (spec §8, plan constraint 5): a rig that cannot be
built must fail the suite, not skip it, or every drive-state test that
follows would hollow out silently.
"""
from __future__ import annotations

import errno
import os

import pytest

from loopback_rig import IMAGE_PATH, LoopbackDrive, attached_devices_for_image

#: A small image is a legitimate state of the rig, not a degenerate one
#: (R3): 8 MiB of ext4 yields ~3.5 MiB usable, plenty for a smoke test,
#: and keeps these four fast. The ENOSPC test in the walk's suite uses
#: the 64 MiB default for the reason R13 gives.
SMALL_IMAGE_BYTES = 8 * 1024 * 1024


def test_s1_the_mounted_rw_root_is_writable_and_reports_free_space():
    with LoopbackDrive(size=SMALL_IMAGE_BYTES) as drive:
        root = drive.root
        # The rig promises a mounted drive: the fixed path is a mountpoint
        # while the rig is open. This is what separates S1's state from
        # S3's, and a rig that "mounts" an ordinary directory would pass
        # the write below and fail every real drive-state test later.
        assert os.path.ismount(root), "the rig promises a mounted drive"
        probe = os.path.join(root, "rig-smoke")
        with open(probe, "wb") as handle:
            handle.write(b"the rig writes")
        with open(probe, "rb") as handle:
            assert handle.read() == b"the rig writes"
        os.remove(probe)
        # free_bytes is the R13 expression (statvfs f_bavail * f_frsize),
        # the same expression the walk's step 3 will use: on a fresh
        # image it is positive, and it cannot exceed the image size.
        assert 0 < drive.free_bytes() < SMALL_IMAGE_BYTES


def test_s2_remount_ro_refuses_writes_with_erofs_and_remount_rw_restores():
    with LoopbackDrive(size=SMALL_IMAGE_BYTES) as drive:
        drive.remount_ro()
        probe = os.path.join(drive.root, "must-not-exist")
        with pytest.raises(OSError) as excinfo:
            with open(probe, "wb"):
                pass
        # Assert the errno, not the message (the plan is explicit): an
        # EACCES here would mean the rig's chown leg is broken, and the
        # walk's EROFS test would then discriminate permission-denied
        # from read-only -- exactly the misnaming R4's chown exists to
        # prevent.
        assert excinfo.value.errno == errno.EROFS
        assert not os.path.exists(probe)
        # The state operations are symmetric: remount-rw makes the root
        # writable again, so S2 exercises both of them.
        drive.remount_rw()
        with open(probe, "wb") as handle:
            handle.write(b"back to read-write")
        os.remove(probe)


def test_s3_the_unmounted_state_is_an_empty_ordinary_directory():
    with LoopbackDrive(size=SMALL_IMAGE_BYTES, mounted=False) as drive:
        root = drive.root
        assert os.path.isdir(root)
        assert not os.path.ismount(root), "the unmounted state is not a mount"
        # No sentinel, no residue: an empty ordinary directory at the
        # fixed path -- the exact state of an fstab-nofail boot with the
        # drive unplugged, which the spec names as the likeliest real
        # bench failure.
        assert os.listdir(root) == []


def test_s4_clean_teardown_leaves_no_device_and_removes_the_image():
    before = attached_devices_for_image()
    with LoopbackDrive(size=SMALL_IMAGE_BYTES) as drive:
        # Non-vacuity: the rig actually attached a device while open.
        # Without this check, the before/after diff below would pass
        # forever for a rig that never attached anything.
        assert len(attached_devices_for_image()) == len(before) + 1
        assert drive.root  # the yielded drive knows its root
    assert attached_devices_for_image() == before
    assert not os.path.exists(IMAGE_PATH)


def test_s4_teardown_on_an_exception_in_the_body():
    before = attached_devices_for_image()
    with pytest.raises(RuntimeError, match="rig smoke"):
        with LoopbackDrive(size=SMALL_IMAGE_BYTES):
            raise RuntimeError("rig smoke: exception in the body")
    assert attached_devices_for_image() == before
    assert not os.path.exists(IMAGE_PATH)


def test_s4_a_double_close_is_a_no_op_that_stays_clean():
    before = attached_devices_for_image()
    with LoopbackDrive(size=SMALL_IMAGE_BYTES) as drive:
        pass
    drive.close()  # the context manager already closed the rig
    drive.close()  # ...a second and third close must be no-ops, not errors
    assert attached_devices_for_image() == before
    assert not os.path.exists(IMAGE_PATH)
