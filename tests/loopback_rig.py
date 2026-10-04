"""The loopback rig: a real filesystem the drive-state tests run against.

The spec (§8) is explicit that the rig is a loopback filesystem, not a
temp directory: you cannot produce ENOSPC, EROFS, or an unmounted root
on a tmpdir, and a mocked ENOSPC proves nothing about whether the
temporary survives -- which is the entire assertion. So this module does
the real thing: truncate an image, attach it to a free loop device,
format it ext4, and mount it at a fixed path.

The rig is test support, deliberately private to tests/ (R1): the wheel
packages src/pare_worker_kit only, so nothing in this module ships, and
a rig is scaffolding, not a dependency of the kit.

Fixed paths (R3). The image and the mountpoint are fixed because the
mountpoint is pinned by agenthost's scoped sudoers entry, and CI's
passwordless sudo accepts the same paths. Every drive state -- mounted
read-write, read-only, unmounted -- is this same path in a different
condition. The image size is a parameter (default 64 MiB, the parent
spec's §14); a small image is a legitimate state of the rig, not a
degenerate one.

Privilege (R2). Every privileged command is tried as-is first and
retried under `sudo -n` on failure; if both legs fail the rig raises
RigUnavailable naming the operation and both errors. Under the local
`sg disk` wrapper the as-is leg carries losetup and mkfs.ext4 and the
`sudo -n` leg carries mount, remount and chown (the five commands
/etc/sudoers.d/pare-rig allows without a password); on CI the as-is leg
fails and `sudo -n` carries everything. One helper code path, both
environments, no environment sniffing. The mount/umount/chown argvs use
the absolute paths and option forms the scoped sudoers entry admits; the
preflight probe chain ran each one against the installed entry before
this file was written.

After every mount, the mount root is chowned to the running uid:gid
(R4), computed dynamically. A fresh ext4 root is root:root 0755; without
the chown the test process gets EACCES everywhere, *including on
read-only mounts*, where the EROFS test would then see "permission
denied" instead of read-only and the whole discrimination would be
void.

Teardown (S4). umount, detach, remove the image -- each step guarded by
its own state flag, so close() is idempotent: a clean exit, an
exception in the body, and a double close all leave zero loop devices
attached to the image. A failure halfway through teardown raises
RigUnavailable and leaves the steps already done done -- a later
close() resumes from where it stopped rather than re-doing them.

RigUnavailable is a loud failure, not a skip (spec §8, plan constraint
5). There is no skip marker anywhere in tests/ for this rig; a rig that
cannot be built must fail the suite so the absence is visible.
"""
from __future__ import annotations

import os
import pwd
import subprocess

#: The rig image. Fixed (R3): CI's passwordless sudo and agenthost's
#: scoped sudoers entry both assume the rig lives at these paths.
IMAGE_PATH = "/tmp/opencode/rig/disk.img"

#: The fixed mountpoint, pinned by the same sudoers entry. The rig
#: yields this path (as ``root``) in whatever state it was entered in.
MOUNT_POINT = "/tmp/opencode/rig/mnt"

#: Default image size: 64 MiB (the parent spec's §14). A fresh ext4
#: image of this size holds roughly 58 MiB; the ENOSPC test (R13) fills
#: exactly what the rig reports as free, on purpose.
DEFAULT_IMAGE_BYTES = 64 * 1024 * 1024


class RigUnavailable(Exception):
    """The rig cannot be built or torn down.

    A loud failure by design (spec §8, plan constraint 5): there is no
    skip mode for a rig that cannot be built, so this is what a test
    that needs the rig sees instead of a skip marker. The message names
    the operation and both errors -- the as-is leg and the `sudo -n`
    leg -- so the operator can tell which privilege the rig is missing
    without re-running it.
    """


def _one_line(text: str) -> str:
    """Collapse a captured stream to one line for an error message."""
    return " ".join(text.split())


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    """Run a command, capturing its output.

    Plain subprocess, no privilege logic here: the privilege policy
    (as-is, then `sudo -n`) is _run_privileged's, and keeping the two
    separate is what makes the as-is leg do the as-is thing.
    """
    return subprocess.run(argv, capture_output=True, text=True)


def _run_privileged(
    operation: str, argv: list[str]
) -> subprocess.CompletedProcess:
    """R2's privilege policy: as-is first, `sudo -n` on failure, else
    RigUnavailable naming the operation and both errors.

    The as-is leg carries what the current user and groups can do
    (under `sg disk`, that includes losetup and mkfs.ext4); the `sudo
    -n` leg carries what needs root (mount, remount, umount, chown --
    the scoped entries locally; everything, passwordless, on CI).
    `sudo -n` never prompts: a NOPASSWD miss is an immediate
    failure, which is exactly the loud behaviour the rig wants.
    """
    direct = _run(argv)
    if direct.returncode == 0:
        return direct
    elevated = _run(["sudo", "-n", *argv])
    if elevated.returncode == 0:
        return elevated
    raise RigUnavailable(
        f"rig operation {operation!r} failed on both privilege legs -- "
        f"as-is rc={direct.returncode} "
        f"({_one_line(direct.stderr) or _one_line(direct.stdout)}); "
        f"sudo -n rc={elevated.returncode} "
        f"({_one_line(elevated.stderr) or _one_line(elevated.stdout)})"
    )


def attached_devices_for_image() -> list[str]:
    """The `losetup -a` lines that mention the rig image.

    The S4 tests diff this before and after a rig's life: teardown is
    proven by the diff, and the mid-life check (exactly one more line
    while the rig is open) is what keeps the diff from passing
    vacuously for a rig that never attached anything.
    """
    result = _run(["losetup", "-a"])
    return [
        line for line in result.stdout.splitlines() if IMAGE_PATH in line
    ]


class LoopbackDrive:
    """A loopback ext4 drive in one of three states, as a context manager.

    Entered mounted (the default), the rig truncates the image at the
    requested size, attaches it to a free loop device, formats it ext4,
    mounts it at MOUNT_POINT, and chowns the root to the running
    uid:gid. Entered unmounted (``mounted=False``), it creates the image
    but does not attach or mount it: the fixed path then sits as an
    empty ordinary directory, the exact state of an fstab-nofail boot
    with the drive unplugged (R15) -- the likeliest real bench failure.

    The context manager yields the drive itself; its ``root`` is the
    fixed mountpoint path, in the state the rig was entered in. The
    state operations the suite needs are methods: ``remount_ro()`` and
    ``remount_rw()`` (S2), and ``free_bytes()`` -- R13's expression,
    ``statvfs f_bavail * f_frsize``, the same expression the walk's
    step 3 will use, so the rig and the walk agree on "free".
    """

    def __init__(
        self,
        size: int = DEFAULT_IMAGE_BYTES,
        mounted: bool = True,
    ) -> None:
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError(f"rig image size must be a positive int, got {size!r}")
        self._size = size
        self._mounted_state = mounted
        self._mounted = False  # is the mountpoint currently mounted
        self._loop: str | None = None  # the loop device, None once detached

    @property
    def root(self) -> str:
        """The drive root: the fixed mountpoint path, in the state the
        rig was entered in (a mounted ext4, or an empty ordinary
        directory when entered unmounted)."""
        return MOUNT_POINT

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> "LoopbackDrive":
        if self._loop is not None or self._mounted:
            raise RuntimeError(
                "rig already entered: close() it before entering it again")
        try:
            os.makedirs(os.path.dirname(IMAGE_PATH), exist_ok=True)
            os.makedirs(MOUNT_POINT, exist_ok=True)
            if attached_devices_for_image():
                # The image is attached to a device this rig does not
                # own. Truncating under a live device would corrupt it,
                # and detaching a foreign device is a side effect beyond
                # the rig's authority (the operator may be mid-probe).
                # Refuse loudly, and say exactly what to do about it.
                raise RigUnavailable(
                    f"{IMAGE_PATH} is already attached to a loop device "
                    f"({attached_devices_for_image()[0]}); detach it "
                    "(losetup -d) before running the rig again")
            # Truncate the image: unprivileged (the image is ours, in
            # /tmp), so it does not go through the privilege helper.
            with open(IMAGE_PATH, "wb") as image:
                image.truncate(self._size)
            if self._mounted_state:
                attached = _run_privileged(
                    "attach the image to a free loop device",
                    ["losetup", "-f", "--show", IMAGE_PATH])
                self._loop = attached.stdout.strip()
                _run_privileged(
                    "format the loop device as ext4",
                    ["mkfs.ext4", "-q", self._loop])
                _run_privileged(
                    "mount the loop device at the fixed mountpoint",
                    ["/usr/bin/mount", "-t", "ext4", self._loop,
                     MOUNT_POINT])
                self._mounted = True
                # R4: a fresh ext4 root is root:root 0755. Chown it to
                # the running user, or the EROFS test would see EACCES
                # instead of EROFS. The uid is the real uid; the gid is
                # the user's PRIMARY group from the passwd entry, not
                # os.getgid(): the local suite runs under `sg disk`,
                # which replaces the real and effective gid with the
                # disk group's (probed here: 1000 -> 6), and the scoped
                # sudoers entry admits the literal "1000:1000" --
                # os.getgid() would build "1000:6" and both privilege
                # legs would fail. On CI (no sg) the passwd primary
                # group is the runner's own, as R4 intends. The gid
                # matters for matching that sudo command, not for
                # access: the test process owns the root by uid, and
                # the owner check is what grants it write.
                primary_gid = pwd.getpwuid(os.getuid()).pw_gid
                _run_privileged(
                    "chown the mount root to the running uid:gid",
                    ["/usr/bin/chown", f"{os.getuid()}:{primary_gid}",
                     MOUNT_POINT])
        except BaseException:
            # A rig that cannot be brought up leaves nothing behind:
            # tear down whatever the sequence got to before re-raising.
            self.close()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False  # never suppress: the body's exception propagates

    def close(self) -> None:
        """Teardown, idempotent: umount, detach, remove the image.

        Each step is guarded by its own state flag, so a double close
        is a no-op and a close that failed halfway resumes from where it
        stopped instead of re-doing finished steps. Every exit path --
        clean, on exception, double close -- leaves zero loop devices
        attached to the image and the image file removed (S4).
        """
        if self._mounted:
            _run_privileged(
                "unmount the rig", ["/usr/bin/umount", MOUNT_POINT])
            self._mounted = False
        if self._loop is not None:
            _run_privileged(
                "detach the loop device", ["losetup", "-d", self._loop])
            self._loop = None
        if os.path.exists(IMAGE_PATH):
            os.remove(IMAGE_PATH)

    # -- state operations ----------------------------------------------------

    def _require_mounted(self) -> None:
        if not self._mounted:
            raise RigUnavailable(
                "the rig is not mounted (entered unmounted, or already "
                "closed); this state operation needs the mounted state")

    def remount_ro(self) -> None:
        """Remount the rig read-only: the S2 state. The option form is
        the one the scoped sudoers entry admits; the as-is leg covers
        the environments where the current user may mount."""
        self._require_mounted()
        _run_privileged(
            "remount the rig read-only",
            ["/usr/bin/mount", "-o", "remount", "-o", "ro", MOUNT_POINT])

    def remount_rw(self) -> None:
        """Remount the rig read-write again (the S2 state, reversed)."""
        self._require_mounted()
        _run_privileged(
            "remount the rig read-write",
            ["/usr/bin/mount", "-o", "remount", "-o", "rw", MOUNT_POINT])

    def free_bytes(self) -> int:
        """Free space on the mounted root, in bytes.

        R13 pins the expression: ``statvfs f_bavail * f_frsize`` -- the
        same expression the walk's step 3 will use, so the rig and the
        walk agree on "free". A rig that reported free space any other
        way would let the ENOSPC test (expected_size = reported free)
        fill a different amount of the drive than the walk thinks it
        is, and the test would stop discriminating what it claims to.
        """
        self._require_mounted()
        stats = os.statvfs(MOUNT_POINT)
        return stats.f_bavail * stats.f_frsize
