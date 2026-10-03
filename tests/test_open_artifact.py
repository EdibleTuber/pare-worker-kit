"""The open_artifact suite: the discriminating tests and the contract pins.

The spec (§5) has a rule for this file: "Each must be verified failing
against an `artifact_path`-only implementation. A test that passes there is
exercising a path that was already correct, and the fix belongs somewhere
else." This suite is that verification, run and committed RED on purpose
(plan R5): `open_artifact` in pare_worker_kit.artifacts is, at the commit
this suite was written against, the deliberately naive baseline -- the
lexical check plus a plain write-mode open of the final path -- and every
discriminator below (labelled D) is red against it, for the reason stated
in its docstring. The reason matters as much as the red: a D failing for
the wrong reason has credited the wrong mechanism, the exact trap the rule
exists to catch. The walk that replaces the baseline (the next task) must
turn every D green and every P below (labelled P) must stay green; a P
fails only if it is miswritten.

What a D and a P are, precisely. A DISCRIMINATOR (D) asserts a refusal or
behaviour the baseline does not have: it must fail against the baseline
and pass against the walk. A CONTRACT PIN (P) protects the walk's ordering
and mechanics -- the happy path, the descriptor's shape and timing, the
spelling of the temporary -- from regression: it may pass against the
baseline (all of them do) and is not a "verified failing" item.

Non-rig tests use a tmp_path root with a hand-written sentinel -- the
canonical UUID plus a trailing newline, the exact shape bench_deploy
writes -- because they exercise the walk, not the deploy. Only the
drive-state tests (D7, D8, D9, D15) use the loopback rig
(tests/loopback_rig.py): ENOSPC, EROFS and the unmounted state cannot be
produced on a tmpdir, and a mocked ENOSPC proves nothing about whether the
temporary survives -- which is the entire assertion. A rig that cannot be
built fails these tests loudly (RigUnavailable); there is no skip mode.

The one deliberate skip in the suite is P8, the cross-package pin against
agent_core's validate_descriptor: it runs wherever agent_core is installed
(this venv, CI's cross-package job) and skips by design elsewhere,
consistent with the guard pattern in test_artifacts.py.
"""
import hashlib
import os
import re
import shutil
import socket
import sys
import threading
import uuid

import pytest

from pare_worker_kit import (ARTIFACT_DESCRIPTOR_FIELDS, SENTINEL_NAME,
                             ArtifactExistsError, ArtifactPathError,
                             DriveFullError, DriveIdMismatchError,
                             DriveNotMountedError, DriveReadOnlyError,
                             InvalidArtifactInputError, NotLinuxError,
                             ProjectDirOpenError, SizeMismatchError,
                             TempAlreadyExistsError, TempVanishedError,
                             open_artifact)
from pare_worker_kit.artifacts import _NAME_RE
from loopback_rig import LoopbackDrive


SLUG = "proj-a"
NAME = "fw.bin"
MEDIA = "application/octet-stream"

HASHED_AT_RE = re.compile(
    r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z\Z")
"""The daemon's hashed_at grammar, stated independently here for the same
reason every wire literal in this repo is: the two packages are installed
separately and never share a Python environment, so a shared import could
not guarantee agreement across the wire any better than two statements can.
ASCII digits only -- P1's daemon-side finding was the Unicode-digit hole,
where [0-9] under a Unicode flag matches, say, U+0661 -- RFC 3339 UTC in
the strict Z form, optional fractional seconds. P8 runs the descriptor
through the daemon's real validator, which is the stronger half of the
agreement; this pin is what fails a run where agent_core is not installed."""


def _prepare(root: str, slug: str, *, drive_id: str | None = None) -> str:
    """Create the project directory, and optionally hand-write the sentinel.

    The sentinel is written by hand -- canonical UUID plus a trailing
    newline, the shape bench_deploy writes -- because these tests exercise
    the walk, not the deploy. Returns the project directory path.
    """
    project = os.path.join(root, slug)
    os.makedirs(project, exist_ok=True)
    if drive_id is not None:
        with open(os.path.join(root, SENTINEL_NAME), "w") as f:
            f.write(drive_id + "\n")
    return project


def _call(root, slug, name, *, drive_id, expected_size=4, media_type=MEDIA):
    """One open_artifact call with the suite's standard facts."""
    return open_artifact(root, slug, name, media_type=media_type,
                         expect_drive_id=drive_id,
                         expected_size=expected_size)


# --- discriminators: red by design against the naive baseline -------------


def test_d1_a_parked_project_directory_symlink_is_the_walks_own_refusal(tmp_path):
    """D1 -- a persistent symlink at the project directory.

    The spec's own formulation of the case artifact_path cannot catch: a
    single-threaded test cannot interleave a racing symlink between the
    lexical check and the open, so it parks the redirection and credits
    the MECHANISM. The walk opens the project directory O_NOFOLLOW and
    refuses it itself (bounded retry, then ProjectDirOpenError); the
    lexical check refuses it too, but that is the st_nlink trap -- the
    right result from the wrong mechanism, which is why this asserts the
    walk's own error class.

    RED against the baseline, for the stated reason: the baseline's
    artifact_path raises ArtifactPathError (right result, wrong
    mechanism), not ProjectDirOpenError.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    with open(os.path.join(root, SENTINEL_NAME), "w") as f:
        f.write(drive_id + "\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / SLUG).symlink_to(outside)
    with pytest.raises(ProjectDirOpenError):
        with _call(root, SLUG, NAME, drive_id=drive_id) as w:
            pass
    # The refusal is a refusal, not a redirect: nothing at the target.
    assert os.listdir(outside) == []


def test_d2_a_hardlink_planted_at_the_temporary_is_refused(tmp_path):
    """D2 -- a pre-existing hardlink at the temporary's path.

    The temporary must be created O_EXCL, and THIS test asserts that
    O_EXCL refuses the planted hardlink -- not that st_nlink does. §5 is
    explicit, and the earlier draft that credited st_nlink is the
    misattribution the "verified failing" rule exists to catch: every
    file step 5's flags produce has st_nlink == 1 by construction, so an
    st_nlink check could never be the mechanism this test is about.

    The message names the file and says to remove it, and does not claim
    it is abandoned (no "orphan"/"abandoned"/"safe" wording): nothing
    distinguishes an orphan from a live writer.

    RED against the baseline, for the stated reason: the baseline has no
    temporary at all; it opens the final path and succeeds, so
    TempAlreadyExistsError is never raised.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    temp_name = NAME + "+partial"
    temp_path = os.path.join(root, SLUG, temp_name)
    seed_dir = tmp_path / "elsewhere"
    seed_dir.mkdir()
    seed = seed_dir / "seed.bin"
    content = b"planted"
    seed.write_bytes(content)
    os.link(str(seed), temp_path)  # nlink 2, known content
    with pytest.raises(TempAlreadyExistsError) as e:
        with _call(root, SLUG, NAME, drive_id=drive_id) as w:
            pass
    msg = str(e.value)
    assert temp_name in msg
    assert "remove" in msg
    low = msg.lower()
    assert "orphan" not in low
    assert "abandoned" not in low
    assert "safe" not in low
    # The planted file is untouched: content and nlink still 2.
    assert seed.read_bytes() == content
    assert os.lstat(temp_path).st_nlink == 2


def test_d3_an_absent_sentinel_is_named_and_diagnosed(tmp_path):
    """D3 -- an absent sentinel: the likeliest real bench failure.

    /mnt/bench-store is fstab-mounted nofail, so a Pi that boots with the
    drive unplugged has an ordinary empty directory there; a bare
    FileNotFoundError is not acceptable. The error is DriveNotMountedError
    with §5's EXACT string, {root} interpolated as the declared root
    (R9) -- backticks and em-dash as in the spec. R8's value pin is
    folded in here: the message assertion uses the literal, so a drift in
    SENTINEL_NAME would fail this test.

    The project directory is pre-created so the baseline reaches the open
    and actually succeeds: the red is then a clean "did not raise", the
    plan's stated reason, rather than a setup crash.

    RED against the baseline, for the stated reason: it has no sentinel
    check and succeeds.
    """
    # R8's value pin, stated with the literal the message must carry.
    assert SENTINEL_NAME == ".bench-store-id"
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG)  # project directory only; no sentinel
    expected_msg = f"no `.bench-store-id` at {root} — is the drive mounted?"
    with pytest.raises(DriveNotMountedError) as e:
        with _call(root, SLUG, NAME, drive_id=drive_id) as w:
            pass
    assert str(e.value) == expected_msg


def test_d4_a_mismatched_sentinel_names_both_ids(tmp_path):
    """D4 -- a sentinel mismatch.

    The sentinel carries UUID A; expect_drive_id is UUID B. The error is
    DriveIdMismatchError and the message names both values: the operator
    must see which stick is plugged in next to which one was declared.

    RED against the baseline, for the stated reason: it succeeds.
    """
    root = str(tmp_path)
    planted = str(uuid.uuid4())   # what the sentinel carries
    declared = str(uuid.uuid4())  # what expect_drive_id is
    assert planted != declared
    _prepare(root, SLUG, drive_id=planted)
    with pytest.raises(DriveIdMismatchError) as e:
        with _call(root, SLUG, NAME, drive_id=declared) as w:
            pass
    msg = str(e.value)
    assert planted in msg
    assert declared in msg


def test_d5_a_symlinked_sentinel_is_treated_as_absent(tmp_path):
    """D5 -- a symlinked sentinel (R8).

    root/.bench-store-id is a symlink to a file containing the CORRECT
    UUID. A non-regular sentinel is no sentinel at all: the identity read
    must be O_NOFOLLOW, so the honest diagnosis is the absent-sentinel
    one -- DriveNotMountedError, §5's exact message -- not a mismatch
    against the redirect. The baseline would have accepted the redirect,
    which is why this discriminates.

    RED against the baseline, for the stated reason: it succeeds (and
    would have accepted the redirection).
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG)  # no regular sentinel at the root
    target = tmp_path / "real-sentinel"
    target.write_text(drive_id + "\n")  # the correct UUID, the wrong form
    os.symlink(str(target), os.path.join(root, SENTINEL_NAME))
    expected_msg = f"no `.bench-store-id` at {root} — is the drive mounted?"
    with pytest.raises(DriveNotMountedError) as e:
        with _call(root, SLUG, NAME, drive_id=drive_id) as w:
            pass
    assert str(e.value) == expected_msg


@pytest.mark.parametrize("expected_size, written", [(100, 50), (100, 150)])
def test_d6_a_clean_exit_at_the_wrong_size_is_refused_and_the_temporary_survives(
        tmp_path, expected_size, written):
    """D6 -- a short read that exits cleanly (parametrised: short, and
    overwriting).

    expected_size is a contract, not a hint: a tool that asks for 100,
    gets 50 (or 150), and leaves the with block cleanly must not publish.
    The error is SizeMismatchError and the message states both numbers.
    The temporary remains with exactly what was written, the final name
    does not exist, and there is no descriptor.

    NO hash-difference assertion: §5 says a truncated dump is not
    distinguishable by hash, so asserting the digest differs would test a
    property this design explicitly disclaims. The assertion is that the
    size check caught it and the temporary survived.

    RED against the baseline, for the stated reason: it exits clean,
    having written in place.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    payload = b"\xab" * written
    with pytest.raises(SizeMismatchError) as e:
        with _call(root, SLUG, NAME, drive_id=drive_id,
                   expected_size=expected_size) as w:
            w.write(payload)
    msg = str(e.value)
    assert str(expected_size) in msg
    assert str(written) in msg
    # The temporary remains with exactly what was written...
    temp = os.path.join(root, SLUG, NAME + "+partial")
    with open(temp, "rb") as f:
        assert f.read() == payload
    # ...the final name does not exist...
    assert not os.path.lexists(os.path.join(root, SLUG, NAME))
    # ...and there is no descriptor.
    with pytest.raises(AttributeError):
        w.descriptor


def test_d7_enospc_mid_write_is_named_and_the_temporary_survives():
    """D7 -- ENOSPC mid-write (rig, R13).

    A fresh default (64 MiB) image; expected_size is exactly the rig's
    reported free bytes (R12's equality admits it), so the write runs
    out at the free boundary: a genuine mid-write ENOSPC. Plan R13
    assumed ext4's metadata overhead lands the exhaustion strictly
    below expected_size; probed twice on this platform (kernel
    6.8.0-142-generic, Ubuntu 24.04 ext4, fresh 64 MiB image), a raw
    write consumes EXACTLY f_bavail * f_frsize bytes before ENOSPC, so
    the boundary below is <=, not <: the spec requires only that no
    descriptor is produced and that the .partial REMAINS, both of which
    are asserted. The error is DriveFullError; the TEMPORARY REMAINS
    with 0 < size <= expected_size -- asserting only the raise would be
    vacuous against a design whose claim is the .partial.

    RED against the baseline, for the stated reason: its raw write raises
    a bare OSError(ENOSPC) (unnamed), and its partial file sits at the
    final name, not a temporary.
    """
    with LoopbackDrive() as drive:
        root = drive.root
        drive_id = str(uuid.uuid4())
        _prepare(root, SLUG, drive_id=drive_id)
        expected_size = drive.free_bytes()
        chunk = b"\0" * (1 << 20)
        # Ceil, not floor: the last chunk must overflow the free space.
        chunks = (expected_size + (1 << 20) - 1) // (1 << 20)
        with pytest.raises(DriveFullError):
            with _call(root, SLUG, NAME, drive_id=drive_id,
                       expected_size=expected_size) as w:
                for _ in range(chunks):
                    w.write(chunk)
        temp = os.path.join(root, SLUG, NAME + "+partial")
        assert os.path.lexists(temp)
        size = os.lstat(temp).st_size
        assert 0 < size <= expected_size
        assert not os.path.lexists(os.path.join(root, SLUG, NAME))
        with pytest.raises(AttributeError):
            w.descriptor


def test_d8_a_read_only_mount_is_named_read_only():
    """D8 -- EROFS (rig, R14).

    The sentinel and project directory are written while the rig is
    read-write, then it is remounted read-only, so the refusal lands at
    the moment it matters (R14: the write-probe at the temporary's
    creation, not at the project directory's). The error is
    DriveReadOnlyError; the message says read-only (case-insensitive) and
    does NOT say "permission denied" -- §5: that phrasing sends the
    operator to the wrong problem, and ext4's default errors=remount-ro
    makes read-only the expected end state of a failing drive. No
    temporary is created.

    RED against the baseline, for the stated reason: it raises a bare
    OSError(EROFS).
    """
    with LoopbackDrive() as drive:
        root = drive.root
        drive_id = str(uuid.uuid4())
        _prepare(root, SLUG, drive_id=drive_id)  # while read-write
        drive.remount_ro()
        with pytest.raises(DriveReadOnlyError) as e:
            with _call(root, SLUG, NAME, drive_id=drive_id) as w:
                pass
        low = str(e.value).lower()
        assert "read-only" in low
        assert "permission denied" not in low
        assert not os.path.lexists(os.path.join(root, SLUG, NAME + "+partial"))
        assert not os.path.lexists(os.path.join(root, SLUG, NAME))


def test_d9_an_unmounted_root_is_the_absent_sentinel_diagnosis():
    """D9 -- the unmounted state (rig, R15).

    The rig entered unmounted: the image exists but the fixed path is an
    empty ordinary directory -- the exact state of an fstab-nofail boot
    with the drive unplugged, the real-world shape of D3 (which builds
    the same state by hand on a tmpdir). The error is
    DriveNotMountedError with §5's exact message.

    The project directory is pre-created, which the walk does not care
    about (its sentinel check fires before the project directory is
    touched) and which lets the baseline reach the open and succeed: the
    red stays a clean "did not raise".

    The unmounted root is the rig's FIXED path, not a per-test tmpdir:
    its contents survive the rig's teardown, so this test removes the
    project directory it created -- in a finally, because in the red
    state the failure happens before an ordinary trailing line runs, and
    a leftover directory would fail the rig's own smoke test that
    asserts the unmounted state is an empty ordinary directory. rmtree,
    not rmdir: in the red state the baseline has written the final name
    inside the project directory.

    RED against the baseline, for the stated reason: it succeeds.
    """
    with LoopbackDrive(size=8 * 1024 * 1024, mounted=False) as drive:
        root = drive.root
        try:
            drive_id = str(uuid.uuid4())
            _prepare(root, SLUG)
            expected_msg = (f"no `.bench-store-id` at {root} — "
                            f"is the drive mounted?")
            with pytest.raises(DriveNotMountedError) as e:
                with _call(root, SLUG, NAME, drive_id=drive_id) as w:
                    pass
            assert str(e.value) == expected_msg
        finally:
            if os.path.lexists(os.path.join(root, SLUG)):
                shutil.rmtree(os.path.join(root, SLUG))


def test_d10_a_completed_artifact_at_the_final_name_is_refused_and_untouched(
        tmp_path):
    """D10 -- a completed artifact already at the final name.

    The final name holds content X. The error is ArtifactExistsError --
    a distinct refusal from D2's, because a completed artifact is in the
    way, not a temporary, and the operator's choice is different: the
    message must not misdiagnose a finished dump as a stray. X is
    byte-identical afterwards (the baseline's plain write-mode open
    truncates and clobbers it), and the temporary remains (R22: every
    post-creation failure leaves it on the drive).

    RED against the baseline, for the stated reason: its plain write-mode
    open truncates and clobbers X, so nothing is raised at all.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    final = os.path.join(root, SLUG, NAME)
    x = b"pre-existing artifact"
    with open(final, "wb") as f:
        f.write(x)
    with pytest.raises(ArtifactExistsError) as e:
        with _call(root, SLUG, NAME, drive_id=drive_id,
                   expected_size=4) as w:
            w.write(b"data")
    # The message is about a completed artifact, not a temporary.
    assert NAME + "+partial" not in str(e.value)
    with open(final, "rb") as f:
        assert f.read() == x
    temp = os.path.join(root, SLUG, NAME + "+partial")
    assert os.path.lexists(temp)


def test_d11_a_vanished_temporary_is_named(tmp_path):
    """D11 -- the temporary vanishes under the writer.

    Enter, write the full bytes, then remove the sole unexpected entry in
    the project directory -- the temporary, DISCOVERED, not named: if the
    implementation's temporary were named differently, the discovery would
    still find it, and the test would not have to know the spelling. The
    exit must raise TempVanishedError (§5: ENOENT at publish, the other
    half of the two-writers case seen from the writer's side), and the
    final name does not exist.

    Against the baseline the discovery step finds no temporary -- the
    baseline writes in place, so the sole entry IS the final name -- and
    this test asserts the temporary's presence explicitly, with that
    message, so the red is a clean assertion, not a setup crash.

    RED against the baseline, for the stated reason: as above.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    project = _prepare(root, SLUG, drive_id=drive_id)
    payload = b"\x7f" * 64
    with pytest.raises(TempVanishedError):
        with _call(root, SLUG, NAME, drive_id=drive_id,
                   expected_size=len(payload)) as w:
            w.write(payload)
            unexpected = [e for e in sorted(os.listdir(project))
                          if e != NAME]
            assert len(unexpected) == 1, \
                "no temporary: implementation writes in place"
            os.remove(os.path.join(project, unexpected[0]))
    assert not os.path.lexists(os.path.join(project, NAME))


def test_d12_the_platform_gate_refuses_before_any_filesystem_operation(
        tmp_path, monkeypatch):
    """D12 -- the platform gate (R17).

    A monkeypatched non-Linux platform and a NONEXISTENT root. The error
    is NotLinuxError -- not FileNotFoundError, not a drive error -- and
    there is no filesystem side effect anywhere: the gate runs before
    input validation and before the filesystem, so a missing root on the
    wrong platform must name the platform, not the directory.

    RED against the baseline, for the stated reason: it has no gate, so
    the open of the nonexistent path raises FileNotFoundError.
    """
    monkeypatch.setattr(sys, "platform", "darwin")
    root = str(tmp_path / "absent-root")  # does not exist
    drive_id = str(uuid.uuid4())
    with pytest.raises(NotLinuxError):
        with _call(root, SLUG, NAME, drive_id=drive_id) as w:
            pass
    assert not os.path.lexists(root)


def test_d13_a_second_writer_on_the_same_name_is_refused(tmp_path):
    """D13 -- two writers, one name.

    Writer 1 enters (its temporary exists) and has written partway;
    writer 2 enters with the same (root, slug, name). Writer 2 gets
    TempAlreadyExistsError -- O_EXCL refusing the name writer 1 holds --
    and writer 1's temporary is untouched (content). The message does not
    assume abandonment: §5's timeout case, where an operator told "remove
    it" would unlink a running dump's target mid-write. Writer 1 then
    still finishes cleanly on its own exit.

    RED against the baseline, for the stated reason: its second open
    truncates writer 1's in-flight file, so nothing is raised.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    partial = b"first writer's in-flight bytes"
    temp = os.path.join(root, SLUG, NAME + "+partial")
    with _call(root, SLUG, NAME, drive_id=drive_id,
               expected_size=len(partial)) as w1:
        w1.write(partial)
        with pytest.raises(TempAlreadyExistsError) as e:
            with _call(root, SLUG, NAME, drive_id=drive_id,
                       expected_size=len(partial)) as w2:
                pass
        msg = str(e.value)
        assert NAME + "+partial" in msg
        assert "remove" in msg
        low = msg.lower()
        assert "orphan" not in low
        assert "abandoned" not in low
        assert "safe" not in low
        # Writer 1's temporary is untouched (content).
        with open(temp, "rb") as f:
            assert f.read() == partial
    # And writer 1 still publishes cleanly on its own exit.
    with open(os.path.join(root, SLUG, NAME), "rb") as f:
        assert f.read() == partial


def test_d14_an_abnormal_exit_propagates_unwrapped_and_keeps_the_temporary(
        tmp_path):
    """D14 -- abnormal exit.

    Enter, write partway, raise inside the with body. The original
    exception propagates unwrapped (the exit raises nothing of its own);
    the temporary remains with the partial content; the final name does
    not exist; and there is no descriptor (R16: a descriptor exists only
    for a file that reached the end).

    RED against the baseline, for the stated reason: its partial bytes
    sit at the final name -- the temporary's path does not exist at all,
    which the explicit presence assertion below makes the red.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    partial = b"half of a dump"
    writer = None
    with pytest.raises(RuntimeError, match="boom"):
        with _call(root, SLUG, NAME, drive_id=drive_id,
                   expected_size=len(partial) + 1) as w:
            writer = w
            w.write(partial)
            raise RuntimeError("boom")
    temp = os.path.join(root, SLUG, NAME + "+partial")
    assert os.path.lexists(temp), \
        "no temporary: implementation writes in place"
    with open(temp, "rb") as f:
        assert f.read() == partial
    assert not os.path.lexists(os.path.join(root, SLUG, NAME))
    with pytest.raises(AttributeError):
        writer.descriptor


def test_d15_an_expected_size_above_the_free_space_is_refused_before_any_byte():
    """D15 -- expected_size exceeds free space (rig, R12).

    A small (8 MiB) image whose usable space is a few MiB; expected_size
    is far above it. The step-3 precheck (free < expected_size, strict)
    must refuse BEFORE any byte: no project directory created, no
    temporary created -- the sentinel check still runs first, and the
    sentinel is present, so this is the free-space refusal and not the
    absent-sentinel one.

    The project directory is deliberately NOT pre-created: the assertion
    that it is not created requires it to be absent at call time, and
    pre-creating it would make the walk (correctly) find an existing
    directory rather than create one. Against the baseline this costs one
    step of the plan's stated red: with no project directory its plain
    open raises FileNotFoundError at the open, before a write could reach
    ENOSPC -- same root cause (no step-3 precheck), one step earlier.
    Recorded in the ledger as the one red-reason deviation.

    RED against the baseline, for the stated reason (deviation noted):
    it has no free-space check; FileNotFoundError at the open of the
    nonexistent project directory.
    """
    with LoopbackDrive(size=8 * 1024 * 1024) as drive:
        root = drive.root
        drive_id = str(uuid.uuid4())
        _prepare(root, SLUG, drive_id=drive_id)  # sentinel + project dir
        os.rmdir(os.path.join(root, SLUG))       # ...but no project dir
        with pytest.raises(DriveFullError):
            with _call(root, SLUG, NAME, drive_id=drive_id,
                       expected_size=10 * 1024 ** 3) as w:
                pass
        assert not os.path.lexists(os.path.join(root, SLUG))
        assert not os.path.lexists(os.path.join(root, SLUG, NAME + "+partial"))


@pytest.mark.parametrize("media_type, expected_size", [
    (None, 4),                                # a tool that cannot state
                                              # its media type
    (MEDIA, None),                            # silently disables the
                                              # short-read check
    (MEDIA, -1),
    (MEDIA, "100"),
    (MEDIA, True),                            # bool is an int in Python
])
def test_d16_the_tool_supplied_facts_are_validated(tmp_path, media_type,
                                                   expected_size):
    """D16 -- the tool-supplied facts.

    media_type not a str, or expected_size not a non-negative int (bools
    rejected): each is InvalidArtifactInputError. A None expected_size
    that silently disables the short-read check is worse than a refusal,
    because it would publish truncated dumps with correct hashes of the
    truncated bytes.

    RED against the baseline, for the stated reason: it ignores these
    parameters and succeeds.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    with pytest.raises(InvalidArtifactInputError):
        with _call(root, SLUG, NAME, drive_id=drive_id,
                   media_type=media_type,
                   expected_size=expected_size) as w:
            pass


def test_d17_a_fifo_at_the_sentinel_is_refused_and_does_not_block(tmp_path):
    """D17 -- a FIFO parked at the sentinel (R8, step 2).

    root/.bench-store-id is a named pipe. A local attacker with write
    access inside the root needs no privilege to mkfifo it (deleting a
    real sentinel first, if one exists). The step-2 open must NOT block:
    O_RDONLY on a FIFO blocks in the kernel until a writer opens the
    other end, and nothing in the walk ever does, so a blocking open is
    a permanent hang for the daemon -- an availability failure, and a
    departure from R8 (a non-regular sentinel is DriveNotMountedError,
    §5's exact message, never a hang). The fstat branch is exactly where
    the FIFO is refused (S_ISFIFO is not S_ISREG); it is reachable only
    if the open carries O_NONBLOCK.

    The walk runs on a daemon thread with a bounded join: a blocking
    open leaves the thread alive and this test fails in a couple of
    seconds instead of hanging the suite.

    RED against the baseline, for the stated reason: it has no sentinel
    check at all and raises no DriveNotMountedError (a clean "did not
    raise", as in D3).
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG)  # no regular sentinel at the root
    os.mkfifo(os.path.join(root, SENTINEL_NAME))
    expected_msg = f"no `.bench-store-id` at {root} — is the drive mounted?"

    outcome = {}

    def run():
        try:
            with _call(root, SLUG, NAME, drive_id=drive_id) as w:
                pass
        except BaseException as e:  # noqa: BLE001 - the test inspects it
            outcome["error"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(2.0)
    assert not t.is_alive(), (
        "the walk blocked on the FIFO sentinel: step 2's open must carry "
        "O_NONBLOCK, and a non-regular sentinel is refused, not parked")
    assert "error" in outcome, "the walk did not refuse the FIFO sentinel"
    assert isinstance(outcome["error"], DriveNotMountedError)
    assert str(outcome["error"]) == expected_msg


# --- contract pins: green by design ---------------------------------------


def test_p1_the_happy_path_publishes_the_final_name_and_a_descriptor(tmp_path):
    """P1 -- the happy path (contract pin, green against the baseline).

    Write exactly expected_size in two chunks (60 + 40). The final name
    holds exactly the concatenated content; the temporary is gone; and
    writer.descriptor has exactly the seven keys of
    ARTIFACT_DESCRIPTOR_FIELDS -- in wire order, the insertion order being
    the wire order -- with sha256 over the bytes written, size
    expected_size, path the normalised declared root + slug + name,
    drive_id expect_drive_id, media_type as supplied, host the hostname,
    and hashed_at in the daemon's P1 grammar (ASCII digits, RFC 3339 Z).
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    first, second = b"a" * 60, b"b" * 40
    with _call(root, SLUG, NAME, drive_id=drive_id,
               expected_size=len(first) + len(second)) as w:
        w.write(first)
        w.write(second)
    final = os.path.join(root, SLUG, NAME)
    with open(final, "rb") as f:
        assert f.read() == first + second
    assert not os.path.lexists(os.path.join(root, SLUG, NAME + "+partial"))
    d = w.descriptor
    assert set(d) == set(ARTIFACT_DESCRIPTOR_FIELDS)
    assert tuple(d) == ARTIFACT_DESCRIPTOR_FIELDS  # wire order
    assert d["sha256"] == hashlib.sha256(first + second).hexdigest()
    assert d["size"] == len(first) + len(second)
    assert d["path"] == os.path.normpath(root) + "/" + SLUG + "/" + NAME
    assert d["drive_id"] == drive_id
    assert d["media_type"] == MEDIA
    assert d["host"] == socket.gethostname()
    assert HASHED_AT_RE.fullmatch(d["hashed_at"])


def test_p2_a_zero_byte_artifact_is_a_complete_artifact(tmp_path):
    """P2 -- the zero-byte artifact (contract pin).

    expected_size 0, no writes, clean exit: a dump that legitimately
    produced nothing is still a complete artifact. The final name exists
    with length 0, and the descriptor says size 0 with the EMPTY digest
    -- not a missing field, not a None.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    with _call(root, SLUG, NAME, drive_id=drive_id,
               expected_size=0) as w:
        pass
    final = os.path.join(root, SLUG, NAME)
    assert os.path.exists(final)
    assert os.path.getsize(final) == 0
    assert w.descriptor["size"] == 0
    assert w.descriptor["sha256"] == hashlib.sha256(b"").hexdigest()


def test_p3_path_shaped_inputs_are_refused_before_any_filesystem_operation(
        tmp_path):
    """P3 -- path-shaped inputs before the filesystem (contract pin).

    Non-str root/slug/name, a traversal slug, a separator slug, a
    separator name: each is ArtifactPathError (R10/R18: the walk validates
    the root's rules, SLUG_RE and _NAME_RE before any filesystem
    operation), and no directory or file is created under the root.
    Validation precedes filesystem operations, and the walk must keep
    that ordering.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    cases = [
        (None, SLUG, NAME),      # non-str root (workers.yaml as int/None)
        (123, SLUG, NAME),       # non-str root
        (root, None, NAME),      # non-str slug
        (root, 123, NAME),       # non-str slug
        (root, SLUG, None),      # non-str name
        (root, "../x", NAME),    # a traversal slug
        (root, "a/b", NAME),     # a separator slug
        (root, SLUG, "a/b"),     # a separator name
    ]
    for r, s, n in cases:
        with pytest.raises(ArtifactPathError):
            with _call(r, s, n, drive_id=drive_id) as w:
                pass
    # Nothing was created: the root still holds only its sentinel and the
    # project directory the test itself prepared.
    assert sorted(os.listdir(root)) == [SENTINEL_NAME, SLUG]


def test_p4_a_symlinked_root_is_followed_not_refused(tmp_path):
    """P4 -- root is a symlink: followed, not refused (contract pin).

    §5 step 1 is deliberate: the root is the operator's own declaration in
    workers.yaml, the trust anchor for the whole mechanism, and there is
    nothing more trusted to check it against. The walk opens it FOLLOWING
    symlinks; this pins that against over-refusal (the project directory
    and the artifact are both checked, the root is not). The descriptor's
    path names the DECLARED root, not the resolved target: it is what the
    operator's scp uses and what the daemon's containment check compares.

    The setup pre-creates the project directory through the link: the
    baseline has no project-directory step (the walk's step 4 does), so
    without it the plain open fails on the missing parent and this pin
    would fail for a reason it is not about. The walk handles an existing
    project directory, so the pin holds against it too.
    """
    real = tmp_path / "real"
    real.mkdir()
    root_link = tmp_path / "store"
    root_link.symlink_to(real)
    root = str(root_link)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)  # sentinel + project dir, via link
    with _call(root, SLUG, NAME, drive_id=drive_id,
               expected_size=4) as w:
        w.write(b"abcd")
    with open(os.path.join(root, SLUG, NAME), "rb") as f:  # via the link
        assert f.read() == b"abcd"
    assert w.descriptor["path"] == \
        os.path.normpath(root) + "/" + SLUG + "/" + NAME


def test_p5_the_temporary_name_is_outside_the_legal_name_space(tmp_path):
    """P5 -- the temporary-name property, tied to the spelling (R11).

    For each of "dump", "dump.partial", "dump.partial.partial" (all
    verified to match _NAME_RE -- the spec ran the regex, and this
    re-verifies it so a drift in the regex re-opens the question): the
    temporary name, name + "+partial", does not match _NAME_RE (it
    contains a character outside its alphabet) and does not begin with
    "." (the orphan must stay visible to a plain ls at the bench).

    The implementation is tied to the spelling, conditionally: the exact
    temporary is pre-seeded, and IF the implementation refuses it (as the
    walk does, with TempAlreadyExistsError), the message must name the
    seeded file exactly. Against the baseline no refusal happens and the
    tie is vacuous -- discriminating the refusal is D2's job; this pin
    only fixes what the refusal, when it arrives, must call the file.
    """
    drive_id = str(uuid.uuid4())
    for name in ("dump", "dump.partial", "dump.partial.partial"):
        # The spec ran the regex; verify it still holds.
        assert _NAME_RE.fullmatch(name), name
        temp_name = name + "+partial"
        assert not _NAME_RE.fullmatch(temp_name), name
        assert not temp_name.startswith("."), name
        root = str(tmp_path / ("root-" + name.replace(".", "")))
        _prepare(root, SLUG, drive_id=drive_id)
        with open(os.path.join(root, SLUG, temp_name), "wb") as f:
            f.write(b"seed")
        raised = None
        try:
            with _call(root, SLUG, name, drive_id=drive_id,
                       expected_size=4) as w:
                pass
        except TempAlreadyExistsError as e:
            raised = e
        if raised is not None:
            assert temp_name in str(raised)


def test_p6_the_descriptor_exists_only_after_a_clean_exit(tmp_path):
    """P6 -- descriptor timing (contract pin).

    .descriptor is absent before a clean exit (AttributeError -- the
    attribute does not exist; it is not set to None) and present
    immediately after: a descriptor exists only for a file that reached
    the end.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    with _call(root, SLUG, NAME, drive_id=drive_id,
               expected_size=4) as w:
        with pytest.raises(AttributeError):
            w.descriptor
        w.write(b"abcd")
    assert isinstance(w.descriptor, dict)


def test_p7_write_returns_the_count_and_rejects_non_bytes(tmp_path):
    """P7 -- the write() contract (contract pin).

    write(b) returns the count written; multiple writes accumulate (P1's
    two chunks cover the accumulation half); non-bytes input (str) raises
    TypeError -- a programming error, consistent with the built-in file
    API, the one place a bare builtin is right.
    """
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    with _call(root, SLUG, NAME, drive_id=drive_id,
               expected_size=10) as w:
        assert w.write(b"hello") == 5
        assert w.write(b"world") == 5
        with pytest.raises(TypeError):
            w.write("not bytes")


def test_p8_the_descriptor_survives_the_daemons_validator(tmp_path):
    """P8 -- the cross-package pin (the one deliberate skip in the suite).

    Build a descriptor via the happy path with root R and slug S, then run
    it through agent_core's validate_descriptor against a WorkerSpec that
    declares artifact_root=R and the sentinel's UUID as
    artifact_drive_id: it must pass. The wire contract is pinned on both
    sides (P1's discipline), and the kit's path/hashed_at/drive_id shapes
    survive the daemon's containment and grammar checks -- including the
    ASCII-digit hashed_at pin that P1's daemon-side fix landed.

    Runs wherever agent_core is installed (the local venv, CI's
    cross-package job); skips by design elsewhere, consistent with the
    guard pattern in test_artifacts.py.
    """
    ac = pytest.importorskip(
        "agent_core.workers.artifacts",
        reason="agent_core is not installed here; the daemon-side half of "
               "this pin runs in agent_core's own suite")
    from agent_core.workers.types import WorkerSpec
    root = str(tmp_path)
    drive_id = str(uuid.uuid4())
    _prepare(root, SLUG, drive_id=drive_id)
    with _call(root, SLUG, NAME, drive_id=drive_id,
               expected_size=4) as w:
        w.write(b"abcd")
    descriptor = w.descriptor
    spec = WorkerSpec(
        name="bench",
        transport="stdio",
        command="bench-worker",
        risk_default="low",
        artifact_root=root,
        artifact_drive_id=drive_id,
    )
    assert ac.validate_descriptor(
        descriptor, spec=spec, tool="dump", slug=SLUG) == descriptor
