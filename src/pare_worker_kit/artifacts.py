"""What a tool produces, and where a worker is allowed to write it.

The daemon routes on this declaration rather than on the model's choice of
tool: a tool marked `artifact` returns a DESCRIPTOR of a file it wrote, never
the file's contents. Without it, a two-gigabyte firmware dump would cross the
network as one tool result.
"""
import errno
import hashlib
import os
import re
import socket
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone

PRODUCES_META_KEY = "agent_core/produces"
"""The _meta key a tool uses to declare what it returns.

Stated here AND in agent_core, with a guard test on each side, because the
daemon and the worker are separately installed packages that never share a
Python environment -- so a shared import could not guarantee agreement across
the wire any better than two literals can.
"""

PRODUCES_RESULT = "result"
PRODUCES_ARTIFACT = "artifact"

VALID_PRODUCES = (PRODUCES_RESULT, PRODUCES_ARTIFACT)
"""Absent means `result`. An unrecognised value is a conformance failure at
build time, not a silent default -- the same choice the risk tier makes, and
copying the mechanism without copying that choice would lose the property."""

ARTIFACT_DESCRIPTOR_FIELDS = ("host", "path", "size", "sha256", "hashed_at",
                              "media_type", "drive_id")
"""The seven fields a `produces: artifact` tool returns, in wire order.

Stated here AND in agent_core, with a guard test on each side, for the same
reason as PRODUCES_META_KEY above: the two packages are separately installed
and never share a Python environment, so a shared import could not guarantee
agreement across the wire any better than two statements can. The worker
builds exactly these fields (open_artifact, which lands after this) and the
daemon's validate_descriptor requires exactly these; a field present on one
side and not the other is a descriptor that validates on one machine and is
refused on the other, with no useful error anywhere. All seven are required;
none is optional. The eighth field of the object that gets published,
produced_by, is added by the daemon AFTER validation and never travels.
"""

RESERVED_SLUG_ARG = "project_slug"
"""The tool-argument name the daemon injects with the project's ArcticBase
slug. RESERVED_DRIVE_ID_ARG is the same arrangement for the drive id the
artifact must land on; see it below.

Reserved means the daemon supplies the value: injected at the dispatch
chokepoint, overwriting whatever the model supplied, so the model never sees
it as an input it may choose. A worker names its tool-handler parameter after
this value so the injection lands where the handler expects it -- which is
why the value must be a legal Python identifier as well as wire vocabulary.
Stated here AND in agent_core, with a guard test on each side. Changing
either value is a wire-breaking change.
"""

RESERVED_DRIVE_ID_ARG = "expected_drive_id"
"""The same arrangement as RESERVED_SLUG_ARG, for the drive id. The worker
passes the injected value through to open_artifact as expect_drive_id; a
descriptor whose drive_id differs is refused.
"""


_SLUG_MAX = 64
"""ArcticBase's cap. Stated as a constant so the pattern below and the tests
that probe the boundary cannot disagree about it."""

SLUG_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,%d}" % (_SLUG_MAX - 1))
"""The same rule agent_core states, character for character, for the same
reason PRODUCES_META_KEY is stated twice: the two packages are separately
installed and never share a Python environment, so a shared import could not
guarantee agreement across the wire any better than two statements can. A
guard test on each side keeps them equal -- comparing flags as well as the
pattern text, because `[a-z]` under re.IGNORECASE matches U+212A KELVIN SIGN
and U+017F LATIN SMALL LETTER LONG S, so identical pattern strings with
different flags are different alphabets.

If they drift, a slug the daemon accepts is one the worker refuses, and
hardware tools stop working with no useful error.

Matched with `fullmatch`, never `match`: an unanchored check accepts
`proj/../../etc`. The leading-alphanumeric requirement keeps a slug out of
argument-injection range in the scp/tar commands an operator later runs by
hand -- `-rf` and `--checkpoint-action=exec=sh` are legal directory names.
"""

_NAME_MAX = 128
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,%d}" % (_NAME_MAX - 1))
"""One path component, ASCII only, no separator and no leading dot or dash.

ASCII by construction is what makes the Unicode question moot: nothing that
normalises (NFC/NFD/NFKC) or case-folds onto an allowed character is itself
allowed, because every allowed character is a single ASCII byte that is a
fixed point of all four normalisation forms.
"""


class ArtifactPathError(ValueError):
    """A path that would have escaped the operator-declared artifact root."""


def _root_rules(root: str) -> str:
    """The operator-declared root's rules, shared by artifact_path and
    open_artifact.

    Takes a root already type-checked to a str (the two callers check types
    in their own order) and returns the normalised root. Stated ONCE here so
    the lexical entry (artifact_path) and the walk (open_artifact) cannot
    drift: a root one admits that the other refuses would be a path that is
    contained on one reading of the declaration and not the other.
    """
    if not root.startswith("/"):
        raise ArtifactPathError(f"artifact root must be absolute, got {root!r}")
    # A `..` inside the root is refused even though the root is trusted,
    # because the containment check in artifact_path is LEXICAL and the
    # kernel's is not: for `/a/b/../c` where `b` is a symlink to `/x/y`,
    # normpath says `/a/c` and the kernel says `/x/c`. Accepting it would
    # mean checking containment against a directory that is not the one
    # written to.
    if ".." in root.split("/"):
        raise ArtifactPathError(
            f"artifact root must be normalised, got {root!r}: a '..' component "
            f"does not name the directory the operator declared")
    # Stated as a PROPERTY rather than as a slash count, because the property
    # is precisely what the backstop at the end of artifact_path needs, and
    # it tracks the stdlib automatically if these functions ever change: a
    # root that is not a `commonpath` prefix of ITSELF cannot have
    # containment checked against it, and every comparison against it is
    # meaningless.
    #
    # Today the only paths with that shape begin with exactly two slashes.
    # POSIX leaves those implementation-defined, and Python splits the
    # difference: `normpath` PRESERVES the `//` while `commonpath` COLLAPSES
    # it. Refused rather than collapsed to one slash, because fail-closed is
    # the right default for a path form the standard declines to define -- on
    # a platform where `//host` names a different filesystem, collapsing it
    # would silently relocate the artifact root. The operator gets a message
    # naming the ambiguity instead of a containment error that diagnoses the
    # wrong problem.
    base = os.path.normpath(root)
    if os.path.commonpath([base, base]) != base:
        raise ArtifactPathError(
            f"ambiguous artifact root {root!r}: a path beginning with exactly "
            f"two slashes is implementation-defined in POSIX and is not a "
            f"prefix of itself, so containment cannot be checked against it")
    # Deliberately NOT checked: whether `root` itself is a symlink. It is the
    # operator's own declaration in workers.yaml, which is the trust anchor
    # for both callers -- there is nothing more trusted to check it against,
    # and an operator who points the root at a symlinked mount has made a
    # decision, not a mistake. The walk's step 1 opens it FOLLOWING symlinks
    # for exactly this reason.
    return base


def artifact_path(root: str, slug: str, name: str) -> str:
    """Build a contained path for an artifact, refusing anything that escapes.

    THIS CHECK CANNOT BE DONE BY THE DAEMON. The daemon runs on another
    machine and has no view of this filesystem, so resolving symlinks there
    would resolve against the wrong namespace -- worse than not checking at
    all. It has to happen here, on the machine that owns the files.

    Be honest about what it buys: this defends against a buggy worker, a
    confused path and a hostile *client*. It does not make a hostile worker
    honest -- nothing running on the worker can.

    AND DO NOT REACH FOR sha256 AS THE ANSWER TO THAT. The descriptor's
    digest is computed by the producer, over the bytes the producer chose, so
    it cannot attest that those are the right bytes. A worker that truncates
    a dump returns a perfectly correct sha256 OF THE TRUNCATED BYTES, and the
    operator verifies it successfully -- indistinguishable, by hash alone,
    from a complete one. Content-addressing is not authenticity here, because
    the producer supplies both halves of the comparison.

    What it does buy is real but narrower, and worth keeping: integrity
    across the transfer, so a corrupted or half-finished `scp` is detected
    rather than silently acted on; and a stable identity for the artifact in
    audit, dedup and later reference. Authenticity needs a digest the producer
    did not supply -- a vendor's published hash, one recorded before the
    worker could have been compromised, or a signature over a key the worker
    does not hold.

    THERE IS A TOCTOU WINDOW AND IT IS ACCEPTED, NOT FIXED. This function
    returns a path and never holds a file descriptor, so anything that can
    write inside the root can replace the checked component with a symlink
    (or a hardlink, which leaves no symlink to find) between this call
    returning and the caller opening the file, and the write lands on the
    attacker's target. Closing it would mean returning an open fd from an
    `openat`/`O_NOFOLLOW` walk, which is not the contract this function has.
    Do not read the symlink checks below as a guarantee: they stop a
    *persistent* redirection, not a racing one. Nothing downstream detects an
    attacker who wins that race either: the operator retrieves the file the
    attacker substituted, and its sha256 matches it, for the reason in the
    paragraph above. What actually closes this is at the CALL SITE -- open
    with `O_NOFOLLOW | O_CREAT | O_EXCL` and write through that descriptor,
    never re-opening by path -- or an expected digest from outside the worker.

    Raises ArtifactPathError -- and only ArtifactPathError -- for every bad
    input, including wrong types. A caller catching it must not also have to
    catch TypeError from inside `re`.
    """
    # Types first: `root` comes from workers.yaml, so an operator writing
    # `artifact_root: 1234` hands us an int, and `slug`/`name` cross the wire
    # as JSON, where null and numbers are ordinary values.
    if not isinstance(root, str):
        raise ArtifactPathError(
            f"artifact root must be a str, got {type(root).__name__}")
    if not isinstance(slug, str):
        raise ArtifactPathError(
            f"invalid project slug: must be a str, got {type(slug).__name__}")
    if not isinstance(name, str):
        raise ArtifactPathError(
            f"invalid artifact name: must be a str, got {type(name).__name__}")

    # The root's rules are the shared helper's (stated once, so the walk in
    # open_artifact refuses the same roots for the same reasons); only the
    # type checks stay here, in this function's own order.
    root = _root_rules(root)

    if not SLUG_RE.fullmatch(slug):
        raise ArtifactPathError(
            f"invalid project slug {slug!r}: must match {SLUG_RE.pattern!r}")
    if not _NAME_RE.fullmatch(name):
        raise ArtifactPathError(
            f"invalid artifact name {name!r}: must match {_NAME_RE.pattern!r} "
            f"-- one component, no separators and no traversal")

    project = os.path.join(root, slug)
    # lexists + islink, i.e. lstat, not stat: stat follows the link and would
    # report the TARGET's type, so a symlinked project directory pointing at /
    # would look like a perfectly ordinary directory. lexists rather than
    # exists for the same reason -- a dangling symlink is still a redirection
    # and exists() reports False for one.
    if os.path.lexists(project) and os.path.islink(project):
        raise ArtifactPathError(
            f"project directory {project!r} is a symlink; refusing to write "
            f"artifacts through it")

    path = os.path.join(project, name)
    # Any symlink here is refused, including one whose target is inside the
    # root. That is a deliberate false positive: a link that resolves inside
    # the root today can be repointed outside it before the caller opens the
    # file, and this function cannot bind the target it checked to the one
    # that gets written (see the TOCTOU paragraph above). Fail closed.
    if os.path.lexists(path) and os.path.islink(path):
        raise ArtifactPathError(
            f"artifact path {path!r} is a symlink; refusing to write through "
            f"it, because the operator will later act on this path")

    # Belt and braces, and genuinely unreachable as the code stands -- which
    # is the point of keeping it. Three checks above are jointly what make it
    # so: `root` is a `commonpath` prefix of itself, and neither regex admits
    # a separator, so `path` is always `root` plus two components. Loosen any
    # one of them and this is the check that still refuses traversal.
    #
    # Do not read it as reachable: no input exercises this branch, so it is
    # the invariant above that the tests pin, not this line. If you make it
    # fire, something upstream has stopped holding.
    if os.path.commonpath([path, root]) != root:
        raise ArtifactPathError(f"{path!r} escapes artifact root {root!r}")
    return path


SENTINEL_NAME = ".bench-store-id"
"""The drive-identity sentinel, at {root}/.bench-store-id.

The file bench_deploy writes on the drive (the parent spec §5.5): a
canonical UUID plus a trailing newline. open_artifact reads it before
anything is created and compares its contents against expect_drive_id,
stripping surrounding whitespace (the deployed file ends with a newline)
-- drive identity is established before the first byte is written, not
after. os.path.ismount answers "is this a mount"; the sentinel answers
"which drive", which is the question: a drive that failed to mount leaves
an ordinary empty directory, where the sentinel is simply absent.

A sentinel that is not a regular file is treated as ABSENT, not as its
target's contents (R8): a symlinked sentinel is a redirection, and the
read that establishes identity must refuse to follow one -- so the honest
diagnosis for a symlink is the absent-sentinel one ("there is no real
sentinel here"), not a mismatch against whatever the redirect happens to
point at. The value is pinned by a local test (tests/test_open_artifact.py,
D3), because this literal is stated on both sides of a deploy:
bench_deploy writes it, and an operator who does not find it is told its
name by the error message.
"""


class ArtifactWriteError(Exception):
    """Base for every failure open_artifact raises after the lexical check.

    The promise this hierarchy exists for: a caller never catches a bare
    OSError out of open_artifact. Each drive failure mode has a name, so a
    tool handler -- and the operator reading its error -- can tell "the
    drive is read-only" from "that is the wrong stick" from "the drive
    filled up" without parsing errnos or message text.

    Path-shaped input errors are NOT here: they keep the existing
    ArtifactPathError (a ValueError, unchanged, outside this hierarchy).
    That is the established refusal for anything wrong with root/slug/name,
    and two error families for one input class would force every caller to
    catch both.

    Internal invariant violations -- the step-6 fstat, the inode match at
    publish -- raise THIS class itself rather than a subclass. The
    distinct-error list covers drive failure modes; those are
    "should be unreachable" refusals, and the base class, with a message
    stating which invariant broke, is the honest name for them.
    """


class NotLinuxError(ArtifactWriteError):
    """The A7 platform gate.

    open_artifact is Linux-only, and the refusal lands before any
    filesystem operation: a nonexistent root on a non-Linux platform must
    name the platform, not the missing directory. A FileNotFoundError
    there would diagnose the wrong problem on a machine the operator
    knows cannot run this.
    """


class DriveNotMountedError(ArtifactWriteError):
    """The sentinel is absent -- or is not a regular file.

    The message is the spec's exact string, `no `.bench-store-id` at
    {root} -- is the drive mounted?`, because this is the likeliest real
    bench failure: /mnt/bench-store is fstab-mounted nofail, so a Pi that
    boots with the drive unplugged has an ordinary empty directory there,
    and the operator needs the diagnosis, not an errno. Distinct from a
    mismatch: a bare FileNotFoundError, or a mismatch against an id the
    operator cannot see, would send them looking for the wrong thing.

    A symlinked sentinel is diagnosed this way too (R8): a non-regular
    sentinel is a redirection, O_NOFOLLOW refuses it, and the honest
    statement is that there is no real sentinel here.
    """


class DriveIdMismatchError(ArtifactWriteError):
    """The sentinel exists but carries a UUID other than expect_drive_id.

    The message names both values: the operator must see which stick is
    plugged in next to which one workers.yaml declared. ismount cannot
    make this distinction for removable drives, which is the whole reason
    the sentinel exists.
    """


class DriveReadOnlyError(ArtifactWriteError):
    """EROFS, named as read-only and never as permission denied.

    ext4's default errors=remount-ro makes read-only the EXPECTED end
    state of a failing drive, not an exotic one; "permission denied"
    sends the operator to the wrong problem (and on a read-only mount the
    two are genuinely different: the permissions may be exactly right).
    """


class DriveFullError(ArtifactWriteError):
    """ENOSPC, wherever it lands: the free-space precheck, mid-write, or at
    fsync. One class, because the operator's remedy is the same in all
    three -- make room -- and the messages may differ by which moment
    caught it. ENOSPC surfaces at write or fsync, never at a buffered
    write(), and is not swallowed: the writer holds the descriptor and
    calls os.write, so there is no buffered layer to swallow it into.
    """


class FileTooLargeError(ArtifactWriteError):
    """EFBIG, naming FAT32's 4 GiB ceiling.

    The store is ext4, but a replacement stick might not be, and the
    message must say which wall was hit. Not constructible on the ext4
    rig (the ceiling needs FAT32 or a multi-giB image), so it is pinned
    by taxonomy and message content rather than by a rig test -- the same
    "impossible to construct or vacuous" standard that dropped the
    wrong-filesystem sentinel test.
    """


class SizeMismatchError(ArtifactWriteError):
    """bytes_written != expected_size on a clean exit: the short read.

    expected_size is a contract, not a hint, and this is the spec's one
    defence against a truncated dump that leaves the with block cleanly:
    a correct size and a correct hash of the truncated bytes, which is the
    ordinary hardware failure. The message states both numbers. The
    temporary is kept: a truncated dump is not distinguishable by hash, so
    the only honest artifact is the orphan, visible to ls and to
    bench_doctor.
    """


class TempAlreadyExistsError(ArtifactWriteError):
    """O_EXCL refusal at the temporary's path (step 5).

    The message names the file and says to remove it, and must NOT assume
    it is abandoned: nothing here distinguishes an orphan from a live
    writer, and the likeliest way to meet one is the timeout case -- a
    dump that outlived its session -- where an operator told to "remove
    it" would unlink a running dump's target mid-write. The file is left
    in place deliberately: the orphan is worth more than a convenient
    retry.
    """


class ArtifactExistsError(ArtifactWriteError):
    """EEXIST at publish (step 7): a completed artifact is in the way.

    Distinct message from TempAlreadyExistsError, because the operator's
    choice is different: a finished dump is not a stray to clear, it is a
    previous run's output, and removing it destroys data. The atomic
    refusal is what protects the previous run in the first place --
    neither rename nor replace may silently overwrite it.
    """


class TempVanishedError(ArtifactWriteError):
    """ENOENT at publish (step 7): the temporary vanished while it was
    being written.

    The other half of the two-writers case, seen from the writer's side:
    something with write access in the project directory removed the file
    between the write and the publish. The final name is not created and
    no descriptor is produced: a descriptor exists only for a file that
    reached the end.
    """


class ProjectDirOpenError(ArtifactWriteError):
    """Step 4's bounded retry exhausted: a symlink is parked at the
    project directory.

    The message names the slug and states that a symlink was detected.
    The retry is bounded because anything with write access inside the
    root can otherwise drive an open/mkdir loop against a racing symlink
    indefinitely; the give-up is a fail-safe refusal, not a fallback.
    This is the walk's OWN refusal for a persistent redirection at the
    project directory -- the lexical check in artifact_path cannot bind
    what the open sees, and this is the one case it cannot catch.
    """


class InvalidArtifactInputError(ArtifactWriteError):
    """A tool-supplied fact is not what it must be.

    media_type must be a str (not None: a tool that cannot state its
    media type has not decided what it is writing), and expected_size
    must be an int, not a bool, >= 0. The walk refuses rather than
    silently defaulting: a None expected_size that disables the short-
    read check is worse than a refusal, because it would publish
    truncated dumps with correct hashes of the truncated bytes.
    """


def _close_quietly(fd):
    """Close a descriptor, never raising.

    R22 requires every fd closed on every path; a close that fails (say,
    on a drive that errors its final writeback) must not mask the
    exception the walk is already carrying -- the operator's error is the
    drive's, not the cleanup's.
    """
    try:
        os.close(fd)
    except OSError:
        pass


def _drive_not_mounted_message(root):
    """Step 2's refusal string: the spec's exact wording, verbatim.

    Backticks and the em-dash as in the spec (R9 pins both). The em-dash
    is written as an escape because it is load-bearing: D3/D5/D9 compare
    the message character for character, and a hyphen or an en-dash would
    be a different string. {root} is the DECLARED root -- the string the
    operator wrote in workers.yaml -- not the normalised form.
    """
    return f"no `{SENTINEL_NAME}` at {root} \u2014 is the drive mounted?"


_SENTINEL_MAX_BYTES = 4096
"""The deployed sentinel is a canonical UUID plus a trailing newline (37
bytes); a cap four orders of magnitude above that distinguishes "not a
sentinel" from "a sentinel," and bounds the read."""


def _sentinel_drive_id(root_fd, declared_root):
    """Step 2: read the drive's identity, O_NOFOLLOW, relative to the root
    descriptor (spec §5 step 2).

    Returns the whitespace-stripped sentinel value (the deployed file ends
    with a newline). Every way the sentinel is not a small regular file
    with a clean value -- absent, a symlink (O_NOFOLLOW refuses it: ELOOP
    on a link to a file, ENOTDIR on a link to a directory; R8), a
    directory, a FIFO, oversized, undecodable -- raises
    DriveNotMountedError with the exact message, because the honest
    diagnosis for all of them is "there is no real sentinel here." A
    mismatch against whatever a redirection happens to point at would
    send the operator to the wrong stick, which is the failure this
    check exists to prevent.

    The open carries O_NONBLOCK: an O_RDONLY open of a FIFO parks in the
    kernel until a writer arrives, and nothing in the walk ever does,
    so without the flag a FIFO parked at the sentinel (no privilege
    needed from anything with write access inside the root) would hang
    the daemon instead of being refused by the fstat branch below.
    """
    try:
        fd = os.open(SENTINEL_NAME,
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=root_fd)
    except OSError:
        raise DriveNotMountedError(
            _drive_not_mounted_message(declared_root)) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            # A directory -- and a FIFO, which the open's O_NONBLOCK
            # keeps from parking the walk -- opens O_RDONLY on Linux;
            # only fstat tells.
            raise DriveNotMountedError(
                _drive_not_mounted_message(declared_root))
        buf = bytearray()
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > _SENTINEL_MAX_BYTES:
                break
        if len(buf) > _SENTINEL_MAX_BYTES:
            raise DriveNotMountedError(
                _drive_not_mounted_message(declared_root))
        try:
            return buf.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise DriveNotMountedError(
                _drive_not_mounted_message(declared_root)) from None
    except OSError as e:
        # A read error on the sentinel is not an absent sentinel, but the
        # promise is that callers never see a bare OSError: name it.
        raise ArtifactWriteError(
            f"reading the sentinel {SENTINEL_NAME} failed: {e.strerror or e}"
        ) from e
    finally:
        _close_quietly(fd)


_PROJECT_DIR_ATTEMPTS = 3
"""Step 4's bounded retry (R21). Anything with write access inside the
root can otherwise drive an open/mkdir loop against a racing symlink
indefinitely; the give-up is a fail-safe refusal, not a fallback."""


def _project_dir_errno_refusal(action, slug, e):
    """Name an unexpected errno from step 4's open or mkdir.

    R9's promise: the caller never sees a bare OSError. EROFS and ENOSPC
    have drive names; the rest are invariant-shaped failures and take the
    base class.
    """
    if e.errno == errno.EROFS:
        return DriveReadOnlyError(
            f"the artifact root is read-only: {action} project directory "
            f"{slug!r} failed (EROFS); ext4 remounts read-only when it "
            f"detects an error, so check the drive")
    if e.errno == errno.ENOSPC:
        return DriveFullError(
            f"no space left on the artifact root: {action} project "
            f"directory {slug!r} failed (ENOSPC)")
    return ArtifactWriteError(
        f"could not {action} project directory {slug!r}: "
        f"{e.strerror or e}")


def _open_project_dir(root_fd, slug):
    """Step 4: open the project directory O_DIRECTORY|O_NOFOLLOW relative
    to the root descriptor, created if absent (spec §5 step 4).

    The race-free counterpart of artifact_path's lexists/islink pair,
    which checks a PERSISTENT redirection and says so: O_NOFOLLOW makes a
    racing symlink safe (it is refused, never followed), so the retry
    cannot be an escape -- but the retry must be BOUNDED (R21) and end in
    a named give-up, because a parked symlink makes every attempt fail the
    same way.

    ENOENT -> mkdir through the descriptor -> retry. That is the normal
    first-time case, and the racing-replacement case: a racer that creates
    the directory (or parks a symlink under it) between the open and the
    mkdir meets EEXIST, which is tolerated -- something else created it,
    and the next open decides whether what it created is usable.
    ELOOP / ENOTDIR -> a symlink is parked at the project directory
    (probed: a single symlink-to-directory surfaces as ENOTDIR, a chain as
    ELOOP) -> retry. Exhaustion -> ProjectDirOpenError: the walk's OWN
    refusal for a persistent redirection (R10: not ArtifactPathError,
    which is the lexical check's error and would credit the wrong
    mechanism -- that misattribution is exactly D1's point).
    """
    for _ in range(_PROJECT_DIR_ATTEMPTS):
        try:
            return os.open(slug, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                           | os.O_CLOEXEC, dir_fd=root_fd)
        except OSError as e:
            if e.errno == errno.ENOENT:
                try:
                    os.mkdir(slug, 0o700, dir_fd=root_fd)
                except OSError as m:
                    if m.errno != errno.EEXIST:
                        raise _project_dir_errno_refusal("create", slug, m)
                continue
            if e.errno in (errno.ELOOP, errno.ENOTDIR):
                continue
            raise _project_dir_errno_refusal("open", slug, e)
    raise ProjectDirOpenError(
        f"could not open project directory {slug!r} relative to the "
        f"artifact root after {_PROJECT_DIR_ATTEMPTS} attempts: a symlink "
        f"was detected at the project directory; the walk refuses to "
        f"follow it")


def _link_into_dir(temp_name, name, project_fd):
    """R19 step 1: hardlink the temporary onto the final name, both
    relative to the project descriptor, follow_symlinks=False.

    A link onto an existing name fails EEXIST without touching it -- the
    atomic refusal (os.rename/os.replace would replace the destination,
    which is precisely what RENAME_NOREPLACE exists to prevent, and this
    Python has no stdlib RENAME_NOREPLACE). follow_symlinks=False means
    that if the temporary's NAME is swapped for a symlink between step 6
    and publish, a copy of the symlink is installed (caught by the lstat
    verify) instead of an attacker's inode being hardlinked into the
    final name.

    Both paths are relative to the SAME project descriptor, so one
    src_dir_fd + one dst_dir_fd bind them; the keyword pair has been in
    the stdlib since Python 3.3 (3.10 docs: "Added the src_dir_fd,
    dst_dir_fd, and follow_symlinks arguments"), so no signature
    branching is needed across the 3.10/3.12 CI legs -- the 3.10 leg
    confirms it runs (R23).
    """
    os.link(temp_name, name, src_dir_fd=project_fd, dst_dir_fd=project_fd,
            follow_symlinks=False)


def _publish(temp_name, name, temp_stat, project_fd):
    """Step 7's publish (R19): hardlink, verify, unlink, fsync.

    Pure stdlib, all dir_fd-relative, no arch-specific code. The
    requirement it meets: atomic publish, EEXIST refusal when name
    exists (a completed artifact is in the way, untouched), the temporary
    consumed, and the final name left as the exact inode the walk created
    and verified at step 6.
    """
    try:
        _link_into_dir(temp_name, name, project_fd)
    except OSError as e:
        if e.errno == errno.EEXIST:
            # A completed artifact is in the way. Distinct message from
            # TempAlreadyExistsError (R9): the operator's choice is
            # different -- a finished dump is not a stray to clear, and
            # the message says so by naming nothing that looks like one.
            raise ArtifactExistsError(
                f"a completed artifact named {name!r} already exists in "
                f"the project directory; it is untouched -- removing it "
                f"destroys the previous run's output, and that is the "
                f"operator's call") from e
        if e.errno == errno.ENOENT:
            # The temporary vanished while it was being written: the
            # other half of the two-writers case, seen from the writer's
            # side. The final name is not created.
            raise TempVanishedError(
                f"the temporary {temp_name!r} vanished while it was being "
                f"written; the final name was not created") from e
        raise ArtifactWriteError(
            f"publish of {name!r} failed: {e.strerror or e}") from e
    final_stat = os.lstat(name, dir_fd=project_fd)
    if stat.S_ISLNK(final_stat.st_mode):
        # Our own link installed a symlink: the temporary's name was
        # swapped for a link between step 6 and publish, and
        # follow_symlinks=False made the swap a copy of the link. Remove
        # the name WE just created (R19 step 2), best effort -- if the
        # removal itself fails, the invariant error below is still the
        # error that matters -- then raise the base error naming what
        # broke.
        try:
            os.unlink(name, dir_fd=project_fd)
        except OSError:
            pass
        raise ArtifactWriteError(
            "publish invariant broken: the final name is a symlink (the "
            "temporary's name was swapped between the step-6 fstat and "
            "the publish); the swapped name has been removed")
    if (not stat.S_ISREG(final_stat.st_mode)
            or final_stat.st_ino != temp_stat.st_ino
            or final_stat.st_dev != temp_stat.st_dev):
        raise ArtifactWriteError(
            "publish invariant broken: the final name is not the regular "
            "file the walk created and verified at step 6 (the inode or "
            "device differs)")
    try:
        os.unlink(temp_name, dir_fd=project_fd)
    except OSError as e:
        if e.errno == errno.ENOENT:
            # The temporary vanished AFTER the link: the final name holds
            # the verified inode, but a second writer removed the
            # temporary under us, so the refusal is the vanished-
            # temporary one -- the same two-writers case one step later
            # than the class's canonical (pre-link) form.
            raise TempVanishedError(
                f"the temporary {temp_name!r} vanished between the publish "
                f"link and its removal; the final name remains") from e
        raise ArtifactWriteError(
            f"could not remove {temp_name!r} after publishing {name!r}: "
            f"{e.strerror or e}") from e
    try:
        os.fsync(project_fd)
    except OSError as e:
        if e.errno == errno.ENOSPC:
            raise DriveFullError(
                f"the drive filled up while fsyncing the project directory "
                f"after publishing {name!r}") from e
        raise ArtifactWriteError(
            f"fsync of the project directory failed after publishing "
            f"{name!r}: {e.strerror or e}") from e


class _ArtifactWriter:
    """The writer open_artifact yields (R20).

    Holds the temporary's descriptor and writes through it with os.write
    -- no buffered layer, so ENOSPC surfaces at write() and is not
    swallowed into one (§5): the operator's error must name the moment it
    was caught. write(b) accepts bytes-like (bytes/bytearray/memoryview),
    writes it all (the loop handles partial writes; EINTR is retried by
    the interpreter), returns the count written, and updates the inline
    SHA-256 and the byte count. The producing tool already has every byte
    in hand, so the digest is nearly free (§5.5).

    The .descriptor attribute does not exist until after a clean exit,
    and that absence is itself contract (P6): a descriptor exists only
    for a file that reached the end, never for an in-flight one.
    """

    def __init__(self, fd, path, media_type, expect_drive_id):
        self._fd = fd
        self._path = path
        self._media_type = media_type
        self._expect_drive_id = expect_drive_id
        self._hash = hashlib.sha256()
        self._bytes_written = 0

    def write(self, data):
        """Write all of data, hash it inline, return the count written.

        Non-bytes input raises TypeError: a programming error, consistent
        with the built-in file API -- the one place a bare builtin is
        right. ENOSPC raises DriveFullError, naming the moment: the
        remedy (make room) is the same wherever the drive filled up.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"write() takes bytes, got {type(data).__name__}")
        view = memoryview(data)
        written = 0
        while written < len(view):
            try:
                n = os.write(self._fd, view[written:])
            except OSError as e:
                if e.errno == errno.ENOSPC:
                    raise DriveFullError(
                        f"the drive filled up mid-write: {written} of "
                        f"{len(view)} bytes of this write landed before "
                        f"ENOSPC; make room and retry") from e
                raise ArtifactWriteError(
                    f"write failed at byte {written} of {self._path}: "
                    f"{e.strerror or e}") from e
            written += n
        self._bytes_written += written
        self._hash.update(view)
        return written

    def _build_descriptor(self):
        """The seven worker-reported fields, in wire order (R16)."""
        return {
            "host": socket.gethostname(),
            "path": self._path,
            "size": self._bytes_written,
            "sha256": self._hash.hexdigest(),
            "hashed_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "media_type": self._media_type,
            "drive_id": self._expect_drive_id,
        }


@contextmanager
def open_artifact(root, slug, name, *, media_type, expect_drive_id,
                  expected_size):
    """Write an artifact under the operator-declared root, and report it.

    The signature is the spec's (§5): a context manager yielding a writer
    with write(b) -- hashing inline -- and, after a clean exit,
    writer.descriptor: the seven worker-reported fields of
    ARTIFACT_DESCRIPTOR_FIELDS.

    The body is the spec's seven-step walk, and the ordering IS the
    security: every step after the first is relative to a held
    descriptor, and no path string is re-opened after being checked
    (re-opening by path is what reintroduces the race this function
    exists to close). Each step, as ordering:

    1. root opened as a directory, FOLLOWING symlinks -- deliberate, as
       in artifact_path: the operator's declaration in workers.yaml is
       the trust anchor for the whole mechanism, and there is nothing
       more trusted to check it against.
    2. the sentinel read O_NOFOLLOW relative to that descriptor and
       compared to expect_drive_id BEFORE anything is created: drive
       identity is established before the first byte is written. This
       subsumes ismount for the case that actually happens (a drive that
       failed to mount leaves an empty directory, where the sentinel is
       absent), but NOT the write-probe: the sentinel is equally readable
       on a read-only mount, which step 5's O_CREAT|O_EXCL catches at the
       moment it matters.
    3. free space checked from the same descriptor (the answer cannot
       come from a different filesystem than the one written to);
       refused only when free < expected_size, strict (R12: equality is
       admitted and the write itself is the arbiter).
    4. the project directory opened O_DIRECTORY|O_NOFOLLOW relative to
       root, created if absent, bounded retry (R21).
    5. the temporary {name}+partial (R11) created O_WRONLY|O_CREAT|
       O_EXCL|O_NOFOLLOW relative to the project descriptor. O_EXCL is
       the refusal a pre-existing file meets -- the planted hardlink, the
       live writer's temporary, the operator's leftover.
    6. the HELD descriptor fstat-ed (never lstat on a path): regular
       file, st_nlink == 1, st_dev equal to root's. Belt-and-braces by
       construction (§5 says so, and says not to attribute a catch to
       it): it is the one check that still refuses if step 5's flags are
       ever loosened.
    7. on a CLEAN EXIT ONLY: bytes_written == expected_size (the spec's
       one defence against a short read that exits cleanly -- a
       truncated dump that left the with block, with a correct hash of
       the truncated bytes), fsync the file, then the publish per R19
       (hardlink with follow_symlinks=False -- the atomic EEXIST refusal;
       lstat-verify the final name is the inode step 6 saw; unlink the
       temporary; fsync the project directory), and only then the
       descriptor.

    Abnormal exit: no size check, no publish, no unlink -- the temporary
    remains with whatever was written, and the body's exception
    propagates unwrapped (the exit raises nothing of its own). The walk
    NEVER unlinks the temporary (R22): it is consumed only by a
    successful publish, and every post-step-5 failure leaves it on the
    drive, visible to ls and to bench_doctor.

    A caller never catches a bare OSError out of this function (R9's
    promise): drive failure modes have names (the R9 subclasses), and
    every other errno is wrapped in the base ArtifactWriteError.
    Path-shaped inputs keep ArtifactPathError (R18) -- raised before any
    filesystem operation, as is the validation of the tool-supplied
    facts (InvalidArtifactInputError) -- and the platform gate (R17)
    runs before both, reading sys.platform at call time: a nonexistent
    root on a non-Linux platform must name the platform, not the missing
    directory.
    """
    # R17: the platform gate FIRST -- before input validation, before the
    # filesystem. A7 accepted Linux-only as the cost of this function;
    # D12 pins the ordering by monkeypatching sys.platform, so it is read
    # here, at call time, not at import.
    if sys.platform != "linux":
        raise NotLinuxError(
            f"open_artifact is Linux-only; sys.platform is "
            f"{sys.platform!r}")

    # R18: input validation, before any filesystem operation. The root's
    # rules are artifact_path's, through the shared helper (stated once,
    # so the lexical entry and the walk refuse the same roots for the
    # same reasons); the type checks stay in this function's own order,
    # as in artifact_path.
    if not isinstance(root, str):
        raise ArtifactPathError(
            f"artifact root must be a str, got {type(root).__name__}")
    if not isinstance(slug, str):
        raise ArtifactPathError(
            f"invalid project slug: must be a str, got {type(slug).__name__}")
    if not isinstance(name, str):
        raise ArtifactPathError(
            f"invalid artifact name: must be a str, got "
            f"{type(name).__name__}")
    declared_root = root  # operator-facing messages name the declared root
    root = _root_rules(root)
    if not SLUG_RE.fullmatch(slug):
        raise ArtifactPathError(
            f"invalid project slug {slug!r}: must match {SLUG_RE.pattern!r}")
    if not _NAME_RE.fullmatch(name):
        raise ArtifactPathError(
            f"invalid artifact name {name!r}: must match "
            f"{_NAME_RE.pattern!r} -- one component, no separators and no "
            f"traversal")
    # The tool-supplied facts (R18): refused, never defaulted. A None
    # expected_size that silently disables the short-read check would
    # publish truncated dumps with correct hashes of the truncated bytes.
    if not isinstance(media_type, str):
        raise InvalidArtifactInputError(
            f"media_type must be a str, got {type(media_type).__name__} -- "
            f"a tool that cannot state its media type has not decided what "
            f"it is writing")
    if isinstance(expected_size, bool):
        raise InvalidArtifactInputError(
            "expected_size must be an int, not a bool: a bool is an int in "
            "Python, and True would declare a one-byte artifact")
    if not isinstance(expected_size, int):
        raise InvalidArtifactInputError(
            f"expected_size must be an int, got "
            f"{type(expected_size).__name__} -- a tool that cannot state "
            f"its size in advance cannot have the short-read check")
    if expected_size < 0:
        raise InvalidArtifactInputError(
            f"expected_size must be >= 0, got {expected_size}")

    temp_name = name + "+partial"
    # R16: the descriptor's path is the NORMALISED DECLARED root plus the
    # two components -- not the resolved target: it is what the
    # operator's scp uses and what the daemon's containment check
    # compares.
    path = os.path.join(root, slug, name)

    # Step 1: root as a directory, following symlinks (the trust anchor).
    # Not openable as a directory -> ArtifactPathError naming the root
    # (the root is a path-shaped input; its family stays the path
    # family, per R9).
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as e:
        raise ArtifactPathError(
            f"artifact root {declared_root!r} cannot be opened as a "
            f"directory: {e.strerror or e}") from e
    try:
        root_stat = os.fstat(root_fd)
    except OSError as e:
        _close_quietly(root_fd)
        raise ArtifactWriteError(
            f"could not stat the artifact root {declared_root!r}: "
            f"{e.strerror or e}") from e
    try:
        # Step 2: drive identity BEFORE anything is created.
        drive_id = _sentinel_drive_id(root_fd, declared_root)
        if drive_id != expect_drive_id:
            raise DriveIdMismatchError(
                f"drive id mismatch: the sentinel {SENTINEL_NAME} at "
                f"{declared_root!r} carries {drive_id!r}, but "
                f"expect_drive_id is {expect_drive_id!r} -- which stick is "
                f"plugged in?")
        # Step 3: free space from the same descriptor (R12: strict <).
        try:
            vfs = os.fstatvfs(root_fd)
        except OSError as e:
            raise ArtifactWriteError(
                f"could not read the free space of {declared_root!r}: "
                f"{e.strerror or e}") from e
        free = vfs.f_bavail * vfs.f_frsize
        if free < expected_size:
            raise DriveFullError(
                f"the drive is full: {free} bytes free at "
                f"{declared_root!r}, but {expected_size} are required")
        # Step 4: the project directory, O_NOFOLLOW, bounded retry.
        project_fd = _open_project_dir(root_fd, slug)
        try:
            # Step 5: the temporary, O_EXCL -- the refusal a pre-existing
            # file meets. On a read-only mount the O_CREAT fails with
            # EROFS before any bytes are written: the spec's write-probe,
            # done at the moment it matters.
            try:
                temp_fd = os.open(
                    temp_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600, dir_fd=project_fd)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    raise TempAlreadyExistsError(
                        f"a file named {temp_name!r} already exists at the "
                        f"temporary's path; remove it if it is a leftover, "
                        f"then retry -- nothing here can tell a leftover "
                        f"from a live writer, so it is left in place") from e
                if e.errno == errno.EROFS:
                    raise DriveReadOnlyError(
                        f"the artifact root is read-only: creating "
                        f"{temp_name!r} failed (EROFS); ext4 remounts "
                        f"read-only when it detects an error, so check "
                        f"the drive") from e
                if e.errno == errno.ENOSPC:
                    raise DriveFullError(
                        f"no space left on the artifact root: creating "
                        f"{temp_name!r} failed (ENOSPC)") from e
                raise ArtifactWriteError(
                    f"creating the temporary {temp_name!r} failed: "
                    f"{e.strerror or e}") from e
            try:
                # Step 6: the HELD descriptor, never lstat on a path.
                temp_stat = os.fstat(temp_fd)
                if not stat.S_ISREG(temp_stat.st_mode):
                    raise ArtifactWriteError(
                        f"step-6 invariant broken: {temp_name!r} is not a "
                        f"regular file (mode {temp_stat.st_mode:o})")
                if temp_stat.st_nlink != 1:
                    raise ArtifactWriteError(
                        f"step-6 invariant broken: {temp_name!r} has "
                        f"{temp_stat.st_nlink} links, expected 1")
                if temp_stat.st_dev != root_stat.st_dev:
                    raise ArtifactWriteError(
                        f"step-6 invariant broken: {temp_name!r} is on "
                        f"device {temp_stat.st_dev}, the root is on "
                        f"{root_stat.st_dev}")
                writer = _ArtifactWriter(temp_fd, path, media_type,
                                         expect_drive_id)
                try:
                    yield writer
                except BaseException:
                    # Abnormal exit: no size check, no publish, no
                    # unlink. The re-raise is required -- a contextmanager
                    # that lets the body's exception be swallowed reports
                    # the error as handled -- and it is all this exit
                    # does: the temporary remains (R22), and the original
                    # propagates unwrapped.
                    raise
                # Step 7, on a clean exit ONLY.
                if writer._bytes_written != expected_size:
                    raise SizeMismatchError(
                        f"expected {expected_size} bytes but wrote "
                        f"{writer._bytes_written}: the temporary "
                        f"{temp_name!r} is kept, unpublished, for "
                        f"inspection")
                try:
                    os.fsync(temp_fd)
                except OSError as e:
                    if e.errno == errno.ENOSPC:
                        raise DriveFullError(
                            f"the drive filled up while fsyncing "
                            f"{temp_name!r}") from e
                    raise ArtifactWriteError(
                        f"fsync of {temp_name!r} failed: "
                        f"{e.strerror or e}") from e
                _publish(temp_name, name, temp_stat, project_fd)
                # R16: a descriptor exists only for a file that reached
                # the end -- set LAST, after the publish.
                writer.descriptor = writer._build_descriptor()
            finally:
                _close_quietly(temp_fd)
        finally:
            _close_quietly(project_fd)
    finally:
        _close_quietly(root_fd)
