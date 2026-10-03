"""What a tool produces, and where a worker is allowed to write it.

The daemon routes on this declaration rather than on the model's choice of
tool: a tool marked `artifact` returns a DESCRIPTOR of a file it wrote, never
the file's contents. Without it, a two-gigabyte firmware dump would cross the
network as one tool result.
"""
import hashlib
import os
import re
import socket
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

    if not root.startswith("/"):
        raise ArtifactPathError(f"artifact root must be absolute, got {root!r}")
    # A `..` inside the root is refused even though the root is trusted,
    # because the containment check below is LEXICAL and the kernel's is not:
    # for `/a/b/../c` where `b` is a symlink to `/x/y`, normpath says `/a/c`
    # and the kernel says `/x/c`. Accepting it would mean checking containment
    # against a directory that is not the one written to.
    if ".." in root.split("/"):
        raise ArtifactPathError(
            f"artifact root must be normalised, got {root!r}: a '..' component "
            f"does not name the directory the operator declared")
    # Stated as a PROPERTY rather than as a slash count, because the property
    # is precisely what the backstop at the end of this function needs, and it
    # tracks the stdlib automatically if these functions ever change: a root
    # that is not a `commonpath` prefix of ITSELF cannot have containment
    # checked against it, and every comparison against it is meaningless.
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
    # for this whole function -- there is nothing more trusted to check it
    # against, and an operator who points the root at a symlinked mount has
    # made a decision, not a mistake.
    root = base

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


class _ArtifactWriter:
    """The writer open_artifact yields.

    Deliberately minimal in the baseline this ships in: write() delegates
    to the open file object and hashes inline -- the producing tool
    already has every byte in hand, so the digest is nearly free. The
    .descriptor attribute does not exist until after a clean exit, and
    that absence is itself contract (P6): a descriptor exists only for a
    file that reached the end, never for an in-flight one.
    """

    def __init__(self, handle, path, media_type, expect_drive_id):
        self._handle = handle
        self._path = path
        self._media_type = media_type
        self._expect_drive_id = expect_drive_id
        self._hash = hashlib.sha256()
        self._bytes_written = 0

    def write(self, data):
        """Write data, hash it inline, return the count written.

        Non-bytes input raises TypeError from the file object: a
        programming error, consistent with the built-in file API -- the
        one place a bare builtin is right.
        """
        written = self._handle.write(data)
        self._bytes_written += written
        self._hash.update(data[:written])
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

    THIS IS THE RED-STATE BASELINE (plan R5), COMMITTED AS-IS. The body
    is deliberately the "artifact_path-only implementation" the spec's
    test rule names: the lexical containment check, then a plain
    write-mode open of the final path. There is no temporary, no
    sentinel check, no platform gate, no free-space check, no size
    check, no fsync, and no atomic publish; raw OSError propagates
    unwrapped; and the R9 classes above and SENTINEL_NAME are declared
    (the tests import them) but this body raises none of them. The
    discriminating suite (tests/test_open_artifact.py) is verified RED
    against exactly this code, per discriminator with each red's reason
    recorded in the ledger; the red set is the contract that the walk
    which replaces this body (Task 3) must turn green.

    Do not read artifact_path's docstring above as a description of this
    function's safety: this baseline has precisely the weaknesses the
    suite is red for. It opens the final path it was handed, so a
    persistent symlink at the project directory is caught only by the
    lexical check (the right result, the wrong mechanism -- that is D1),
    a missing sentinel is not checked at all (D3), and a short read that
    exits cleanly publishes a correct hash of the truncated bytes (D6).
    """
    path = artifact_path(root, slug, name)
    handle = open(path, "wb")
    writer = _ArtifactWriter(handle, path, media_type, expect_drive_id)
    try:
        yield writer
    except BaseException:
        # Abnormal exit: close the file and re-raise the body's exception
        # unwrapped -- the exit raises nothing of its own, and no
        # descriptor is ever set on this path. A close that fails (say,
        # flushing into an ENOSPC the body already hit) must not mask the
        # body's exception, so the close is guarded.
        try:
            handle.close()
        except OSError:
            pass
        raise
    # Clean exit: close, then set the descriptor. No size check -- the
    # baseline's most conspicuous absence, D6 is red for it -- and
    # expected_size is accepted but unused here, on purpose: D16's
    # discriminators are red for the missing validation.
    handle.close()
    writer.descriptor = writer._build_descriptor()
