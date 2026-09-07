"""What a tool produces, and where a worker is allowed to write it.

The daemon routes on this declaration rather than on the model's choice of
tool: a tool marked `artifact` returns a DESCRIPTOR of a file it wrote, never
the file's contents. Without it, a two-gigabyte firmware dump would cross the
network as one tool result.
"""
import os
import re

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
