import pytest

from pare_worker_kit import (PRODUCES_ARTIFACT, PRODUCES_META_KEY,
                             PRODUCES_RESULT, VALID_PRODUCES)


def test_the_meta_key_is_stable_protocol():
    """agent_core states this same literal independently; a guard test in each
    suite keeps them equal. Changing it is a wire-breaking change."""
    assert PRODUCES_META_KEY == "agent_core/produces"


def test_result_is_the_default_value():
    """A tool that says nothing produces a result. Only an explicit
    declaration opts into the artifact path."""
    assert PRODUCES_RESULT == "result"
    assert PRODUCES_ARTIFACT == "artifact"
    assert VALID_PRODUCES == ("result", "artifact")


def test_it_agrees_with_agent_cores():
    ac = pytest.importorskip(
        "agent_core.workers.artifacts",
        reason="agent_core is not installed here; the daemon-side half of "
               "this check runs in agent_core's own suite")
    assert ac.PRODUCES_META_KEY == PRODUCES_META_KEY
    assert ac.VALID_PRODUCES == VALID_PRODUCES


def test_the_slug_rule_agrees_with_agent_cores():
    """The kit states ArcticBase's slug rule independently, because the two
    packages are separately installed and never share a Python environment.
    If they drift, a slug the daemon accepts is one the worker refuses, with
    no useful error anywhere.

    Compare flags as well as the pattern text: two identical pattern strings
    compiled with different flags (re.IGNORECASE, re.ASCII, re.UNICODE) are
    different rules, so `.pattern` equality alone would not pin agreement.
    """
    from pare_worker_kit.artifacts import SLUG_RE
    ac = pytest.importorskip(
        "agent_core.workers.artifacts",
        reason="agent_core is not installed here; the daemon-side half of "
               "this check runs in agent_core's own suite")
    assert SLUG_RE.pattern == ac.SLUG_RE.pattern
    assert SLUG_RE.flags == ac.SLUG_RE.flags


# Task 8: worker-side containment
import os

from pare_worker_kit import ArtifactPathError, artifact_path


def test_a_normal_name_lands_under_root_and_slug(tmp_path):
    root = str(tmp_path)
    out = artifact_path(root, "router-b", "fw-0001.bin")
    assert out == os.path.join(root, "router-b", "fw-0001.bin")


@pytest.mark.parametrize("bad", ["../escape", "a/../../escape", "/etc/shadow",
                                 "sub/dir/file", "..", "."])
def test_a_name_that_escapes_is_refused(bad):
    """The worker constructs the path; the daemon supplies only a slug. A name
    containing a separator or a traversal is a bug or an attack, never a
    legitimate artifact name."""
    with pytest.raises(ArtifactPathError):
        artifact_path("/mnt/bench-store", "router-b", bad)


@pytest.mark.parametrize("bad", ["../other", "a/b", "/abs", ""])
def test_a_slug_that_escapes_is_refused(bad):
    with pytest.raises(ArtifactPathError):
        artifact_path("/mnt/bench-store", bad, "fw.bin")


def test_a_symlinked_project_directory_is_refused(tmp_path):
    """The case the daemon cannot check. A slug directory that is a symlink
    pointing outside the root would put every artifact for that project
    somewhere the operator did not authorise -- and `scp` follows symlinks."""
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "router-b").symlink_to(outside)
    with pytest.raises(ArtifactPathError, match="symlink"):
        artifact_path(str(root), "router-b", "fw.bin")


def test_an_existing_symlinked_artifact_is_refused(tmp_path):
    """A descriptor naming /etc/shadow via a symlink inside the root would turn
    the worker into a file-exfiltration primitive against its own host, because
    the operator will later act on that path."""
    root = tmp_path / "root"
    (root / "router-b").mkdir(parents=True)
    (root / "router-b" / "fw.bin").symlink_to("/etc/hostname")
    with pytest.raises(ArtifactPathError, match="symlink"):
        artifact_path(str(root), "router-b", "fw.bin")


def test_a_relative_root_is_refused():
    with pytest.raises(ArtifactPathError, match="absolute"):
        artifact_path("bench-store", "router-b", "fw.bin")


# --- adversarial probes, promoted to tests ---

@pytest.mark.parametrize("bad", [None, 123, True, b"router-b", ("router-b",)])
def test_a_non_string_slug_is_refused_as_an_artifact_path_error(bad):
    """A caller passing the wrong type must get the module's own error, not a
    TypeError from inside `re`. Callers catch ArtifactPathError; a TypeError
    escaping this function would crash a worker's tool handler instead of
    being reported as a refused path."""
    with pytest.raises(ArtifactPathError):
        artifact_path("/mnt/bench-store", bad, "fw.bin")


@pytest.mark.parametrize("bad", [None, 123, True, b"fw.bin", ("fw.bin",)])
def test_a_non_string_name_is_refused_as_an_artifact_path_error(bad):
    with pytest.raises(ArtifactPathError):
        artifact_path("/mnt/bench-store", "router-b", bad)


@pytest.mark.parametrize("bad", [None, 123, True, b"/mnt/bench-store"])
def test_a_non_string_root_is_refused_as_an_artifact_path_error(bad):
    """`root` arrives from workers.yaml, which is YAML: an operator writing
    `artifact_root: 1234` gets an int, not a string."""
    with pytest.raises(ArtifactPathError):
        artifact_path(bad, "router-b", "fw.bin")


@pytest.mark.parametrize("bad", [
    "fw\x00.bin",          # NUL truncates the path at the OS boundary
    "fw\x00/../../etc",
    "fw.bin\n",            # a trailing newline: why fullmatch, not match+'$'
    "fw\n.bin",
    "fw bin",
    "-rf",                 # a leading dash is argument injection into scp/tar
    "--checkpoint-action=exec=sh",
    ".hidden",
    "fw.bin/",
])
def test_a_name_with_a_hostile_character_is_refused(bad):
    with pytest.raises(ArtifactPathError, match="artifact name"):
        artifact_path("/mnt/bench-store", "router-b", bad)


@pytest.mark.parametrize("bad", [
    "ｒouter",         # FULLWIDTH LATIN SMALL LETTER R -- not ASCII 'r'
    "Krouter",        # KELVIN SIGN, casefolds to 'k'
    "İrouter",        # LATIN CAPITAL I WITH DOT ABOVE, casefolds to 'i̇'
    "rоuter",         # CYRILLIC SMALL O, a homoglyph of 'o'
])
def test_a_unicode_lookalike_slug_is_refused(bad):
    """The alphabet is ASCII by construction, so nothing that merely
    normalises or case-folds onto an allowed character is accepted."""
    with pytest.raises(ArtifactPathError, match="slug"):
        artifact_path("/mnt/bench-store", bad, "fw.bin")


def test_a_name_longer_than_the_cap_is_refused():
    """Relationship, not a literal: whatever the cap is, one past it fails and
    exactly it passes. This survives a legitimate change to the cap."""
    from pare_worker_kit.artifacts import _NAME_MAX
    ok = "a" * _NAME_MAX
    assert artifact_path("/mnt/bench-store", "router-b", ok).endswith(ok)
    with pytest.raises(ArtifactPathError, match="artifact name"):
        artifact_path("/mnt/bench-store", "router-b", "a" * (_NAME_MAX + 1))


def test_a_slug_longer_than_the_cap_is_refused():
    from pare_worker_kit.artifacts import _SLUG_MAX
    ok = "a" * _SLUG_MAX
    assert artifact_path("/mnt/bench-store", ok, "fw.bin").endswith("fw.bin")
    with pytest.raises(ArtifactPathError, match="slug"):
        artifact_path("/mnt/bench-store", "a" * (_SLUG_MAX + 1), "fw.bin")


def test_an_absolute_root_containing_a_traversal_is_refused(tmp_path):
    """`/mnt/store/../../etc` is absolute and passes a startswith('/') test,
    but it does not name what the operator wrote down. Refuse it at the door
    rather than silently writing somewhere else."""
    with pytest.raises(ArtifactPathError, match="normalised|absolute"):
        artifact_path("/mnt/bench-store/../../etc", "router-b", "fw.bin")


def test_a_symlink_inside_the_root_is_still_refused(tmp_path):
    """Deliberately fail closed. A symlink whose target happens to be inside
    the root is legitimate today and a redirection tomorrow; `artifact_path`
    returns a path and never holds the file open, so it cannot bind the
    target it checked to the one that gets written."""
    root = tmp_path / "root"
    (root / "router-b").mkdir(parents=True)
    (root / "router-b" / "real.bin").write_bytes(b"x")
    (root / "router-b" / "fw.bin").symlink_to(root / "router-b" / "real.bin")
    with pytest.raises(ArtifactPathError, match="symlink"):
        artifact_path(str(root), "router-b", "fw.bin")


def test_a_dangling_symlink_at_the_artifact_path_is_refused(tmp_path):
    """lexists, not exists: a symlink to a file that does not exist yet is
    still a redirection, and `exists()` reports False for it."""
    root = tmp_path / "root"
    (root / "router-b").mkdir(parents=True)
    (root / "router-b" / "fw.bin").symlink_to(tmp_path / "nope")
    with pytest.raises(ArtifactPathError, match="symlink"):
        artifact_path(str(root), "router-b", "fw.bin")


def test_a_real_directory_and_file_are_accepted(tmp_path):
    """The refusals above must not be refusing everything."""
    root = tmp_path / "root"
    (root / "router-b").mkdir(parents=True)
    (root / "router-b" / "fw.bin").write_bytes(b"x")
    out = artifact_path(str(root), "router-b", "fw.bin")
    assert out == str(root / "router-b" / "fw.bin")


def test_the_returned_path_is_absolute_and_under_the_root(tmp_path):
    out = artifact_path(str(tmp_path), "router-b", "fw.bin")
    assert os.path.isabs(out)
    assert os.path.commonpath([out, str(tmp_path)]) == str(tmp_path)


def test_the_containment_backstop_is_not_dead_code():
    """`//` is the one input that reaches the final commonpath check: POSIX
    keeps exactly two leading slashes through normpath, but commonpath
    collapses them, so root and prefix disagree and the path is refused.

    Two things are pinned here. The behaviour -- an ambiguous root fails
    closed. And the fact that the backstop is reachable at all, so it cannot
    be deleted as unreachable by someone who checked only the happy path.
    """
    with pytest.raises(ArtifactPathError, match="escapes artifact root"):
        artifact_path("//", "router-b", "fw.bin")


@pytest.mark.parametrize("root,expected_base", [
    ("/mnt/store/", "/mnt/store"),
    ("/mnt//store", "/mnt/store"),
    ("/mnt/./store", "/mnt/store"),
    ("/mnt/store/.", "/mnt/store"),
])
def test_a_sloppy_but_honest_root_is_normalised_not_refused(root, expected_base):
    """An operator writing a trailing slash in workers.yaml has not made a
    mistake worth failing a hardware run over."""
    assert artifact_path(root, "router-b", "fw.bin") == \
        os.path.join(expected_base, "router-b", "fw.bin")
