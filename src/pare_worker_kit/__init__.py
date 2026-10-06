"""The server half of a PARE worker.

Deliberately small, and depends on `mcp` alone: a worker runs on whatever
machine owns its hardware, which may be a Raspberry Pi.
"""
from pare_worker_kit.artifacts import (ARTIFACT_DESCRIPTOR_FIELDS,
                                        PRODUCES_ARTIFACT, PRODUCES_META_KEY,
                                        PRODUCES_RESULT, RESERVED_DRIVE_ID_ARG,
                                        RESERVED_SLUG_ARG, SENTINEL_NAME,
                                        VALID_PRODUCES, ArtifactExistsError,
                                        ArtifactPathError, ArtifactWriteError,
                                        DriveFullError, DriveIdMismatchError,
                                        DriveNotMountedError,
                                        DriveReadOnlyError, FileTooLargeError,
                                        InvalidArtifactInputError,
                                        NotLinuxError, ProjectDirOpenError,
                                        SizeMismatchError,
                                        TempAlreadyExistsError,
                                        TempVanishedError, artifact_path,
                                        open_artifact)
from pare_worker_kit.risk import RISK_TIER_META_KEY, VALID_RISK_TIERS
from pare_worker_kit.serve import (WorkerServeError, resolve_bind_address,
                                    run_worker, stamp_version)

__all__ = ["ARTIFACT_DESCRIPTOR_FIELDS", "PRODUCES_ARTIFACT",
            "PRODUCES_META_KEY", "PRODUCES_RESULT", "RESERVED_DRIVE_ID_ARG",
            "RESERVED_SLUG_ARG", "SENTINEL_NAME", "VALID_PRODUCES",
            "ArtifactExistsError", "ArtifactPathError", "ArtifactWriteError",
            "DriveFullError", "DriveIdMismatchError", "DriveNotMountedError",
            "DriveReadOnlyError", "FileTooLargeError",
            "InvalidArtifactInputError", "NotLinuxError",
            "ProjectDirOpenError", "SizeMismatchError",
            "TempAlreadyExistsError", "TempVanishedError", "artifact_path",
            "RISK_TIER_META_KEY", "VALID_RISK_TIERS", "open_artifact",
            "run_worker", "resolve_bind_address", "stamp_version",
            "WorkerServeError"]
__version__ = "0.3.0"
