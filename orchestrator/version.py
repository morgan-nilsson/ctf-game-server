"""Content digest of the installed tree.

ONE implementation, used by both install.sh (to record what it installed) and
ctfctl (to check what is running). They were originally two copies that sorted
their file lists differently, which made every install report DRIFT against
itself — the hash is order-dependent, so "same files" is not enough; the
traversal has to be identical too.

  python3 -m orchestrator.version            # digest of the tree it lives in
  python3 -m orchestrator.version --marker   # the .version file's contents
"""
from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

# The code that actually runs the game. Docs, config and tests are excluded:
# editing a doc should not read as a tampered install.
DIRS = ("bin", "orchestrator", "topology")


def tree_digest(root: str | Path | None = None) -> str:
    root = Path(root) if root else Path(__file__).resolve().parent.parent
    files = []
    for name in DIRS:
        directory = root / name
        if directory.is_dir():
            files.extend(p for p in directory.rglob("*")
                         if p.is_file() and "__pycache__" not in p.parts)
    digest = hashlib.sha256()
    # One global sort by path relative to the root, so the order cannot depend
    # on how the caller walks the directories.
    for path in sorted(files, key=lambda p: str(p.relative_to(root))):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent.parent
    digest = tree_digest(root)
    if "--marker" in argv:
        print(f"installed={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
        print(f"digest={digest}")
    else:
        print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
