"""Packs a release tarball that is the same bytes every time for the same inputs.

Usage: python3 scripts/pack.py <out.tar.gz> <folder name in the archive> <file>...
Every entry gets the time SOURCE_DATE_EPOCH (0 when unset), owner 0:0 with no names, and mode 0755 for the
binary or 0644 otherwise; entries are sorted and gzip carries no name or time. `tar` on macOS and Linux each
stamp their own times and owners, which is why this is not a tar command. Standard library only.
"""
import gzip, io, os, sys, tarfile


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    out, folder, files = sys.argv[1], sys.argv[2], sorted(sys.argv[3:], key=os.path.basename)
    when = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        def add(name, data, mode, kind=tarfile.REGTYPE):
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = kind, mode, when
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.size = len(data) if data is not None else 0
            tar.addfile(info, io.BytesIO(data) if data is not None else None)

        add(folder, None, 0o755, tarfile.DIRTYPE)
        for path in files:
            name = os.path.basename(path)
            with open(path, "rb") as f:
                data = f.read()
            add(f"{folder}/{name}", data, 0o755 if os.access(path, os.X_OK) and name == "enterplace" else 0o644)
    with open(out, "wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())


if __name__ == "__main__":
    main()
