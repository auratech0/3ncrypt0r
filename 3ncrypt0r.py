
#!/usr/bin/env python3
"""
3ncrypt0r - encrypted file vault.
 
File layout:
    0    8    magic b"3NCRYPT0"
    8    1    format version
    9    1    kdf id (1 = scrypt, 2 = argon2id)
    10   16   kdf params, four big-endian uint32
    26   32   salt
    58   12   dek nonce      | zeroed by kill / kill-key
    70   64   wrapped dek    |
    134  4    chunk size
    138  ..   chunks, each [uint32 length][ciphertext]
"""
 
from __future__ import annotations
 
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
 
APP = "3ncrypt0r"
RELEASE = "2.0.0"
REQUIREMENTS = ["cryptography>=44", "argon2-cffi>=23"]
 
 
def data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return base / APP
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / APP
 
 
def _dep_failure(detail: str = "") -> None:
    print(f"{APP}: could not install dependencies." + (f" {detail}" if detail else ""),
          file=sys.stderr)
    print(f"Install them manually: {sys.executable} -m pip install "
          + " ".join(f'"{r}"' for r in REQUIREMENTS), file=sys.stderr)
    raise SystemExit(1)
 
 
def _bootstrap() -> None:
    try:
        import cryptography  # noqa: F401
        return
    except ImportError:
        pass
    if os.environ.get("N3_NO_AUTO_INSTALL") or os.environ.get("N3_BOOTSTRAPPED"):
        _dep_failure()
 
    import venv
 
    root = data_dir() / "runtime"
    python = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    print(f"{APP}: first run, installing dependencies into {root}", file=sys.stderr)
    try:
        if not python.exists():
            venv.EnvBuilder(with_pip=True, clear=True).create(str(root))
        subprocess.check_call(
            [str(python), "-m", "pip", "install", "--quiet",
             "--disable-pip-version-check", *REQUIREMENTS])
    except (OSError, subprocess.CalledProcessError) as exc:
        _dep_failure(str(exc))
 
    env = {**os.environ, "N3_BOOTSTRAPPED": "1"}
    script = os.path.abspath(__file__)
    os.execve(str(python), [str(python), script, *sys.argv[1:]], env)
 
 
_bootstrap()
 
from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import (  # noqa: E402
    AESGCM, ChaCha20Poly1305)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: E402
 
try:
    from argon2.low_level import Type as Argon2Type, hash_secret_raw
except ImportError:
    hash_secret_raw = None
 
MAGIC = b"3NCRYPT0"
FORMAT_VERSION = 2
LEGACY_MAGIC = b"ENCVAULT"
 
KDF_SCRYPT, KDF_ARGON2ID = 1, 2
SCRYPT_PARAMS = (17, 8, 1, 0)        # log2(N)=17 -> 128 MiB
ARGON2_PARAMS = (3, 131072, 4, 0)    # 3 passes, 128 MiB, 4 lanes
 
SALT_LEN, NONCE_LEN, KEY_LEN = 32, 12, 32
OFF_DEK_NONCE, OFF_WRAPPED, OFF_CHUNK_SIZE = 58, 70, 134
HEADER_LEN = 138
WRAPPED_LEN = KEY_LEN + 32
CHUNK_SIZE = 1 << 20
FRAME_OVERHEAD = 36
 
 
def die(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)
 
 
def master_key_path() -> Path:
    return data_dir() / "master.key"
 
 
def registry_path() -> Path:
    return data_dir() / "vault.json"
 
 
def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
 
 
def confirm(prompt: str, expected: str) -> bool:
    try:
        return input(prompt).strip() == expected
    except (EOFError, KeyboardInterrupt):
        print()
        return False
 
 
def load_master_key() -> bytes:
    try:
        key = master_key_path().read_bytes()
    except FileNotFoundError:
        die(f"Master key not found. Run `{APP} init` first.")
    if len(key) != KEY_LEN:
        die(f"Master key is corrupt (expected {KEY_LEN} bytes, found {len(key)}).")
    return key
 
 
def load_registry() -> dict:
    try:
        reg = json.loads(registry_path().read_text("utf-8"))
    except FileNotFoundError:
        return {"version": 2, "files": {}}
    except (json.JSONDecodeError, UnicodeDecodeError):
        die(f"Registry is corrupt. Encrypted files are unaffected; delete "
            f"{registry_path()} to rebuild the index.")
    reg.setdefault("files", {})
    return reg
 
 
def save_registry(reg: dict) -> None:
    atomic_write(registry_path(), json.dumps(reg, indent=2).encode("utf-8"))
 
 
def stretch(kdf_id: int, params: tuple, password: bytes, salt: bytes) -> bytes:
    if kdf_id == KDF_ARGON2ID:
        if hash_secret_raw is None:
            die("This file was sealed with Argon2id. Install argon2-cffi to open it.")
        t, m, p, _ = params
        return hash_secret_raw(secret=password, salt=salt, time_cost=t, memory_cost=m,
                               parallelism=p, hash_len=KEY_LEN, type=Argon2Type.ID)
    if kdf_id == KDF_SCRYPT:
        logn, r, p, _ = params
        return Scrypt(salt=salt, length=KEY_LEN, n=1 << logn, r=r, p=p).derive(password)
    die(f"Unsupported key derivation id {kdf_id}.")
 
 
def preferred_kdf() -> tuple:
    if hash_secret_raw is not None:
        return KDF_ARGON2ID, ARGON2_PARAMS
    return KDF_SCRYPT, SCRYPT_PARAMS
 
 
def split(secret: bytes, salt: bytes | None, info: bytes) -> tuple:
    block = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN * 2,
                 salt=salt, info=info).derive(secret)
    return AESGCM(block[:KEY_LEN]), ChaCha20Poly1305(block[KEY_LEN:])
 
 
def wrapping_ciphers(master_key: bytes, password: bytes, salt: bytes,
                     kdf_id: int, params: tuple) -> tuple:
    return split(master_key + stretch(kdf_id, params, password, salt),
                 salt, b"3ncrypt0r:v2:kek")
 
 
def data_ciphers(dek: bytes) -> tuple:
    return split(dek, None, b"3ncrypt0r:v2:dek")
 
 
def seal(aes, cha, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    return cha.encrypt(nonce, aes.encrypt(nonce, data, aad), aad)
 
 
def unseal(aes, cha, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    return aes.decrypt(nonce, cha.decrypt(nonce, data, aad), aad)
 
 
def chunk_nonce(index: int) -> bytes:
    return struct.pack(">4xQ", index)
 
 
def chunk_aad(digest: bytes, index: int, final: bool) -> bytes:
    return digest + struct.pack(">QB", index, final)
 
 
def read_password(twice: bool) -> bytes:
    try:
        pw = getpass("Enter password for this file: " if twice else "Enter password: ")
        if twice:
            if not pw:
                die("Empty password. Aborted.")
            if pw != getpass("Confirm password: "):
                die("Passwords do not match. Aborted.")
            if len(pw) < 12:
                print("Note: short password. The master key is the only other thing "
                      "protecting this file.", file=sys.stderr)
        return pw.encode("utf-8")
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(1)
 
 
def parse_header(raw: bytes, path: Path) -> tuple:
    if len(raw) >= 8 and raw[:8] == LEGACY_MAGIC:
        die(f"{path} uses the v1 format. Decrypt it with the old build first.")
    if len(raw) < HEADER_LEN or raw[:8] != MAGIC:
        die(f"Not a {APP} file: {path}")
    if raw[8] != FORMAT_VERSION:
        die(f"Unsupported format version {raw[8]}: {path}")
    kdf_id = raw[9]
    params = struct.unpack(">4I", raw[10:26])
    salt = raw[26:58]
    dek_nonce = raw[OFF_DEK_NONCE:OFF_WRAPPED]
    wrapped = raw[OFF_WRAPPED:OFF_CHUNK_SIZE]
    chunk_size = struct.unpack(">I", raw[OFF_CHUNK_SIZE:HEADER_LEN])[0]
    if not 0 < chunk_size <= 1 << 26:
        die(f"Implausible chunk size in header: {path}")
    return kdf_id, params, salt, dek_nonce, wrapped, chunk_size
 
 
def key_destroyed(raw_header: bytes) -> bool:
    return raw_header[OFF_DEK_NONCE:OFF_CHUNK_SIZE] == b"\x00" * (
        OFF_CHUNK_SIZE - OFF_DEK_NONCE)
 
 
def shred_key(path: Path) -> bool:
    try:
        with open(path, "r+b") as fh:
            if fh.read(8) != MAGIC:
                return False
            fh.seek(OFF_DEK_NONCE)
            fh.write(b"\x00" * (OFF_CHUNK_SIZE - OFF_DEK_NONCE))
            fh.flush()
            os.fsync(fh.fileno())
        return True
    except FileNotFoundError:
        return False
 
 
def cmd_init(args) -> None:
    path = master_key_path()
    if path.exists():
        die(f"Vault already initialized at {path}. Use `{APP} kill-all` to destroy it.")
    print("Initializing vault...")
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)
    atomic_write(path, os.urandom(KEY_LEN))
    kdf_id, _ = preferred_kdf()
    print(f"Master key generated at {path}")
    print(f"Key derivation: {'Argon2id' if kdf_id == KDF_ARGON2ID else 'scrypt'}")
    print("Keep this file safe. If lost, encrypted files cannot be recovered.")
    if sys.platform == "win32":
        print("Note: permissions are not restricted on Windows. Anyone with access "
              "to your user profile can read the master key.")
 
 
def cmd_encrypt(args) -> None:
    src = Path(args.file)
    if not src.is_file():
        die(f"File not found: {src}")
    out = Path(args.output) if args.output else src.with_name(src.name + ".enc")
    if out.exists() and not args.force:
        die(f"Refusing to overwrite: {out}. Use --force.")
 
    master_key = load_master_key()
    password = read_password(twice=True)
    kdf_id, params = preferred_kdf()
 
    salt = os.urandom(SALT_LEN)
    dek_nonce = os.urandom(NONCE_LEN)
    dek = os.urandom(KEY_LEN)
 
    prefix = (MAGIC + bytes([FORMAT_VERSION, kdf_id]) + struct.pack(">4I", *params)
              + salt)
    kek_aes, kek_cha = wrapping_ciphers(master_key, password, salt, kdf_id, params)
    wrapped = seal(kek_aes, kek_cha, dek_nonce, dek, prefix)
 
    header = prefix + dek_nonce + wrapped + struct.pack(">I", CHUNK_SIZE)
    assert len(header) == HEADER_LEN, len(header)
    digest = hashlib.sha256(header).digest()
    aes, cha = data_ciphers(dek)
 
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(out.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fout, src.open("rb") as fin:
            fout.write(header)
            index, buf = 0, fin.read(CHUNK_SIZE)
            while True:
                nxt = fin.read(CHUNK_SIZE)
                final = not nxt
                frame = seal(aes, cha, chunk_nonce(index), buf,
                             chunk_aad(digest, index, final))
                fout.write(struct.pack(">I", len(frame)) + frame)
                if final:
                    break
                buf, index = nxt, index + 1
            fout.flush()
            os.fsync(fout.fileno())
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
 
    reg = load_registry()
    reg["files"][str(out.resolve())] = {
        "original_name": src.name,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "size": src.stat().st_size,
    }
    save_registry(reg)
 
    print(f"File encrypted: {out}")
    if args.remove_original:
        src.unlink()
        print(f"Original deleted: {src}")
        print("Note: deletion does not scrub the data from disk. On SSDs and on "
              "journaling or copy-on-write filesystems, remnants can survive.")
    else:
        print("Original file still exists. Delete it if you want.")
 
 
def cmd_decrypt(args) -> None:
    src = Path(args.file)
    if not src.is_file():
        die(f"File not found: {src}")
    size = src.stat().st_size
    with src.open("rb") as fh:
        header = fh.read(HEADER_LEN)
    kdf_id, params, salt, dek_nonce, wrapped, chunk_size = parse_header(header, src)
    if key_destroyed(header):
        die(f"Key destroyed. {src} can never be decrypted.")
 
    if args.output:
        out = Path(args.output)
    elif src.suffix == ".enc":
        out = src.with_suffix("")
    else:
        out = src.with_name(src.name + ".decrypted")
    if out.exists() and not args.force:
        die(f"Refusing to overwrite: {out}. Use --force.")
 
    master_key = load_master_key()
    password = read_password(twice=False)
    kek_aes, kek_cha = wrapping_ciphers(master_key, password, salt, kdf_id, params)
    try:
        dek = unseal(kek_aes, kek_cha, dek_nonce, wrapped, header[:OFF_DEK_NONCE])
    except InvalidTag:
        die("Decryption failed. Wrong password, wrong master key, or corrupted file.")
 
    digest = hashlib.sha256(header).digest()
    aes, cha = data_ciphers(dek)
 
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(out.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fout, src.open("rb") as fin:
            fin.seek(HEADER_LEN)
            index = 0
            while True:
                raw_len = fin.read(4)
                if len(raw_len) != 4:
                    die(f"Truncated file: {src}")
                length = struct.unpack(">I", raw_len)[0]
                if not 0 < length <= chunk_size + FRAME_OVERHEAD:
                    die(f"Corrupted file: {src}")
                frame = fin.read(length)
                if len(frame) != length:
                    die(f"Truncated file: {src}")
                final = fin.tell() >= size
                try:
                    fout.write(unseal(aes, cha, chunk_nonce(index), frame,
                                      chunk_aad(digest, index, final)))
                except InvalidTag:
                    die(f"Decryption failed. {src} was altered or truncated.")
                if final:
                    break
                index += 1
            fout.flush()
            os.fsync(fout.fileno())
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    print(f"Decrypted to: {out}")
 
 
def cmd_list(args) -> None:
    reg = load_registry()
    if not reg["files"]:
        print("No files tracked.")
        return
    for path_str, meta in sorted(reg["files"].items(), key=lambda kv: kv[1]["created"]):
        path = Path(path_str)
        status = ""
        if not path.exists():
            status = " [missing]"
        else:
            try:
                with path.open("rb") as fh:
                    if key_destroyed(fh.read(HEADER_LEN)):
                        status = " [key destroyed]"
            except OSError:
                status = " [unreadable]"
        print(f"- {path.name} (created {meta['created'][:10]}){status}")
        if args.paths:
            print(f"    {path}")
 
 
def cmd_kill(args) -> None:
    path = Path(args.file).resolve()
    if not path.is_file():
        die(f"File not found: {path}")
    print(f"WARNING: this permanently deletes {path.name} and its encryption key.")
    print("This action cannot be undone.")
    if not confirm("Type 'YES' to confirm: ", "YES"):
        die("Aborted.")
    if not shred_key(path):
        die(f"Not a {APP} file: {path}")
    path.unlink()
    reg = load_registry()
    reg["files"].pop(str(path), None)
    save_registry(reg)
    print("Deleted.")
 
 
def cmd_kill_key(args) -> None:
    path = Path(args.file).resolve()
    if not path.is_file():
        die(f"File not found: {path}")
    print(f"This will make {path.name} impossible to decrypt.")
    print("Copies elsewhere carry their own key and are unaffected.")
    if not confirm("Type 'YES' to confirm: ", "YES"):
        die("Aborted.")
    if not shred_key(path):
        die(f"Not a {APP} file: {path}")
    print("Key destroyed. File remains but is now unreadable.")
 
 
def cmd_kill_all(args) -> None:
    reg = load_registry()
    tracked = list(reg["files"])
    print("WARNING: this will delete:")
    print("- Master encryption key")
    print(f"- All encrypted files ({len(tracked)} tracked)")
    print("- All metadata")
    print("You will NOT be able to recover anything.")
    print("This action CANNOT be undone.")
    print()
    phrase = "I understand this is permanent"
    if not confirm(f"Type the full phrase '{phrase}' to confirm: ", phrase):
        die("Aborted.")
 
    skipped = []
    for path_str in tracked:
        path = Path(path_str)
        if not path.exists():
            continue
        if path.is_symlink() or not shred_key(path):
            skipped.append(path)
            continue
        path.unlink()
 
    key = master_key_path()
    try:
        with open(key, "r+b") as fh:
            fh.write(os.urandom(KEY_LEN))
            fh.flush()
            os.fsync(fh.fileno())
        key.unlink()
    except FileNotFoundError:
        pass
    try:
        registry_path().unlink()
    except FileNotFoundError:
        pass
 
    print("Vault destroyed.")
    for path in skipped:
        print(f"Skipped (not a {APP} file, or a symlink): {path}", file=sys.stderr)
    print("Note: encrypted copies stored elsewhere are now undecryptable, but they "
          "still exist.")
 
 
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP, description="Encrypted file vault.")
    p.add_argument("--version", action="version", version=f"{APP} {RELEASE}")
    sub = p.add_subparsers(dest="command", required=True)
 
    sub.add_parser("init", help="generate the master key").set_defaults(func=cmd_init)
 
    enc = sub.add_parser("encrypt", help="encrypt a file with a password")
    enc.add_argument("file")
    enc.add_argument("-o", "--output")
    enc.add_argument("--remove-original", action="store_true")
    enc.add_argument("--force", action="store_true", help="overwrite the output file")
    enc.set_defaults(func=cmd_encrypt)
 
    dec = sub.add_parser("decrypt", help="decrypt a file")
    dec.add_argument("file")
    dec.add_argument("-o", "--output")
    dec.add_argument("--force", action="store_true", help="overwrite the output file")
    dec.set_defaults(func=cmd_decrypt)
 
    lst = sub.add_parser("list", help="show tracked files")
    lst.add_argument("--paths", action="store_true", help="show full paths")
    lst.set_defaults(func=cmd_list)
 
    k = sub.add_parser("kill", help="destroy a file's key and delete the file")
    k.add_argument("file")
    k.set_defaults(func=cmd_kill)
 
    kk = sub.add_parser("kill-key", help="destroy a file's key, keep the file")
    kk.add_argument("file")
    kk.set_defaults(func=cmd_kill_key)
 
    sub.add_parser("kill-all", help="destroy the master key, tracked files and metadata"
                   ).set_defaults(func=cmd_kill_all)
    return p
 
 
def main() -> None:
    args = build_parser().parse_args()
    try:
        args.func(args)
    except PermissionError as exc:
        die(f"Permission denied: {exc.filename}")
    except OSError as exc:
        die(f"I/O error: {exc}")
 
 
if __name__ == "__main__":
    main()
 
