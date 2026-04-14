#!/usr/bin/env python3

import argparse
import getpass
import os
import sys
import struct
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, constant_time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"EXEOBFv1"  # 8 bytes
HEADER_STRUCT = "<8sIII16s16sI"  # magic, scrypt_n, scrypt_r, scrypt_p, iv(16), salt(16), chunk_size
HEADER_SIZE = struct.calcsize(HEADER_STRUCT)
HMAC_TAG_SIZE = 32
DEFAULT_CHUNK_SIZE = 64 * 1024
DEFAULT_SCRYPT_N = 1 << 14  # 16384
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
MAX_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB safety upper bound
MIN_CHUNK_SIZE = 4096


def derive_keys(password: bytes, salt: bytes, n: int, r: int, p: int) -> Tuple[bytes, bytes]:
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes")
    if len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    kdf = Scrypt(salt=salt, length=64, n=n, r=r, p=p, backend=default_backend())
    full_key = kdf.derive(password)
    aes_key = full_key[:32]
    hmac_key = full_key[32:]
    return aes_key, hmac_key


def clamp_chunk_size(chunk_size: int) -> int:
    if chunk_size < MIN_CHUNK_SIZE:
        return MIN_CHUNK_SIZE
    if chunk_size > MAX_CHUNK_SIZE:
        return MAX_CHUNK_SIZE
    return chunk_size


def mask_file(input_path: Path, output_path: Path, password: str, overwrite: bool, chunk_size: int = DEFAULT_CHUNK_SIZE,
              scrypt_n: int = DEFAULT_SCRYPT_N, scrypt_r: int = DEFAULT_SCRYPT_R, scrypt_p: int = DEFAULT_SCRYPT_P) -> None:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Output file exists: {output_path}. Use --force to overwrite.")

    chunk_size = clamp_chunk_size(chunk_size)

    salt = os.urandom(16)
    iv = os.urandom(16)
    aes_key, hmac_key = derive_keys(password.encode("utf-8"), salt, scrypt_n, scrypt_r, scrypt_p)

    header = struct.pack(HEADER_STRUCT, MAGIC, scrypt_n, scrypt_r, scrypt_p, iv, salt, chunk_size)

    encryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend()).encryptor()
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())

    # Include header in HMAC to protect parameters
    h.update(header)

    with input_path.open("rb") as fin, output_path.open("wb") as fout:
        fout.write(header)
        while True:
            plaintext_chunk = fin.read(chunk_size)
            if not plaintext_chunk:
                break
            ciphertext_chunk = encryptor.update(plaintext_chunk)
            if ciphertext_chunk:
                fout.write(ciphertext_chunk)
                h.update(ciphertext_chunk)
        final_ct = encryptor.finalize()
        if final_ct:
            fout.write(final_ct)
            h.update(final_ct)
        tag = h.finalize()
        fout.write(tag)


def unmask_file(input_path: Path, output_path: Path, password: str, overwrite: bool) -> None:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Output file exists: {output_path}. Use --force to overwrite.")

    total_size = input_path.stat().st_size
    if total_size < HEADER_SIZE + HMAC_TAG_SIZE:
        raise ValueError("File is too small to be a masked file")

    with input_path.open("rb") as fin:
        header = fin.read(HEADER_SIZE)
        if len(header) != HEADER_SIZE:
            raise ValueError("Invalid header size")
        magic, scrypt_n, scrypt_r, scrypt_p, iv, salt, chunk_size = struct.unpack(HEADER_STRUCT, header)
        if magic != MAGIC:
            raise ValueError("Invalid file magic. Not a masked file or wrong format version.")

        chunk_size = clamp_chunk_size(chunk_size)

        aes_key, hmac_key = derive_keys(password.encode("utf-8"), salt, scrypt_n, scrypt_r, scrypt_p)
        decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend()).decryptor()
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(header)

        ciphertext_length = total_size - HEADER_SIZE - HMAC_TAG_SIZE
        bytes_remaining = ciphertext_length

        temp_output_path = Path(str(output_path) + ".partial.tmp")
        try:
            with temp_output_path.open("wb") as fout:
                while bytes_remaining > 0:
                    to_read = min(chunk_size, bytes_remaining)
                    chunk = fin.read(to_read)
                    if not chunk:
                        raise ValueError("Unexpected end of file while reading ciphertext")
                    bytes_remaining -= len(chunk)
                    h.update(chunk)
                    plaintext = decryptor.update(chunk)
                    if plaintext:
                        fout.write(plaintext)
                final_pt = decryptor.finalize()
                if final_pt:
                    fout.write(final_pt)

            # Read and verify tag
            tag = fin.read(HMAC_TAG_SIZE)
            if len(tag) != HMAC_TAG_SIZE:
                raise ValueError("Invalid or missing authentication tag")
            calc_tag = h.finalize()
            if not constant_time.bytes_eq(tag, calc_tag):
                raise ValueError("Authentication failed: wrong password or corrupted file")

            # All good, move into place
            if output_path.exists() and overwrite:
                output_path.unlink()
            temp_output_path.replace(output_path)
        except Exception:
            # Clean up partial file on error
            if temp_output_path.exists():
                try:
                    temp_output_path.unlink()
                except Exception:
                    pass
            raise


def print_info(input_path: Path) -> None:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    total_size = input_path.stat().st_size
    with input_path.open("rb") as fin:
        header = fin.read(HEADER_SIZE)
        if len(header) != HEADER_SIZE:
            print("Invalid or truncated header")
            return
        magic, scrypt_n, scrypt_r, scrypt_p, iv, salt, chunk_size = struct.unpack(HEADER_STRUCT, header)
        if magic != MAGIC:
            print("Not a masked file (magic mismatch)")
            return
        ciphertext_length = max(0, total_size - HEADER_SIZE - HMAC_TAG_SIZE)
        print("Format: EXEOBF v1")
        print(f"Size (total): {total_size} bytes")
        print(f"Ciphertext size: {ciphertext_length} bytes")
        print(f"Scrypt n/r/p: {scrypt_n}/{scrypt_r}/{scrypt_p}")
        print(f"Chunk size: {clamp_chunk_size(chunk_size)} bytes")
        print(f"IV: {iv.hex()}")
        print(f"Salt: {salt.hex()}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Mask (encrypt) and unmask (decrypt) files using password-based AES-CTR with HMAC-SHA256.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_mask = sub.add_parser("mask", help="Mask (encrypt) an input file")
    p_mask.add_argument("-i", "--in", dest="inp", required=True, help="Path to input file (e.g., .exe)")
    p_mask.add_argument("-o", "--out", dest="outp", help="Output path (defaults to input + .obf)")
    p_mask.add_argument("-p", "--password", dest="password", help="Password (if omitted, will prompt)")
    p_mask.add_argument("--force", action="store_true", help="Overwrite output if it exists")
    p_mask.add_argument("--chunk", type=int, default=DEFAULT_CHUNK_SIZE, help="Chunk size for streaming I/O")

    p_unmask = sub.add_parser("unmask", help="Unmask (decrypt) a masked file")
    p_unmask.add_argument("-i", "--in", dest="inp", required=True, help="Path to masked input file (.obf)")
    p_unmask.add_argument("-o", "--out", dest="outp", help="Output path (defaults to input without .obf)")
    p_unmask.add_argument("-p", "--password", dest="password", help="Password (if omitted, will prompt)")
    p_unmask.add_argument("--force", action="store_true", help="Overwrite output if it exists")

    p_info = sub.add_parser("info", help="Show info about a masked file")
    p_info.add_argument("-i", "--in", dest="inp", required=True, help="Path to masked input file (.obf)")

    args = parser.parse_args(argv)

    if args.cmd == "mask":
        in_path = Path(args.inp)
        out_path = Path(args.outp) if args.outp else Path(str(in_path) + ".obf")
        password = args.password or getpass.getpass("Password: ")
        try:
            mask_file(in_path, out_path, password, overwrite=args.force, chunk_size=args.chunk)
            print(f"Masked file written to: {out_path}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        return 0

    if args.cmd == "unmask":
        in_path = Path(args.inp)
        if args.outp:
            out_path = Path(args.outp)
        else:
            s = str(in_path)
            out_path = Path(s[:-4]) if s.lower().endswith(".obf") else Path(s + ".dec")
        password = args.password or getpass.getpass("Password: ")
        try:
            unmask_file(in_path, out_path, password, overwrite=args.force)
            print(f"Unmasked file written to: {out_path}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        return 0

    if args.cmd == "info":
        try:
            print_info(Path(args.inp))
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
