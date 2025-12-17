#!/usr/bin/env python3
"""
pixelcrypto.py
Encrypt / Decrypt images using pixel permutation + keystream XOR.

Dependencies:
  pillow, numpy
Install:
  pip install pillow numpy
"""

import sys
import hashlib
from PIL import Image, PngImagePlugin
import numpy as np


# -------------------- CRYPTO UTILITIES --------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def derive_seed_and_key(password: str) -> bytes:
    return sha256(password.encode("utf-8"))


def keystream_bytes(key_bytes: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        counter_bytes = counter.to_bytes(8, "big")
        out += hashlib.sha256(key_bytes + counter_bytes).digest()
        counter += 1
    return bytes(out[:length])


def make_permutation(length: int, seed_bytes: bytes) -> np.ndarray:
    seed_int = int.from_bytes(seed_bytes[:8], "big")
    rng = np.random.default_rng(seed_int)
    return rng.permutation(length)


# -------------------- ENCRYPTION --------------------

def encrypt_image(in_path: str, out_path: str, password: str):
    im = Image.open(in_path).convert("RGB")
    arr = np.array(im)
    flat = arr.flatten()
    L = flat.size

    key = derive_seed_and_key(password)
    perm = make_permutation(L, key)
    permuted = flat[perm]

    ks = keystream_bytes(key, L)
    cipher = np.frombuffer(
        bytes(a ^ b for a, b in zip(permuted.tobytes(), ks)),
        dtype=np.uint8
    )

    cipher_arr = cipher.reshape(arr.shape)
    out_im = Image.fromarray(cipher_arr, "RGB")

    # Integrity metadata
    orig_hash = hashlib.sha256(flat.tobytes()).hexdigest()
    pnginfo = PngImagePlugin.PngInfo()
    pnginfo.add_text("orig_image_sha256", orig_hash)
    pnginfo.add_text("pixelcrypto_version", "1.0")

    out_im.save(out_path, pnginfo=pnginfo)

    print("\n Encryption successful")
    print(f"Encrypted image saved as: {out_path}")
    print(f"Embedded SHA-256 hash: {orig_hash}")


# -------------------- DECRYPTION --------------------

def decrypt_image(in_path: str, out_path: str, password: str):
    im = Image.open(in_path).convert("RGB")
    arr = np.array(im)
    flat_cipher = arr.flatten()
    L = flat_cipher.size

    metadata = im.info
    orig_hash_stored = metadata.get("orig_image_sha256")

    key = derive_seed_and_key(password)
    ks = keystream_bytes(key, L)

    permuted_bytes = bytes(a ^ b for a, b in zip(flat_cipher.tobytes(), ks))
    permuted = np.frombuffer(permuted_bytes, dtype=np.uint8)

    perm = make_permutation(L, key)
    inv_perm = np.argsort(perm)
    recovered = permuted[inv_perm]

    recovered_arr = recovered.reshape(arr.shape)
    out_im = Image.fromarray(recovered_arr, "RGB")
    out_im.save(out_path)

    recovered_hash = hashlib.sha256(recovered.tobytes()).hexdigest()

    print("\n Decryption complete")
    if orig_hash_stored:
        if recovered_hash == orig_hash_stored:
            print("Integrity check: PASSED ")
        else:
            print("Integrity check: FAILED  (Wrong password or tampered image)")
    else:
        print("No integrity metadata found.")

    print(f"Decrypted image saved as: {out_path}")


# -------------------- MAIN (USER INPUT) --------------------

if __name__ == "__main__":
    print("\n=== PixelCrypto Image Encryptor ===")

    mode = input("Enter mode (encrypt / decrypt): ").strip().lower()
    if mode not in ("encrypt", "decrypt"):
        print(" Invalid mode. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)

    input_image = input("Enter input image filename (e.g., input.png): ").strip()
    output_image = input("Enter output image filename: ").strip()
    password = input("Enter password: ").strip()

    if not input_image or not output_image or not password:
        print(" Inputs cannot be empty.")
        sys.exit(1)

    try:
        if mode == "encrypt":
            encrypt_image(input_image, output_image, password)
        else:
            decrypt_image(input_image, output_image, password)
    except FileNotFoundError:
        print(" Image file not found. Check the filename and path.")
    except Exception as e:
        print(" Error:", e)
