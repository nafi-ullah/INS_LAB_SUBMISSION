#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSE-478 Lab 4: Programming Symmetric & Asymmetric Crypto
Author: [Your Name]
Date: 2025-11-08

Functionalities:
1. AES (128/256 bits) Encryption/Decryption (ECB, CFB)
2. RSA Encryption/Decryption
3. RSA Signature & Verification
4. SHA-256 Hashing
5. Execution Time Measurement & Graphing
"""

import os
import time
import hashlib
import matplotlib.pyplot as plt
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ------------------ AES SECTION ------------------
def generate_aes_key(bits):
    key = get_random_bytes(bits // 8)
    with open(f"aes_{bits}_key.bin", "wb") as f:
        f.write(key)
    print(f"AES-{bits} key generated and saved.")
    return key

def load_aes_key(bits):
    with open(f"aes_{bits}_key.bin", "rb") as f:
        return f.read()

def aes_encrypt(file_in, bits, mode):
    key = load_aes_key(bits)
    data = open(file_in, "rb").read()

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        # pad to 16 bytes
        pad_len = 16 - len(data) % 16
        data += bytes([pad_len]) * pad_len
        ciphertext = cipher.encrypt(data)
    elif mode == "CFB":
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = iv + cipher.encrypt(data)
    else:
        raise ValueError("Invalid AES mode")

    with open("aes_encrypted.bin", "wb") as f:
        f.write(ciphertext)
    print("AES Encryption complete. Output: aes_encrypted.bin")

def aes_decrypt(bits, mode):
    key = load_aes_key(bits)
    ciphertext = open("aes_encrypted.bin", "rb").read()

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]
    elif mode == "CFB":
        iv = ciphertext[:16]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext[16:])
    else:
        raise ValueError("Invalid AES mode")

    print("Decrypted content:\n", plaintext.decode(errors="ignore"))

# ------------------ RSA SECTION ------------------
def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("rsa_private.pem", "wb") as f:
        f.write(private_key)
    with open("rsa_public.pem", "wb") as f:
        f.write(public_key)
    print(f"RSA-{bits} key pair generated and saved.")

def rsa_encrypt(file_in):
    data = open(file_in, "rb").read()
    public_key = RSA.import_key(open("rsa_public.pem").read())
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(data)
    with open("rsa_encrypted.bin", "wb") as f:
        f.write(ciphertext)
    print("RSA Encryption complete.")

def rsa_decrypt():
    ciphertext = open("rsa_encrypted.bin", "rb").read()
    private_key = RSA.import_key(open("rsa_private.pem").read())
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    print("Decrypted content:\n", plaintext.decode(errors="ignore"))

# ------------------ SIGNATURE SECTION ------------------
def rsa_sign(file_in):
    private_key = RSA.import_key(open("rsa_private.pem").read())
    data = open(file_in, "rb").read()
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    with open("signature.bin", "wb") as f:
        f.write(signature)
    print("Signature generated and saved as signature.bin")

def rsa_verify(file_in):
    public_key = RSA.import_key(open("rsa_public.pem").read())
    data = open(file_in, "rb").read()
    signature = open("signature.bin", "rb").read()
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("Signature verification successful ✅")
    except (ValueError, TypeError):
        print("Signature verification failed ❌")

# ------------------ HASH SECTION ------------------
def sha256_hash(file_in):
    data = open(file_in, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    print("SHA-256:", digest)

# ------------------ TIMING EXPERIMENT ------------------
def measure_time():
    aes_bits_list = [16, 32, 64, 128, 256]
    rsa_bits_list = [512, 1024, 2048, 3072, 4096]

    aes_times, rsa_times = [], []
    temp_file = "sample.txt"
    open(temp_file, "w").write("This is a sample message for timing tests.")

    for bits in aes_bits_list:
        start = time.time()
        key = get_random_bytes(max(bits // 8, 2))
        cipher = AES.new(key[:16], AES.MODE_ECB)
        data = b"Hello Crypto" * 100
        cipher.encrypt(data.ljust((len(data)//16 + 1)*16, b' '))
        aes_times.append(time.time() - start)

    for bits in rsa_bits_list:
        start = time.time()
        key = RSA.generate(bits)
        msg = b"Hello Crypto"
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(msg)
        rsa_times.append(time.time() - start)

    plt.plot(aes_bits_list, aes_times, marker="o", label="AES")
    plt.plot(rsa_bits_list, rsa_times, marker="x", label="RSA")
    plt.xlabel("Key Size (bits)")
    plt.ylabel("Execution Time (seconds)")
    plt.title("Execution Time vs Key Size")
    plt.legend()
    plt.grid(True)
    plt.savefig("timing_plot.png")
    plt.show()
    print("Timing plot saved as timing_plot.png")

# ------------------ MAIN MENU ------------------
def main():
    while True:
        print("\n--- CSE-478 Lab 4 Menu ---")
        print("1. AES Encryption/Decryption")
        print("2. RSA Encryption/Decryption")
        print("3. RSA Signature & Verification")
        print("4. SHA-256 Hashing")
        print("5. Measure Execution Time & Plot")
        print("0. Exit")

        choice = input("Select option: ")

        if choice == "1":
            bits = int(input("Enter AES key length (128 or 256): "))
            mode = input("Enter mode (ECB/CFB): ").upper()
            if not os.path.exists(f"aes_{bits}_key.bin"):
                generate_aes_key(bits)
            fname = input("Enter input filename to encrypt: ")
            aes_encrypt(fname, bits, mode)
            aes_decrypt(bits, mode)

        elif choice == "2":
            if not os.path.exists("rsa_private.pem"):
                bits = int(input("Enter RSA key length (e.g. 2048): "))
                generate_rsa_keys(bits)
            fname = input("Enter file to encrypt: ")
            rsa_encrypt(fname)
            rsa_decrypt()

        elif choice == "3":
            fname = input("Enter file to sign: ")
            rsa_sign(fname)
            rsa_verify(fname)

        elif choice == "4":
            fname = input("Enter file for SHA-256 hashing: ")
            sha256_hash(fname)

        elif choice == "5":
            measure_time()

        elif choice == "0":
            print("Exiting...")
            break

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
