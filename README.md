# Pixel-Based Image Encryption Tool

A modern image-encryption system built using pixel permutation + cryptographic keystream mixing.  
Developed as part of **Prodigy InfoTech Cybersecurity Internship — Task 02**.

## Features
- Password-driven image encryption  
- Pixel-level permutation (position obfuscation)  
- XOR keystream encryption (lightweight stream cipher model)  
- Metadata-embedded SHA-256 integrity hash  
- Fully reversible, lossless decryption  
- Works with PNG/JPG images

## How It Works
1. Convert image → RGB byte array.  
2. Derive key from password using SHA-256.  
3. Generate deterministic permutation (pixel shuffle).  
4. Generate keystream → XOR with shuffled pixels.  
5. Embed SHA-256 integrity hash into the encrypted PNG.  
6. Decrypt by reversing XOR + inverse permutation.

**Note:** This tool is educational. For production use, migrate to standard authenticated encryption primitives (e.g., AES-GCM / libsodium).

## Installation
```bash
python -m venv venv
source venv/bin/activate   # Linux / macOS
venv\Scripts\activate      # Windows PowerShell
pip install -r requirements.txt
