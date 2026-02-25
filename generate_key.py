#!/usr/bin/env python
"""
Helper script to generate encryption key for .env file
"""
from cryptography.fernet import Fernet

if __name__ == '__main__':
    key = Fernet.generate_key().decode()
    print("Generated ENCRYPTION_KEY:")
    print(key)
    print("\nAdd this to your .env file:")
    print(f"ENCRYPTION_KEY={key}")
