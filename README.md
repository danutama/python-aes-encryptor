# Advanced Encryption Standard Multi-Format Encryption and Decryption Tool

Author: Danu Pratama

A Python-based application for encrypting and decrypting various data formats using the Advanced Encryption Standard (AES) 128, 192, 256-bit.

## Features

- 🔒 AES Encryption & Decryption
- 📁 Multi-format file support:
  - Text (.txt)
  - Microsoft Word (.docx)
  - Excel (.xlsx)
  - PDF (.pdf)
  - Images (.jpg, .png)
  - Video (.mp4)
  - PowerPoint (.pptx)
- ⏰ Timeout mechanism to limit execution time
- 📊 Estimated brute force duration display

## Disclaimer

This project is created **for educational and experimental use only**. Brute-forcing AES encryption with full 128-bit keyspace is computationally impractical and should never be used for unauthorized purposes.

Build .EXE
```bash
pyinstaller --onefile --noconsole --hidden-import=tkinter --hidden-import=Crypto.Cipher AdvancedEncryptionStandard.py
