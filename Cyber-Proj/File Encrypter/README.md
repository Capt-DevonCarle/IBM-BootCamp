 # Symmetric Text Encrypter

 A small Python console program that encrypts and decrypts text using a repeating-key XOR operation followed by a Caesar-style character shift.

 ## Features

 - Encrypts a line of text with a user-provided key.
 - Decrypts text produced with the same key.
 - Rejects an empty key.
 - Uses the same `processText` function for both operations.

 ## Requirements

 - Python 3.9 or later.

 ## Run

 From this directory, run:

 ```powershell
 python File-enc-dec.py
 ```

 The program asks you to choose encryption or decryption, enter one line of text, and provide a secret key. Decryption must use the same key used for encryption.

 ## Create a Windows executable

 Install PyInstaller and build a single-file executable with:

 ```powershell
 python -m pip install pyinstaller
 pyinstaller --onefile --console --name file-encrypter File-enc-dec.py
 ```

 The executable is created in the `dist` directory.

 ## Important limitations

 - Despite the project name, the current program processes text entered at the console; it does not read or write files.
 - This is an educational example, not production-grade encryption. It does not provide authenticated encryption, integrity checks, secure key derivation, or secure key storage.
 - Encrypted output may contain non-printable characters, so displaying or copying it through a terminal may not preserve it reliably.
