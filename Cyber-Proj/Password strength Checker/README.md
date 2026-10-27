 # Entropy-Based Password Strength Analyzer

 A Python console program that estimates password strength using character categories, entropy, common-password patterns, and an estimated offline cracking time.

 ## Features

 - Detects lowercase letters, uppercase letters, digits, and special characters.
 - Calculates estimated entropy with `length * log2(character pool size)`.
 - Flags common dictionary terms such as `password`, `123456`, and `qwerty`.
 - Detects simple sequences such as `abc` and `123`.
 - Detects three repeated characters such as `aaa`.
 - Reports a score from 0 to 100, a strength label, warnings, and suggestions.
 - Estimates crack time using an assumed rate of 10 billion guesses per second.

 ## Requirements

 - Python 3.9 or later.

 ## Run

 From this directory, run:

 ```powershell
 python password-strength-check.py
 ```

 Enter the password when prompted.

 ## Create a Windows executable

 Install PyInstaller and build a single-file executable with:

 ```powershell
 python -m pip install pyinstaller
 pyinstaller --onefile --console --name password-strength-check password-strength-check.py
 ```

 The executable is created in the `dist` directory.

 ## Score labels

 | Score | Label |
 | --- | --- |
 | 80-100 | VERY STRONG |
 | 60-79 | STRONG |
 | 40-59 | MODERATE |
 | 20-39 | WEAK |
 | 0-19 | VERY WEAK |

 ## Important limitations

 - Entropy is an estimate based on possible character categories, not a measurement of how the password was actually created.
 - The crack-time result is theoretical and depends on the assumed guessing rate and attack method.
 - The blacklist is short and does not replace a larger breached-password database.
 - This tool should not be used as the only basis for password security decisions.
