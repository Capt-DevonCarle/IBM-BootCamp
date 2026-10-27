 # Phishing and Malicious URL Analyzer

 A Python console program that assigns a heuristic phishing-risk score to a URL by checking for common suspicious indicators.

 ## Features

 - Adds risk for URLs longer than 75 characters.
 - Detects an `@` symbol, which can hide the actual destination in a URL.
 - Detects an apparent IPv4 address used instead of a domain name.
 - Flags selected high-risk top-level domains: `.zip`, `.mov`, `.top`, `.xyz`, `.work`, `.kim`, and `.party`.
 - Flags URLs containing more than three dots.
 - Adds risk when the URL begins with unencrypted `http://` instead of `https://`.
 - Reports a score from 0 to 100 and lists the indicators that were detected.

 ## Requirements

 - Python 3.9 or later.

 ## Run

 From this directory, run:

 ```powershell
 python phising-analyser.py
 ```

 Enter a URL when prompted. The program displays the URL, risk score, threat level, and detected risk factors.

 ## Threat levels

 | Score | Threat level |
 | --- | --- |
 | 0-29 | LOW RISK |
 | 30-59 | MODERATE RISK |
 | 60-100 | HIGH RISK |

 ## Important limitations

 - This is a local heuristic scanner; it does not verify the URL with a reputation service, DNS lookup, certificate check, or live website inspection.
 - A low score does not prove that a URL is safe, and a high score does not prove that it is malicious.
 - The URL parser is intentionally simple and may produce false positives or miss sophisticated phishing URLs.
 - Do not visit a suspicious URL merely to test it.
