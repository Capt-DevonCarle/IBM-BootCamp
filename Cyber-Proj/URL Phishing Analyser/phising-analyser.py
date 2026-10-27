from dataclasses import dataclass, field


@dataclass
class URLReport:
	risk_score: int = 0
	warnings: list[str] = field(default_factory=list)


def analyze_url(url: str) -> URLReport:
	report = URLReport()

	# Check 1: Length check
	if len(url) > 75:
		report.risk_score += 20
		report.warnings.append(
			"URL length exceeds 75 characters (common in obfuscated links)."
		)

	# Check 2: Contains @ symbol
	if "@" in url:
		report.risk_score += 30
		report.warnings.append(
			"Contains '@' symbol (used to hide actual destination domain)."
		)

	# Check 3: Check for an IP address instead of a domain name
	has_ip = False
	for index, character in enumerate(url):
		if character.isdigit():
			dot_count = 0
			current_index = index

			while current_index < len(url) and (
				url[current_index].isdigit() or url[current_index] == "."
			):
				if url[current_index] == ".":
					dot_count += 1
				current_index += 1

			if dot_count == 3:
				has_ip = True
				break

	if has_ip:
		report.risk_score += 35
		report.warnings.append("Uses raw IP address instead of a domain name.")

	# Check 4: Suspicious TLDs
	suspicious_tlds = [".zip", ".mov", ".top", ".xyz", ".work", ".kim", ".party"]
	for tld in suspicious_tlds:
		if tld in url:
			report.risk_score += 20
			report.warnings.append(f"Uses high-risk Top-Level Domain ({tld}).")
			break

	# Check 5: Multiple subdomains / dots
	dot_count = url.count(".")
	if dot_count > 3:
		report.risk_score += 15
		report.warnings.append("Excessive subdomains detected (more than 3 dots).")

	# Check 6: HTTP instead of HTTPS
	if url.startswith("http://"):
		report.risk_score += 15
		report.warnings.append("Unencrypted protocol (HTTP instead of HTTPS).")

	report.risk_score = min(report.risk_score, 100)
	return report


def main() -> None:
	print("=== Cybersecurity Tool: Phishing & Malicious URL Analyzer ===")
	url = input("Enter URL to scan: ").strip()

	report = analyze_url(url)

	print("\n---------------- SCAN RESULTS ----------------")
	print(f"Target URL: {url}")
	print(f"Phishing Risk Score: {report.risk_score} / 100")

	if report.risk_score >= 60:
		print("Threat Level: HIGH RISK (Likely Phishing/Malicious)")
	elif report.risk_score >= 30:
		print("Threat Level: MODERATE RISK (Exercise Caution)")
	else:
		print("Threat Level: LOW RISK (Appears Safe)")

	if report.warnings:
		print("\nDetected Risk Factors:")
		for warning in report.warnings:
			print(f" - {warning}")
	else:
		print("\nNo major suspicious indicators detected.")


if __name__ == "__main__":
	main()
