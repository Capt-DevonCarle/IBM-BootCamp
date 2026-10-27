from dataclasses import dataclass, field
import math


@dataclass
class PasswordAnalysis:
	entropy_bits: float = 0.0
	score: int = 0
	strength_label: str = ""
	time_to_crack: str = ""
	warnings: list[str] = field(default_factory=list)
	suggestions: list[str] = field(default_factory=list)


class PasswordStrengthAnalyzer:
	common_blacklist = [
		"password",
		"123456",
		"qwerty",
		"admin",
		"welcome",
		"letmein",
		"monkey",
		"iloveyou",
	]

	@staticmethod
	def contains_sequence(value: str) -> bool:
		if len(value) < 3:
			return False

		for index in range(len(value) - 2):
			first = value[index].lower()
			second = value[index + 1].lower()
			third = value[index + 2].lower()
			if ord(first) + 1 == ord(second) and ord(second) + 1 == ord(third):
				return True
		return False

	@staticmethod
	def contains_repeats(value: str) -> bool:
		for index in range(len(value) - 2):
			if value[index] == value[index + 1] == value[index + 2]:
				return True
		return False

	def analyze(self, password: str) -> PasswordAnalysis:
		result = PasswordAnalysis()

		has_upper = False
		has_lower = False
		has_digit = False
		has_special = False
		upper_count = 0

		for character in password:
			if character.isupper():
				has_upper = True
				upper_count += 1
			elif character.islower():
				has_lower = True
			elif character.isdigit():
				has_digit = True
			else:
				has_special = True

		pool_size = 0
		if has_lower:
			pool_size += 26
		if has_upper:
			pool_size += 26
		if has_digit:
			pool_size += 10
		if has_special:
			pool_size += 32

		if pool_size == 0 or not password:
			result.strength_label = "Invalid / Empty"
			return result

		result.entropy_bits = len(password) * math.log2(pool_size)

		lower_password = password.lower()
		for bad_word in self.common_blacklist:
			if bad_word in lower_password:
				result.warnings.append(
					f"Contains common dictionary term ('{bad_word}')."
				)
				result.entropy_bits -= 15

		if self.contains_sequence(password):
			result.warnings.append(
				"Contains simple sequential pattern (e.g., '123' or 'abc')."
			)
			result.entropy_bits -= 10

		if self.contains_repeats(password):
			result.warnings.append(
				"Contains repeated character sequences (e.g., 'aaa')."
			)
			result.entropy_bits -= 10

		if len(password) < 12:
			result.suggestions.append("Increase length to at least 12-16 characters.")
		if not has_special:
			result.suggestions.append("Add special characters (!@#$%^&*).")
		if upper_count < 2:
			result.suggestions.append("Include at least 2 uppercase letters.")

		total_combinations = 2 ** max(0.0, result.entropy_bits)
		seconds_to_crack = total_combinations / 1e10

		if seconds_to_crack < 1:
			result.time_to_crack = "Instantaneous"
		elif seconds_to_crack < 60:
			result.time_to_crack = "< 1 minute"
		elif seconds_to_crack < 3600:
			result.time_to_crack = f"{int(seconds_to_crack / 60)} minutes"
		elif seconds_to_crack < 86400:
			result.time_to_crack = f"{int(seconds_to_crack / 3600)} hours"
		elif seconds_to_crack < 31536000:
			result.time_to_crack = f"{int(seconds_to_crack / 86400)} days"
		elif seconds_to_crack < 3153600000:
			result.time_to_crack = f"{int(seconds_to_crack / 31536000)} years"
		else:
			result.time_to_crack = "Centuries / Practically Uncrackable"

		result.score = min(100, max(0, int(result.entropy_bits * 1.25)))

		if result.score >= 80:
			result.strength_label = "VERY STRONG"
		elif result.score >= 60:
			result.strength_label = "STRONG"
		elif result.score >= 40:
			result.strength_label = "MODERATE"
		elif result.score >= 20:
			result.strength_label = "WEAK"
		else:
			result.strength_label = "VERY WEAK"

		return result


def main() -> None:
	analyzer = PasswordStrengthAnalyzer()

	print("=== Cybersecurity Tool: Entropy-Based Password Analyzer ===")
	password = input("Enter password to evaluate: ")

	report = analyzer.analyze(password)

	print("\n---------------- SECURITY REPORT ----------------")
	print(f"Strength Rating   : {report.strength_label} ({report.score}/100)")
	print(f"Entropy Score     : {report.entropy_bits} bits")
	print(f"Est. Offline Crack: {report.time_to_crack}")

	if report.warnings:
		print("\nVulnerabilities Identified:")
		for warning in report.warnings:
			print(f" [!] {warning}")

	if report.suggestions:
		print("\nRecommendations:")
		for suggestion in report.suggestions:
			print(f" [+] {suggestion}")


if __name__ == "__main__":
	main()
