def process_text(text: str, key: str, encrypt: bool) -> str:
	result = []

	for index, character in enumerate(text):
		text_value = ord(character)
		key_value = ord(key[index % len(key)])
		shift = key_value % 7

		if encrypt:
			value = (text_value ^ key_value) + shift
		else:
			value = ((text_value - shift) & 0xFF) ^ key_value

		result.append(chr(value & 0xFF))

	return "".join(result)


def main() -> None:
	print("=== Cybersecurity Tool: Symmetric File & Text Encrypter ===")
	print("1. Encrypt Text")
	print("2. Decrypt Text")

	try:
		choice = int(input("Enter choice (1/2): "))
	except ValueError:
		print("Invalid choice!")
		return

	text = input("Enter text: ")
	key = input("Enter secret key: ")

	if not key:
		print("Key cannot be empty!")
		return

	if choice == 1:
		encrypted = process_text(text, key, True)
		print(f"\n[+] Encrypted Payload: {encrypted}")
	elif choice == 2:
		decrypted = process_text(text, key, False)
		print(f"\n[+] Decrypted Text: {decrypted}")
	else:
		print("Invalid choice!")


if __name__ == "__main__":
	main()
