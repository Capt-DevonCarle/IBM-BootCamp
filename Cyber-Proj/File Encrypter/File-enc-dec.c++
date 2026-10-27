#include <iostream>
#include <string>
#include <fstream>

using namespace std;

// Function to encrypt or decrypt using symmetric XOR + Caesar shift
string processText(const string& text, const string& key, bool encrypt) {
    string result = text;
    size_t keyLen = key.length();

    for (size_t i = 0; i < text.length(); ++i) {
        char keyChar = key[i % keyLen];
        if (encrypt) {
            // Apply XOR operation followed by shift
            result[i] = (text[i] ^ keyChar) + (keyChar % 7);
        } else {
            // Reverse shift followed by XOR operation
            result[i] = (text[i] - (keyChar % 7)) ^ keyChar;
        }
    }
    return result;
}

int main() {
    int choice;
    string text, key;

    cout << "=== Cybersecurity Tool: Symmetric File & Text Encrypter ===\n";
    cout << "1. Encrypt Text\n";
    cout << "2. Decrypt Text\n";
    cout << "Enter choice (1/2): ";
    cin >> choice;
    cin.ignore(); // Clear newline buffer

    cout << "Enter text: ";
    getline(cin, text);

    cout << "Enter secret key: ";
    getline(cin, key);

    if (key.empty()) {
        cout << "Key cannot be empty!\n";
        return 1;
    }

    if (choice == 1) {
        string encrypted = processText(text, key, true);
        cout << "\n[+] Encrypted Payload: " << encrypted << "\n";
    } else if (choice == 2) {
        string decrypted = processText(text, key, false);
        cout << "\n[+] Decrypted Text: " << decrypted << "\n";
    } else {
        cout << "Invalid choice!\n";
    }

    return 0;
}