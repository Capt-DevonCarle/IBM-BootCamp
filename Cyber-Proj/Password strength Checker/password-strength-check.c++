#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include <cctype>

using namespace std;

struct PasswordAnalysis {
    double entropyBits = 0.0;
    int score = 0; // 0 to 100
    string strengthLabel;
    string timeToCrack;
    vector<string> warnings;
    vector<string> suggestions;
};

class PasswordStrengthAnalyzer {
private:
    // List of common weak base patterns
    const vector<string> commonBlacklist = {
        "password", "123456", "qwerty", "admin", "welcome", "letmein", "monkey", "iloveyou"
    };

    bool containsSequence(const string& str) {
        if (str.length() < 3) return false;
        for (size_t i = 0; i < str.length() - 2; ++i) {
            // Check for sequential characters (e.g., abc, 123)
            if (tolower(str[i]) + 1 == tolower(str[i+1]) && tolower(str[i+1]) + 1 == tolower(str[i+2])) {
                return true;
            }
        }
        return false;
    }

    bool containsRepeats(const string& str) {
        for (size_t i = 0; i < str.length() - 2; ++i) {
            if (str[i] == str[i+1] && str[i+1] == str[i+2]) {
                return true;
            }
        }
        return false;
    }

public:
    PasswordAnalysis analyze(const string& password) {
        PasswordAnalysis result;
        
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        int upperCount = 0, lowerCount = 0, digitCount = 0, specialCount = 0;

        // 1. Character Set Classification
        for (char c : password) {
            if (isupper(c)) { hasUpper = true; upperCount++; }
            else if (islower(c)) { hasLower = true; lowerCount++; }
            else if (isdigit(c)) { hasDigit = true; digitCount++; }
            else { hasSpecial = true; specialCount++; }
        }

        // 2. Calculate Character Pool Size (R)
        int poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSpecial) poolSize += 32;

        if (poolSize == 0 || password.empty()) {
            result.strengthLabel = "Invalid / Empty";
            return result;
        }

        // 3. Mathematical Entropy Calculation: E = L * log2(R)
        result.entropyBits = password.length() * (log2(poolSize));

        // 4. Pattern & Dictionary Checks
        string lowerPass = password;
        transform(lowerPass.begin(), lowerPass.end(), lowerPass.begin(), ::tolower);

        for (const string& badWord : commonBlacklist) {
            if (lowerPass.find(badWord) != string::npos) {
                result.warnings.push_back("Contains common dictionary term ('" + badWord + "').");
                result.entropyBits -= 15; // Penalty for dictionary words
            }
        }

        if (containsSequence(password)) {
            result.warnings.push_back("Contains simple sequential pattern (e.g., '123' or 'abc').");
            result.entropyBits -= 10;
        }

        if (containsRepeats(password)) {
            result.warnings.push_back("Contains repeated character sequences (e.g., 'aaa').");
            result.entropyBits -= 10;
        }

        if (password.length() < 12) {
            result.suggestions.push_back("Increase length to at least 12-16 characters.");
        }
        if (!hasSpecial) {
            result.suggestions.push_back("Add special characters (!@#$%^&*).");
        }
        if (upperCount < 2) {
            result.suggestions.push_back("Include at least 2 uppercase letters.");
        }

        // 5. Crack Time Estimation (Assumes 10 Billion Guesses / Sec - GPU Array)
        double totalCombinations = pow(2, max(0.0, result.entropyBits));
        double secondsToCrack = totalCombinations / 1e10;

        if (secondsToCrack < 1) result.timeToCrack = "Instantaneous";
        else if (secondsToCrack < 60) result.timeToCrack = "< 1 minute";
        else if (secondsToCrack < 3600) result.timeToCrack = to_string((int)(secondsToCrack / 60)) + " minutes";
        else if (secondsToCrack < 86400) result.timeToCrack = to_string((int)(secondsToCrack / 3600)) + " hours";
        else if (secondsToCrack < 31536000) result.timeToCrack = to_string((int)(secondsToCrack / 86400)) + " days";
        else if (secondsToCrack < 3153600000) result.timeToCrack = to_string((int)(secondsToCrack / 31536000)) + " years";
        else result.timeToCrack = "Centuries / Practically Uncrackable";

        // 6. Score Mapping (0 to 100)
        result.score = min(100, max(0, (int)(result.entropyBits * 1.25)));

        if (result.score >= 80) result.strengthLabel = "VERY STRONG";
        else if (result.score >= 60) result.strengthLabel = "STRONG";
        else if (result.score >= 40) result.strengthLabel = "MODERATE";
        else if (result.score >= 20) result.strengthLabel = "WEAK";
        else result.strengthLabel = "VERY WEAK";

        return result;
    }
};

int main() {
    PasswordStrengthAnalyzer analyzer;
    string password;

    cout << "=== Cybersecurity Tool: Entropy-Based Password Analyzer ===\n";
    cout << "Enter password to evaluate: ";
    cin >> password;

    PasswordAnalysis report = analyzer.analyze(password);

    cout << "\n---------------- SECURITY REPORT ----------------\n";
    cout << "Strength Rating   : " << report.strengthLabel << " (" << report.score << "/100)\n";
    cout << "Entropy Score     : " << report.entropyBits << " bits\n";
    cout << "Est. Offline Crack: " << report.timeToCrack << "\n";

    if (!report.warnings.empty()) {
        cout << "\nVulnerabilities Identified:\n";
        for (const auto& w : report.warnings) {
            cout << " [!] " << w << "\n";
        }
    }

    if (!report.suggestions.empty()) {
        cout << "\nRecommendations:\n";
        for (const auto& s : report.suggestions) {
            cout << " [+] " << s << "\n";
        }
    }

    return 0;
}