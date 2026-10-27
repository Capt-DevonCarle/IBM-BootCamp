#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

using namespace std;

struct URLReport {
    int riskScore = 0; // 0 to 100
    vector<string> warnings;
};

URLReport analyzeURL(const string& url) {
    URLReport report;

    // Check 1: Length check
    if (url.length() > 75) {
        report.riskScore += 20;
        report.warnings.push_back("URL length exceeds 75 characters (common in obfuscated links).");
    }

    // Check 2: Contains @ symbol
    if (url.find('@') != string::npos) {
        report.riskScore += 30;
        report.warnings.push_back("Contains '@' symbol (used to hide actual destination domain).");
    }

    // Check 3: Check for IP address instead of domain name
    bool hasIP = false;
    for (size_t i = 0; i < url.length(); ++i) {
        if (isdigit(url[i])) {
            int dotCount = 0;
            size_t j = i;
            while (j < url.length() && (isdigit(url[j]) || url[j] == '.')) {
                if (url[j] == '.') dotCount++;
                j++;
            }
            if (dotCount == 3) {
                hasIP = true;
                break;
            }
        }
    }
    if (hasIP) {
        report.riskScore += 35;
        report.warnings.push_back("Uses raw IP address instead of a domain name.");
    }

    // Check 4: Suspicious TLDs
    vector<string> suspiciousTLDs = {".zip", ".mov", ".top", ".xyz", ".work", ".kim", ".party"};
    for (const string& tld : suspiciousTLDs) {
        if (url.rfind(tld) != string::npos) {
            report.riskScore += 20;
            report.warnings.push_back("Uses high-risk Top-Level Domain (" + tld + ").");
            break;
        }
    }

    // Check 5: Multiple subdomains / dots
    int dotCount = count(url.begin(), url.end(), '.');
    if (dotCount > 3) {
        report.riskScore += 15;
        report.warnings.push_back("Excessive subdomains detected (more than 3 dots).");
    }

    // Check 6: HTTP instead of HTTPS
    if (url.rfind("http://", 0) == 0) {
        report.riskScore += 15;
        report.warnings.push_back("Unencrypted protocol (HTTP instead of HTTPS).");
    }

    // Cap score at 100
    if (report.riskScore > 100) report.riskScore = 100;

    return report;
}

int main() {
    string url;
    cout << "=== Cybersecurity Tool: Phishing & Malicious URL Analyzer ===\n";
    cout << "Enter URL to scan: ";
    cin >> url;

    URLReport report = analyzeURL(url);

    cout << "\n---------------- SCAN RESULTS ----------------\n";
    cout << "Target URL: " << url << "\n";
    cout << "Phishing Risk Score: " << report.riskScore << " / 100\n";

    if (report.riskScore >= 60) {
        cout << "Threat Level: HIGH RISK (Likely Phishing/Malicious)\n";
    } else if (report.riskScore >= 30) {
        cout << "Threat Level: MODERATE RISK (Exercise Caution)\n";
    } else {
        cout << "Threat Level: LOW RISK (Appears Safe)\n";
    }

    if (!report.warnings.empty()) {
        cout << "\nDetected Risk Factors:\n";
        for (const string& warning : report.warnings) {
            cout << " - " << warning << "\n";
        }
    } else {
        cout << "\nNo major suspicious indicators detected.\n";
    }

    return 0;
}