import re
import os
import json

# Utility function for CLI banner
def display_banner():
    banner = """
======================================================
              Welcome to SecureCode Scanner
       A Static Code Analysis Tool for Security
======================================================
    """
    print(banner)

# Define vulnerability patterns
vulnerability_patterns = {
    "hardcoded_password": r"['\"](password|passwd|pwd)['\"]\s*:\s*['\"].+['\"]",
    "eval_usage": r"\beval\(",
    "exec_usage": r"\bexec\(",
    "pickle_usage": r"\b(import\s+pickle|pickle\.loads\()",
    "insecure_deserialization": r"pickle\.loads\(",
    "dangerous_imports": r"\b(import\s+(os|sys|subprocess|shlex))",
    "sql_injection": r"(SELECT|INSERT|UPDATE|DELETE)\s+.*\bFROM\b.*['\"].*['\"]",
    "command_injection": r"os\.system\(|subprocess\.(call|run|Popen)\(",
    "weak_hashing": r"hashlib\.(md5|sha1)\(",
    "insecure_input": r"(?<!#).*input\(",
    "insecure_random": r"\brandom\.(randint|random|choice)\(",
    "http_urls": r"http://[^\s]+",
    "open_redirects": r"redirect\((.*request.args.*)\)",
    "hardcoded_api_keys": r"(apikey|api_key|token|access_token)\s*=\s*['\"].+['\"]",
    "overly_permissive_permissions": r"os\.chmod\(.+, 0o7[0-7][0-7]\)",
    "sensitive_logging": r"logging\.(debug|info|warn|error)\(.*(password|secret|token)"
}

# Function to scan a file for vulnerabilities
def scan_file(file_path):
    vulnerabilities = []
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
            for line_number, line in enumerate(lines, start=1):
                for vuln_name, pattern in vulnerability_patterns.items():
                    if re.search(pattern, line):
                        vulnerabilities.append({
                            "vulnerability": vuln_name,
                            "line_number": line_number,
                            "line_content": line.strip()
                        })
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
    return vulnerabilities

# Function to scan a directory recursively
def scan_directory(directory_path):
    results = {}
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".py"):  # Adjust for other languages
                file_path = os.path.join(root, file)
                print(f"Scanning: {file_path}")
                file_vulnerabilities = scan_file(file_path)
                if file_vulnerabilities:
                    results[file_path] = file_vulnerabilities
    return results

# Save results to a file
def save_results(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Results saved to {filename}")

# Main function
if __name__ == "__main__":
    display_banner()
    target_directory = input("Enter the target directory to scan: ")
    print("\nStarting secure code scan...\n")
    scan_results = scan_directory(target_directory)
    
    if scan_results:
        save_results(scan_results, "secure_code_scan_results.json")
        print("\nScan completed! Check secure_code_scan_results.json for details.")
    else:
        print("\nNo vulnerabilities found.")
