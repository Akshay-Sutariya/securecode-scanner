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

# Define vulnerability patterns for Python
python_vulnerability_patterns = {
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

# Define vulnerability patterns for PHP
php_vulnerability_patterns = {
    "sql_injection": r"\b(mysql_query|mysqli_query|pg_query)\s*\(",
    "xss_vulnerability": r"echo\s*\$.*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.*\];",
    "insecure_file_upload": r"move_uploaded_file\s*\(.*\);",
    "eval_usage": r"\beval\s*\(",
    "exec_usage": r"\b(exec|shell_exec|system|passthru)\s*\(",
    "hardcoded_password": r"['\"](password|passwd)['\"]\s*=>\s*['\"].+['\"]",
    "insecure_include": r"\b(include|require|include_once|require_once)\s*\(.*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.*\]\);",
    "unsafe_serialization": r"unserialize\s*\("
}

# Define vulnerability patterns for JavaScript
javascript_vulnerability_patterns = {
    "eval_usage": r"\beval\(",
    "document_write": r"document\.write\(",
    "innerHTML_usage": r"\.innerHTML\s*=",
    "unsanitized_input": r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.*\]",
    "dangerous_globals": r"window\.\w+\s*=",
    "insecure_ajax": r"XMLHttpRequest",
    "unsafe_dom": r"getElementById|querySelector|createElement",
    "hardcoded_api_keys": r"(apikey|api_key|token|access_token)\s*=\s*['\"].+['\"]",
    "http_urls": r"http://[^\s]+",
    "command_execution": r"(child_process|exec|spawn|fork)\("
}

# Define vulnerability patterns for Java
java_vulnerability_patterns = {
    "sql_injection": r"\b(PreparedStatement|Statement)\s*\.\s*(executeQuery|executeUpdate|execute)\s*\(",
    "hardcoded_password": r"['\"](password|passwd)['\"]\s*=\s*['\"].+['\"]",
    "unsafe_deserialization": r"ObjectInputStream\s*\(\s*new\s*ObjectInputStream\s*\(",
    "insecure_logging": r"System\.out\.println\(",
    "eval_usage": r"Runtime\.getRuntime\(\)\.exec\(",
    "command_injection": r"Runtime\.getRuntime\(\)\.exec\(",
    "insecure_input": r"Scanner\s*\(System\.in\)",
    "file_access": r"FileInputStream\s*\(",
    "http_urls": r"http://[^\s]+",
    "hardcoded_api_keys": r"(apikey|api_key|token|access_token)\s*=\s*['\"].+['\"]"
}

# Combine all patterns
vulnerability_patterns = {
    **python_vulnerability_patterns,
    **php_vulnerability_patterns,
    **javascript_vulnerability_patterns,
    **java_vulnerability_patterns
}

# Function to scan a file for vulnerabilities
def scan_file(file_path):
    vulnerabilities = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for line_number, line in enumerate(lines, start=1):
                for vuln_name, pattern in vulnerability_patterns.items():
                    try:
                        if re.search(pattern, line):
                            vulnerabilities.append({
                                "vulnerability": vuln_name,
                                "line_number": line_number,
                                "line_content": line.strip()
                            })
                    except re.error as regex_error:
                        print(f"Regex error in pattern '{vuln_name}': {regex_error}")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except IOError as io_error:
        print(f"I/O error while reading {file_path}: {io_error}")
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
    return vulnerabilities

# Function to scan a directory recursively
def scan_directory(directory_path):
    results = {}
    if not os.path.exists(directory_path):
        print(f"Directory not found: {directory_path}")
        return results
    
    try:
        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith((".py", ".php", ".js", ".java")):  # Include Python, PHP, JavaScript, and Java files
                    file_path = os.path.join(root, file)
                    print(f"Scanning: {file_path}")
                    file_vulnerabilities = scan_file(file_path)
                    if file_vulnerabilities:
                        results[file_path] = file_vulnerabilities
    except Exception as e:
        print(f"Error scanning directory {directory_path}: {e}")
    return results

# Save results to a file
def save_results(results, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {filename}")
    except IOError as io_error:
        print(f"Error saving results to {filename}: {io_error}")
    except Exception as e:
        print(f"Error saving results: {e}")

# Main function
if __name__ == "__main__":
    display_banner()
    target_directory = input("Enter the target directory to scan: ").strip()
    
    if not target_directory:
        print("Directory path cannot be empty.")
    else:
        print("\nStarting secure code scan...\n")
        scan_results = scan_directory(target_directory)
        
        if scan_results:
            save_results(scan_results, "secure_code_scan_results.json")
            print("\nScan completed! Check secure_code_scan_results.json for details.")
        else:
            print("\nNo vulnerabilities found.")
