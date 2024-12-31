SecureCode Scanner Documentation
Introduction
SecureCode Scanner is a static code analysis tool designed to detect security vulnerabilities in Python source code. It scans code for specific patterns that may indicate common security flaws. This tool is useful for identifying issues like hardcoded passwords, unsafe code execution, insecure deserialization, and more. The tool supports scanning both individual files and entire directories, and it generates a comprehensive JSON report of vulnerabilities.

Features
Vulnerability Detection: Identifies a wide range of security vulnerabilities, including:
Hardcoded passwords
Insecure deserialization
SQL injection risks
Command injection
Weak hashing algorithms
Insecure input handling
Dangerous imports and system calls
And more...
CLI Banner: Displays an introductory message when the tool is run.
Directory Scanning: Recursively scans directories for Python files and analyzes them for vulnerabilities.
Report Generation: Outputs a detailed JSON report of the vulnerabilities found in the scanned code.
System Requirements
Operating System: Windows, Linux, macOS
Python Version: Python 3.6 or later
Dependencies: re, os, json (all standard libraries)
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/securecode-scanner.git
Navigate to the directory:

bash
Copy code
cd securecode-scanner
The tool uses Python’s standard libraries, so no additional dependencies are required.

Usage
Run the Tool
To run the tool, execute the following command:

bash
Copy code
python tool.py
The tool will prompt you for a directory to scan.

Example Run
bash
Copy code
Enter the target directory to scan: /path/to/your/code
Starting secure code scan...
Scanning: /path/to/your/code/example.py
Scanning: /path/to/your/code/subdirectory/example2.py
...
Results saved to secure_code_scan_results.json
Scan completed! Check secure_code_scan_results.json for details.
The results will be saved in the secure_code_scan_results.json file.

How It Works
Banner Display: When the tool starts, the display_banner function shows an introductory message.
Pattern Matching: The tool searches for the following vulnerabilities based on regex patterns:
Hardcoded Passwords: Detects passwords, API keys, or tokens stored directly in the code.
Insecure Deserialization: Flags unsafe usage of pickle.loads().
SQL Injection: Identifies patterns that could lead to SQL injection attacks.
Command Injection: Flags unsafe system calls made with os.system() or subprocess functions.
Weak Hashing Algorithms: Flags the use of weak hashing functions like MD5 or SHA1.
Insecure Input Handling: Detects the use of input() without proper sanitization.
Insecure Randomness: Flags insecure random functions like random.choice() or random.randint().
HTTP URLs: Flags hardcoded HTTP URLs (which should be HTTPS).
Open Redirects: Flags potential open redirects in web applications.
Sensitive Logging: Detects logging of sensitive information like passwords or tokens.
Overly Permissive Permissions: Flags file permission settings that may expose sensitive files.
Scanning Files and Directories: The tool scans files in the specified directory (and subdirectories) for these patterns. Python files (.py) are the default, but you can easily adjust it to scan other file types.
Reporting: When vulnerabilities are found, the tool generates a JSON file that lists:
The file path
The line number where the vulnerability is found
The content of the vulnerable line
Vulnerability Patterns
The tool detects the following vulnerabilities based on predefined patterns:

Hardcoded Passwords:

regex
Copy code
r"['\"](password|passwd|pwd)['\"]\s*:\s*['\"].+['\"]"
Insecure Deserialization:

regex
Copy code
r"pickle\.loads\("
SQL Injection:

regex
Copy code
r"(SELECT|INSERT|UPDATE|DELETE)\s+.*\bFROM\b.*['\"].*['\"]"
Command Injection:

regex
Copy code
r"os\.system\(|subprocess\.(call|run|Popen)\("
Weak Hashing:

regex
Copy code
r"hashlib\.(md5|sha1)\("
Insecure Input:

regex
Copy code
r"(?<!#).*input\("
Insecure Randomness:

regex
Copy code
r"\brandom\.(randint|random|choice)\("
HTTP URLs:

regex
Copy code
r"http://[^\s]+"
Open Redirects:

regex
Copy code
r"redirect\((.*request.args.*)\)"
Hardcoded API Keys:

regex
Copy code
r"(apikey|api_key|token|access_token)\s*=\s*['\"].+['\"]"
Overly Permissive Permissions:

regex
Copy code
r"os\.chmod\(.+, 0o7[0-7][0-7]\)"
Sensitive Logging:

regex
Copy code
r"logging\.(debug|info|warn|error)\(.*(password|secret|token)"
Code Breakdown
display_banner()
Displays a welcome banner when the tool is run.

scan_file(file_path)
Scans an individual file for vulnerabilities:

Reads the file line by line
Applies regex patterns to detect security vulnerabilities
Returns a list of found vulnerabilities, including the name, line number, and content.
scan_directory(directory_path)
Recursively scans the directory for Python files and calls scan_file for each one. Vulnerabilities are stored in a dictionary with file paths as keys and vulnerability details as values.

save_results(results, filename)
Saves the results to a JSON file for easy review. The file is formatted with indentation for better readability.

Main Execution
In the if __name__ == "__main__" block:

The banner is displayed.
The user is prompted to input a directory to scan.
The scan starts, and results are saved in a JSON file.
Contributing
To contribute:

Fork the repository.
Create a branch for your changes.
Submit a pull request with a description of your changes.
License
This tool is licensed under the MIT License. See the LICENSE file for more details.

Contact
For inquiries or support, contact us at [your.email@example.com].
