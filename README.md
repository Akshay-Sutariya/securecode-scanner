
# SecureCode Scanner

## Overview

**SecureCode Scanner** is a static code analysis tool designed to help identify common security vulnerabilities in code written in multiple programming languages, including Python, PHP, JavaScript, and Java. The tool scans code files for known patterns of vulnerabilities and generates a report in JSON format.

The primary goal of this tool is to help developers and security professionals identify potential security risks early in the development process, enabling them to fix vulnerabilities before they are deployed to production.

## Features

- **Cross-Language Support**: Scans code in Python, PHP, JavaScript, and Java.
- **Comprehensive Vulnerability Patterns**: Includes detection for common vulnerabilities like SQL injection, insecure deserialization, hardcoded passwords, unsafe file access, and more.
- **CLI-based**: Operates through a command-line interface, making it easy to integrate into build and CI/CD pipelines.
- **Error Handling**: Robust error handling ensures that scanning does not fail due to common file system issues or regex errors.
- **JSON Report**: Results are outputted in a structured JSON format, which can be easily analyzed or integrated with other tools.

## Installation

1. **Clone the repository** (or download the script files directly):

   ```bash
   git clone https://github.com/Akshay-Sutariya/securecode-scanner.git
   cd securecode-scanner
   ```

2. **Install required dependencies** (if any):

   The tool uses Python's built-in libraries (`re`, `os`, `json`), so no additional dependencies are required for basic functionality.

   However, if you want to install extra packages (e.g., for testing), you can create a `requirements.txt` file:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To use the **SecureCode Scanner**, follow these steps:

### 1. Launch the scanner

Run the Python script from the command line:

```bash
python secure_code_scanner.py
```

### 2. Enter the directory path

Once you run the script, it will prompt you to enter the directory you want to scan for vulnerabilities. Enter the full path to the directory containing the code files.

Example:

```bash
Enter the target directory to scan: /path/to/your/code
```

### 3. View the results

The tool will scan all Python (`.py`), PHP (`.php`), JavaScript (`.js`), and Java (`.java`) files in the directory and its subdirectories. After scanning, it will generate a file called `secure_code_scan_results.json` in the same directory.

This file will contain detailed information about any vulnerabilities found, including the file path, vulnerability type, line number, and the content of the vulnerable line.

### Example output:

```json
{
    "path/to/file.py": [
        {
            "vulnerability": "hardcoded_password",
            "line_number": 42,
            "line_content": "password = 'mysecretpassword'"
        },
        {
            "vulnerability": "eval_usage",
            "line_number": 55,
            "line_content": "eval(user_input)"
        }
    ]
}
```

## Vulnerabilities Detected

### Python Vulnerabilities
- **Hardcoded Passwords**: Detects password values hardcoded in the code.
- **Eval Usage**: Flags any usage of `eval()`, which can execute arbitrary code.
- **Insecure Deserialization**: Detects the use of `pickle.loads()`, which can be unsafe if deserialized data is untrusted.
- **SQL Injection**: Looks for vulnerable SQL queries that might be susceptible to injection attacks.
- **Command Injection**: Flags usage of system commands via functions like `os.system()` or `subprocess.call()`.

### PHP Vulnerabilities
- **SQL Injection**: Flags unsafe usage of SQL queries with potential injection risks.
- **XSS Vulnerability**: Flags PHP code that directly outputs user input, which might be susceptible to cross-site scripting attacks.
- **Insecure File Upload**: Detects unsafe file upload handling, which can lead to remote code execution.

### JavaScript Vulnerabilities
- **Eval Usage**: Detects unsafe usage of `eval()`, which can execute arbitrary JavaScript code.
- **InnerHTML Usage**: Flags potentially dangerous usage of `.innerHTML`, which can introduce cross-site scripting (XSS) vulnerabilities.
- **Hardcoded API Keys**: Flags hardcoded API keys, tokens, or sensitive information.

### Java Vulnerabilities
- **SQL Injection**: Flags potential SQL injection risks in Java database queries.
- **Hardcoded Passwords**: Flags hardcoded password values in Java code.
- **Insecure Logging**: Detects usage of insecure logging methods that might expose sensitive information.

## Error Handling

The tool has robust error handling to handle:
- **File Not Found**: If the tool cannot access a file, it will output a relevant error message.
- **Regex Errors**: If a regular expression fails, the tool catches the error and continues scanning other files.
- **Directory Not Found**: If the provided directory doesn't exist, an appropriate message is displayed.
- **General I/O Errors**: Issues with file reading or writing are caught and reported.

## Extending the Tool

You can extend the **SecureCode Scanner** by adding new vulnerability patterns for other languages or new types of vulnerabilities. To add new patterns, modify the `vulnerability_patterns` dictionary and add corresponding regular expressions for the vulnerability you want to detect.

```python
new_vulnerability_patterns = {
    "new_vulnerability_type": r"your-regex-pattern-here"
}

vulnerability_patterns.update(new_vulnerability_patterns)
```


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
