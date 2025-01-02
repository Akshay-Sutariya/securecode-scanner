// Hardcoded API Key
const apiKey = "12345-abcdef";

// Usage of eval
eval("console.log('This is insecure code execution!')");

// Document write vulnerability
document.write("<p>This is directly written to the DOM without sanitization</p>");

// InnerHTML usage
let userInput = "<script>alert('XSS!');</script>";
document.getElementById("output").innerHTML = userInput;

// Insecure AJAX Request
let xhr = new XMLHttpRequest();
xhr.open("GET", "http://example.com/data", true);
xhr.send();

// Command execution using Node.js
const { exec } = require('child_process');
exec('ls -l', (err, stdout, stderr) => {
    if (err) {
        console.error(`Error: ${stderr}`);
    } else {
        console.log(`Output: ${stdout}`);
    }
});

// Unsafe DOM Manipulation
let element = document.getElementById("inputField");
let dangerousValue = element.value;
document.querySelector("#output").innerHTML = dangerousValue;

// Hardcoded URL
let apiUrl = "http://insecure.example.com/api";

// Accessing dangerous global variables
window.globalVar = "Potential risk with global variable manipulation";

// Dangerous random content assignment
