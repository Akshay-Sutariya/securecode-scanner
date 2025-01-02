<?php
// Hardcoded password
$password = "SuperSecretPassword123";

// SQL injection vulnerability
$user_input = $_GET['user'];
$query = "SELECT * FROM users WHERE username = '$user_input'";
$result = mysql_query($query);

// XSS vulnerability
echo $_GET['name'];

// Insecure file upload
if (isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], "/var/www/uploads/" . $_FILES['file']['name']);
}

// Use of eval
$code = $_GET['code'];
eval($code);

// Use of exec
$output = exec("ls -l");

// Insecure include
$page = $_GET['page'];
include($page);

// Unsafe serialization
$data = $_POST['data'];
$unserialized = unserialize($data);

// Hardcoded API key
$api_key
