import java.io.*;
import java.sql.*;
import java.util.Scanner;

public class TestVulnerabilities {
    public static void main(String[] args) {
        // Vulnerability 1: Hardcoded Password
        String password = "admin123";  // Hardcoded password

        // Vulnerability 2: SQL Injection
        String userInput = "test'; DROP TABLE users; --";
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'"; // SQL Injection
        System.out.println("Query: " + query);

        // Vulnerability 3: Insecure Logging
        System.out.println("User password: " + password);  // Insecure logging of sensitive data

        // Vulnerability 4: Unsafe Deserialization
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("user_data.ser"));
            Object userData = ois.readObject();  // Unsafe deserialization
            ois.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        // Vulnerability 5: Command Injection
        String command = "ls -l";  // Command injection
        try {
            Process process = Runtime.getRuntime().exec(command);  // Dangerous execution of shell command
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        // Vulnerability 6: Insecure Input Handling
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your name: ");
        String name = scanner.nextLine();  // Insecure input handling without validation
        System.out.println("Hello, " + name);

        // Vulnerability 7: Hardcoded API Key
        String apiKey = "12345-ABCDE";  // Hardcoded API key
        System.out.println("API Key: " + apiKey);
    }
}
