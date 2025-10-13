#!/usr/bin/env python3
"""
Complete Security Testing Demo Runner
Orchestrates the entire security testing and defense demonstration
"""

import subprocess
import time
import requests
import json
import os
import threading
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict

class SecurityDemoOrchestrator:
    def __init__(self):
        self.webapp_process = None
        self.results = {
            'attacks': [],
            'defenses': [],
            'metrics': defaultdict(int),
            'timeline': []
        }
        
    def start_webapp(self):
        """Start the vulnerable web application"""
        print("🚀 Starting  vulnerable web application...")
        try:
            self.webapp_process = subprocess.Popen(
                ['python', 'vulnerable_webapp.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for webapp to start
            time.sleep(5)
            
            # Test if webapp is running
            response = requests.get('http://localhost:5000', timeout=5)
            if response.status_code == 200:
                print("✅ Web application started successfully")
                return True
            else:
                print("❌ Web application failed to start properly")
                return False
                
        except Exception as e:
            print(f"❌ Failed to start web application: {e}")
            return False
    
    def stop_webapp(self):
        """Stop the web application"""
        if self.webapp_process:
            self.webapp_process.terminate()
            print("🛑 Web application stopped")
    
    def run_attack_scenario(self, scenario_name, attack_function):
        """Run a specific attack scenario and record results"""
        print(f"\n🗡️ Running {scenario_name}...")
        start_time = datetime.now()
        
        try:
            results = attack_function()
            success = len([r for r in results if 'SUCCESS' in str(r)]) > 0
            
            self.results['attacks'].append({
                'scenario': scenario_name,
                'timestamp': start_time.isoformat(),
                'success': success,
                'results': results,
                'duration': (datetime.now() - start_time).total_seconds()
            })
            
            if success:
                self.results['metrics']['successful_attacks'] += 1
                print(f"⚠️ {scenario_name} - VULNERABILITIES FOUND")
            else:
                print(f"✅ {scenario_name} - NO VULNERABILITIES")
                
        except Exception as e:
            print(f"❌ Error in {scenario_name}: {e}")
            
        self.results['timeline'].append({
            'time': start_time.isoformat(),
            'event': f"Attack: {scenario_name}",
            'type': 'attack'
        })
    
    def run_defense_test(self, test_name, defense_function):
        """Run defense effectiveness test"""
        print(f"\n🛡️ Testing {test_name}...")
        start_time = datetime.now()
        
        try:
            results = defense_function()
            
            self.results['defenses'].append({
                'test': test_name,
                'timestamp': start_time.isoformat(),
                'results': results,
                'duration': (datetime.now() - start_time).total_seconds()
            })
            
            print(f"📊 {test_name} - COMPLETED")
            
        except Exception as e:
            print(f"❌ Error in {test_name}: {e}")
        
        self.results['timeline'].append({
            'time': start_time.isoformat(),
            'event': f"Defense Test: {test_name}",
            'type': 'defense'
        })
    
    def sql_injection_demo(self):
        """Demonstrate SQL injection attack"""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT 1,username,password FROM users--"
        ]
        
        results = []
        for payload in payloads:
            try:
                response = requests.post(
                    'http://localhost:5000/vulnerable_login',
                    data={'username': payload, 'password': 'test'},
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        results.append(f"SUCCESS: {payload} - {data.get('message')}")
                        self.results['metrics']['sql_injection_success'] += 1
                    else:
                        results.append(f"FAILED: {payload}")
                else:
                    results.append(f"ERROR: {payload} - Status {response.status_code}")
                    
            except Exception as e:
                results.append(f"ERROR: {payload} - {str(e)}")
        
        return results
    
    def brute_force_demo(self):
        """Demonstrate brute force attack"""
        credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', 'admin123'),
            ('user', 'password'),
            ('test', 'test123'),
            ('guest', 'guest')
        ]
        
        results = []
        for username, password in credentials:
            try:
                response = requests.post(
                    'http://localhost:5000/vulnerable_login',
                    data={'username': username, 'password': password},
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        results.append(f"SUCCESS: {username}:{password}")
                        self.results['metrics']['brute_force_success'] += 1
                    else:
                        results.append(f"FAILED: {username}:{password}")
                        
            except Exception as e:
                results.append(f"ERROR: {username}:{password} - {str(e)}")
                
        return results
    
    def directory_traversal_demo(self):
        """Demonstrate directory traversal attack"""
        payloads = [
            'sensitive_config.txt',
            '../sensitive_config.txt',
            '../../etc/passwd',
            '../../../etc/passwd',
            '..\\..\\windows\\system32\\drivers\\etc\\hosts'
        ]
        
        results = []
        for payload in payloads:
            try:
                response = requests.get(
                    f'http://localhost:5000/files/{payload}',
                    timeout=5
                )
                
                if response.status_code == 200 and len(response.text) > 10:
                    results.append(f"SUCCESS: {payload} - File accessible")
                    self.results['metrics']['directory_traversal_success'] += 1
                else:
                    results.append(f"FAILED: {payload}")
                    
            except Exception as e:
                results.append(f"ERROR: {payload} - {str(e)}")
                
        return results
    
    def test_rate_limiting(self):
        """Test rate limiting effectiveness"""
        results = []
        blocked_count = 0
        
        # Test rate limiting on secure endpoint
        for i in range(10):
            try:
                response = requests.post(
                    'http://localhost:5000/secure_login',
                    data={'username': 'test', 'password': 'wrong'},
                    timeout=5
                )
                
                if response.status_code == 429:
                    blocked_count += 1
                    results.append(f"Request {i+1}: BLOCKED (429)")
                else:
                    results.append(f"Request {i+1}: ALLOWED ({response.status_code})")
                    
                time.sleep(0.5)
                
            except Exception as e:
                results.append(f"Request {i+1}: ERROR - {str(e)}")
        
        self.results['metrics']['rate_limit_blocks'] = blocked_count
        results.append(f"Total blocked: {blocked_count}/10")
        
        return results
    
    def test_input_validation(self):
        """Test input validation effectiveness"""
        malicious_inputs = [
            '<script>alert("XSS")</script>',
            'A' * 1000,  # Long input
            "'; DROP TABLE users; --",
            '../../../etc/passwd',
            '<img src=x onerror=alert(1)>'
        ]
        
        results = []
        blocked_count = 0
        
        for malicious_input in malicious_inputs:
            try:
                # Test search endpoint
                response = requests.get(
                    'http://localhost:5000/secure_search',
                    params={'q': malicious_input},
                    timeout=5
                )
                
                # Check if input was properly sanitized
                if malicious_input not in response.text:
                    blocked_count += 1
                    results.append(f"INPUT SANITIZED: {malicious_input[:30]}...")
                else:
                    results.append(f"INPUT REFLECTED: {malicious_input[:30]}...")
                    
            except Exception as e:
                results.append(f"ERROR testing: {malicious_input[:30]}... - {str(e)}")
        
        self.results['metrics']['input_validation_blocks'] = blocked_count
        results.append(f"Total sanitized: {blocked_count}/{len(malicious_inputs)}")
        
        return results
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\n📊 GENERATING SECURITY REPORT")
        print("=" * 50)
        
        # Attack Summary
        total_attacks = len(self.results['attacks'])
        successful_attacks = sum(1 for attack in self.results['attacks'] if attack['success'])
        
        print(f"\n🗡️ ATTACK SUMMARY:")
        print(f"Total attack scenarios: {total_attacks}")
        print(f"Successful attacks: {successful_attacks}")
        print(f"Attack success rate: {(successful_attacks/total_attacks)*100:.1f}%" if total_attacks > 0 else "0%")
        
        # Defense Summary
        print(f"\n🛡️ DEFENSE SUMMARY:")
        print(f"Rate limiting blocks: {self.results['metrics']['rate_limit_blocks']}")
        print(f"Input validation blocks: {self.results['metrics']['input_validation_blocks']}")
        
        # Vulnerability Details
        print(f"\n⚠️ VULNERABILITIES FOUND:")
        if self.results['metrics']['sql_injection_success'] > 0:
            print(f"- SQL Injection: {self.results['metrics']['sql_injection_success']} successful")
        if self.results['metrics']['brute_force_success'] > 0:
            print(f"- Brute Force: {self.results['metrics']['brute_force_success']} successful")
        if self.results['metrics']['directory_traversal_success'] > 0:
            print(f"- Directory Traversal: {self.results['metrics']['directory_traversal_success']} successful")
        
        # Security Recommendations
        print(f"\n🔧 SECURITY RECOMMENDATIONS:")
        if successful_attacks > 0:
            print("- Implement input validation on all endpoints")
            print("- Use parameterized queries to prevent SQL injection")
            print("- Implement proper file access controls")
            print("- Add rate limiting to all sensitive endpoints")
            print("- Deploy Web Application Firewall (WAF)")
        else:
            print("- Current security measures appear effective")
            print("- Continue regular security testing")
            print("- Monitor security logs for anomalies")
        
        return {
            'total_attacks': total_attacks,
            'successful_attacks': successful_attacks,
            'vulnerabilities_found': successful_attacks > 0,
            'recommendations': 5 if successful_attacks > 0 else 3
        }
    
    def create_visualizations(self):
        """Create security testing visualizations"""
        try:
            import matplotlib.pyplot as plt
            
            # Attack success/failure pie chart
            successful = sum(1 for attack in self.results['attacks'] if attack['success'])
            failed = len(self.results['attacks']) - successful
            
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
            
            # Attack Results Pie Chart
            ax1.pie([successful, failed], labels=['Successful', 'Failed'], 
                   colors=['red', 'green'], autopct='%1.1f%%')
            ax1.set_title('Attack Success Rate')
            
            # Defense Effectiveness Bar Chart
            defenses = ['Rate Limiting', 'Input Validation', 'File Access Control']
            effectiveness = [
                min(100, (self.results['metrics']['rate_limit_blocks'] / 10) * 100),
                min(100, (self.results['metrics']['input_validation_blocks'] / 5) * 100),
                100 if self.results['metrics']['directory_traversal_success'] == 0 else 0
            ]
            
            ax2.bar(defenses, effectiveness, color=['blue', 'green', 'orange'])
            ax2.set_title('Defense Effectiveness (%)')
            ax2.set_ylabel('Effectiveness %')
            ax2.set_ylim(0, 100)
            
            plt.tight_layout()
            plt.savefig('security_report.png', dpi=300, bbox_inches='tight')
            print("📈 Security visualization saved as 'security_report.png'")
            
        except ImportError:
            print("📊 Matplotlib not available for visualizations")
        except Exception as e:
            print(f"❌ Error creating visualizations: {e}")
    
    def save_detailed_results(self):
        """Save detailed results to JSON file"""
        with open('detailed_security_results.json', 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print("💾 Detailed results saved to 'detailed_security_results.json'")
    
    def run_complete_demo(self):
        """Run the complete security demonstration"""
        print("🔒 COMPREHENSIVE SECURITY TESTING DEMONSTRATION")
        print("=" * 55)
        
        # Start web application
        if not self.start_webapp():
            return False
        
        try:
            # Run attack scenarios
            print("\n🗡️ ATTACK PHASE - Testing Vulnerabilities")
            print("-" * 40)
            
            self.run_attack_scenario("SQL Injection", self.sql_injection_demo)
            time.sleep(2)
            
            self.run_attack_scenario("Brute Force Attack", self.brute_force_demo)
            time.sleep(2)
            
            self.run_attack_scenario("Directory Traversal", self.directory_traversal_demo)
            time.sleep(2)
            
            # Run defense tests
            print("\n🛡️ DEFENSE PHASE - Testing Security Controls")
            print("-" * 42)
            
            self.run_defense_test("Rate Limiting", self.test_rate_limiting)
            time.sleep(2)
            
            self.run_defense_test("Input Validation", self.test_input_validation)
            time.sleep(2)
            
            # Generate reports
            print("\n📋 ANALYSIS PHASE - Generating Reports")
            print("-" * 38)
            
            self.generate_security_report()
            self.create_visualizations()
            self.save_detailed_results()
            
            print("\n✅ DEMONSTRATION COMPLETE!")
            print("Check the following files for detailed results:")
            print("- detailed_security_results.json")
            print("- security_report.png")
            print("- security_log.txt (from web application)")
            
            return True
            
        finally:
            self.stop_webapp()

def main():
    """Main execution function"""
    print("Starting comprehensive security testing demonstration...")
    
    # Check prerequisites
    required_files = ['vulnerable_webapp.py']
    for file in required_files:
        if not os.path.exists(file):
            print(f"❌ Required file missing: {file}")
            print("Please ensure all project files are in the current directory.")
            return
    
    # Run demonstration
    orchestrator = SecurityDemoOrchestrator()
    success = orchestrator.run_complete_demo()
    
    if success:
        print("\n🎉 Security demonstration completed successfully!")
        print("\nKey Learning Points:")
        print("- Wfuzz and similar tools can quickly identify vulnerabilities")
        print("- Proper input validation prevents most common attacks")
        print("- Rate limiting effectively stops brute force attempts")
        print("- Defense-in-depth provides comprehensive protection")
        print("- Continuous monitoring is essential for security")
    else:
        print("\n❌ Demonstration failed. Please check the setup and try again.")

if __name__ == "__main__":
    main()