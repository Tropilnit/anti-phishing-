# anti-phishing-
anti phishing scanner for URLs
import string
import urllib.parse



def scan_link_safety(url):

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
    except Exception:
        return "❌ INVALID URL: Please check the link structure."

   
    dangerous_keywords = ["login", "verify", "secure", "bank", "update-account", "free-gift", "signin"]
    known_scam_domains = ["free-netflix.com", "account-security-help.cc", "payment-login-verify.net"]
    trusted_domains = ["google.com", "microsoft.com", "github.com", "devpost.com", "wikipedia.org"]

    # Check 1: Known malicious domains
    if any(scam in domain for scam in known_scam_domains):
        return f"🚨 CRITICAL DANGER: The domain '{domain}' is blacklisted as a known phishing site! Block connection immediately."

    # Check 2: Absolute Trusted Domains
    if any(trusted in domain for trusted in trusted_domains):
        return f"🟢 VERIFIED SAFE: '{domain}' is a recognized, highly trusted platform."

    # Check 3: Hidden Subdomain Masking (e.g., ://attacker.com)
    if domain.count('.') > 2:
        return f"⚠️ HIGH RISK: Suspicious subdomain nesting detected. The real destination is '{domain}', which might be masking as another site."

    # Check 4: Deceptive Keyword Matching
    flagged_words = [word for word in dangerous_keywords if word in url.lower()]
    if flagged_words:
        return f"🟡 WARNING: Potential Phishing. This link contains urgent words {flagged_words} on an unverified domain. Proceed with caution."

    
    if parsed_url.scheme == 'http':
        return "⚠️ MODERATE RISK: This site uses unencrypted HTTP instead of secure HTTPS. Data sent here could be intercepted."

    return f"🟢 LOW RISK: The link '{domain}' looks clean under current algorithmic checks."


print("=========================================")
print("🛡️   DIGITAL ANTI-PHISHING SHIELD   🛡️")
print("=========================================")
user_link = input("Paste a URL / Link to scan for cyber threats: ")
print("-----------------------------------------")
print("Running heuristic protocol scan...")
print(scan_link_safety(user_link))
print("=========================================")
