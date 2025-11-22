import re
import tldextract
import os
from fpdf import FPDF
from colorama import Fore, Style
from tabulate import tabulate
from itertools import cycle
import time
from tqdm import tqdm
import json
import sys
from groq import Groq
from vt_url_check import check_url

# List of common phishing keywords
PHISHING_KEYWORDS = [
    # Urgency and Threats 
    "urgent", "immediate action required", "act now", 
    "important notification", "attention required", 
    "final notice", "last chance", "limited time offer", 
    "time-sensitive", "your action is needed", "critical alert",

    # Fear and Panic 
    "account locked", "unauthorized login attempt", 
    "suspicious activity detected", "payment failed", 
    "security compromised", "your account will be closed", 
    "legal action pending", "fraudulent activity", 
    "data breach", "compliance violation", "penalty warning",

    # Requests for Verification or Action 
    "verify your account", "confirm your password", 
    "update your information", "verify your identity", 
    "validate your login", "reset your credentials", 
    "unlock your account", "reactivate your account", 
    "action required", "secure your account", 
    "login to resolve", "check your details", 
    "account verification required", "identity confirmation needed",

    # Fake Opportunities
    "you have won", "prize", "lottery", "gift card", 
    "reward points", "cash back", "free trial", 
    "special offer", "bonus", "claim your prize", 
    "exclusive offer", "VIP access", "redeem now", 
    "get your refund", "win big", "receive funds",

    # Email and Attachment Lures
    "click here", "open attachment", "download invoice", 
    "open document", "secure link", "view statement", 
    "see details", "open this file", "attachment included", 
    "access your account", "follow the link", 
    "view message", "verify transaction", 
    "document awaiting signature",

    # Financial Scams
    "bank details", "credit card information", 
    "account number", "loan approval", 
    "tax refund", "overpayment", "wire transfer", 
    "secure transaction", "unpaid invoice", 
    "billing error", "payment required", "tax reminder", 
    "financial settlement", "claim payment", 
    "unexpected charge",

    # Posing as Authorities or Companies
    "support team", "official request", "banking alert", 
    "customer service", "IT department", "account security", 
    "trusted source", "system administrator", 
    "helpdesk", "technical support", 
    "service provider", "payment gateway", 
    "verification team", "fraud prevention unit", 
    "compliance team", "risk management", 
    "official communication", "important update",

    # Social Engineering Triggers
    "dear customer", "valued user", "trusted account holder", 
    "dear [username]", "greetings", "hello user", 
    "your trusted partner", "dear friend", "important client", 
    "personalized offer", "exclusive invitation", 
    "relationship update", "membership renewal", 
    "VIP customer alert",

    # Technical Jargon and Fake Security Terms
    "SSL certificate expired", "firewall alert", 
    "IP address mismatch", "malware detected", 
    "system scan required", "login attempt failed", 
    "DNS issue", "email server blocked", 
    "invalid credentials", "security token expired", 
    "two-factor authentication disabled", 
    "unauthorized device detected", "server downtime alert", 
    "software update required",

    # Miscellaneous
    "update your email", "confirm email address", 
    "password expiry", "access suspended", 
    "new feature activation", "trial ending soon", 
    "pending message", "storage limit exceeded", 
    "account migration", "new terms of service", 
    "renew your subscription", "membership expired", 
    "close your account", "pending approval",
]

# Initial list of trusted domains
TRUSTED_DOMAINS = [
    # Social Media and Communication Platforms
    "facebook.com", "twitter.com", "linkedin.com", 
    "instagram.com", "whatsapp.com", "snapchat.com", 
    "tiktok.com", "youtube.com", "pinterest.com", 
    "reddit.com", "tumblr.com", "telegram.org", 

    # Search Engines and Tech Giants
    "google.com", "bing.com", "yahoo.com", 
    "duckduckgo.com", "baidu.com", "ask.com", 
    "aol.com", "wolframalpha.com", 

    # E-commerce and Payment Gateways
    "amazon.com", "ebay.com", "alibaba.com", 
    "etsy.com", "walmart.com", "target.com", 
    "flipkart.com", "wayfair.com", "rakuten.com", 
    "shopify.com", "paypal.com", "stripe.com", 
    "squareup.com", "razorpay.com", "zellepay.com", 
    "venmo.com", "skrill.com", "payoneer.com",

    # Technology and Software Providers
    "microsoft.com", "apple.com", "adobe.com", 
    "oracle.com", "ibm.com", "dell.com", 
    "hp.com", "intel.com", "nvidia.com", 
    "samsung.com", "sony.com", "lenovo.com", 
    "asus.com", "acer.com", "logitech.com", 
    "dropbox.com", "slack.com", "atlassian.com", 

    # Email Providers
    "gmail.com", "outlook.com", "yahoo.com", 
    "icloud.com", "protonmail.com", "zoho.com", 
    "fastmail.com", "gmx.com", "mail.ru", 
    "hotmail.com", "yandex.com", 

    # Cloud and Hosting Services
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com", 
    "heroku.com", "digitalocean.com", "linode.com", 
    "vultr.com", "netlify.com", "vercel.com", 

    # Entertainment and Streaming
    "spotify.com", "netflix.com", "hulu.com", 
    "disneyplus.com", "primevideo.com", "hbomax.com", 
    "peacocktv.com", "pandora.com", "soundcloud.com", 
    "deezer.com", "twitch.tv", 

    # News and Media Outlets
    "bbc.com", "cnn.com", "nytimes.com", 
    "theguardian.com", "reuters.com", "bloomberg.com", 
    "forbes.com", "wsj.com", "aljazeera.com", 
    "time.com", "usatoday.com", "ndtv.com", 
    "foxnews.com", 

    # Educational and Research Institutions
    "harvard.edu", "mit.edu", "ox.ac.uk", 
    "stanford.edu", "berkeley.edu", "cam.ac.uk", 
    "edx.org", "coursera.org", "khanacademy.org", 
    "udemy.com", "pluralsight.com", "codecademy.com",

    # Government and Public Services
    "irs.gov", "gov.uk", "canada.ca", 
    "nhs.uk", "australia.gov.au", "europa.eu", 
    "un.org", "nasa.gov", 

    # Financial Institutions
    "visa.com", "mastercard.com", "chase.com", 
    "bankofamerica.com", "wellsfargo.com", 
    "citibank.com", "americanexpress.com", 
    "hsbc.com", "barclays.com", "icicibank.com", 
    "hdfcbank.com", "sbi.co.in", "dbs.com", 

    # Travel and Hospitality
    "booking.com", "airbnb.com", "expedia.com", 
    "tripadvisor.com", "hotels.com", "trivago.com", 
    "skyscanner.net", "kayak.com", "uber.com", 
    "lyft.com", 

    # Miscellaneous
    "github.com", "gitlab.com", "bitbucket.org", 
    "wikipedia.org", "mozilla.org", "zoom.us", 
    "quora.com", "stackoverflow.com", "medium.com", 
    "notion.so", "evernote.com", "trello.com"
]

# Groq API Key
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Function to simulate a loading animation
def loading_animation(message, duration=3):
    spinner = cycle(['|', '/', '-', '\\'])
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(f"\r{message} {next(spinner)}")
        sys.stdout.flush()
        time.sleep(0.1)
    print("\r" + " " * len(message))  # Clear line

# Function to scan email for phishing keywords
def check_phishing_keywords(email_content):
    found_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if re.search(rf"\b{keyword}\b", email_content, re.IGNORECASE):
            found_keywords.append(keyword)
    return found_keywords

# Function to extract URLs from email
def extract_urls(email_content):
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, email_content)
    return urls

# Function to analyze URLs with progress bar
def analyze_urls(urls):
    suspicious_urls = []
    for url in tqdm(urls, desc="Analyzing URLs"):
        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        if domain not in TRUSTED_DOMAINS:
            suspicious_urls.append(url)
    return suspicious_urls

# Function to analyze email with Groq AI
def analyze_with_ai(email_content):
    try:
        client = Groq(api_key=GROQ_API_KEY)
        completion = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert cybersecurity analyst. Analyze the following email content for phishing indicators. Identify suspicious patterns, urgent language, inconsistencies, or mismatched contexts that might be missed by simple keyword matching. Provide a verdict (SAFE, SUSPICIOUS, or PHISHING) and a concise explanation of your reasoning."
                },
                {
                    "role": "user",
                    "content": email_content
                }
            ],
            temperature=0.5,
            max_completion_tokens=1024,
            top_p=1,
            stream=True,
            stop=None
        )

        print(Fore.MAGENTA + "\n--- AI Smart Analysis ---" + Style.RESET_ALL)
        full_response = ""
        for chunk in completion:
            content = chunk.choices[0].delta.content or ""
            print(content, end="")
            full_response += content
        print("\n" + "-" * 30)
        return full_response
    except Exception as e:
        print(Fore.RED + f"\nAI Analysis Error: {e}" + Style.RESET_ALL)
        return None

# Function to read email content from a file
def read_email_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            email_content = file.read()
        return email_content
    except FileNotFoundError:
        print(Fore.RED + "File not found. Please check the file path." + Style.RESET_ALL)
        return None

# Function to generate a PDF report
def generate_report(file_name, keywords, urls):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Phishing Analysis Report", ln=True, align="C")
    pdf.cell(200, 10, txt=f"File: {file_name}", ln=True, align="L")
    pdf.cell(200, 10, txt="Detected Phishing Keywords:", ln=True, align="L")
    pdf.multi_cell(0, 10, ", ".join(keywords) if keywords else "None")
    pdf.cell(200, 10, txt="Suspicious URLs:", ln=True, align="L")
    pdf.multi_cell(0, 10, "\n".join(urls) if urls else "None")
    pdf.output("phishing_report.pdf")
    print(Fore.GREEN + "Report saved as phishing_report.pdf" + Style.RESET_ALL)

# Function to load trusted domains from a file
def load_trusted_domains(file_path="trusted_domains.json"):
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            return json.load(file)
    return TRUSTED_DOMAINS

# Function to save trusted domains to a file
def save_trusted_domains(domains, file_path="trusted_domains.json"):
    with open(file_path, "w") as file:
        json.dump(domains, file)

# CLI Menu
def cli_menu():
    while True:
        print(Fore.CYAN + "\n--- Phishing Detection CLI ---" + Style.RESET_ALL)
        print(Fore.YELLOW + """
        [1] Analyze an Email File
        [2] View Trusted Domains
        [3] Add a Trusted Domain
        [4] Generate a Report
        [5] Show Help
        [6] Exit
        """ + Style.RESET_ALL)

        choice = input(Fore.GREEN + "Enter your choice: " + Style.RESET_ALL)

        if choice == "1":
            file_path = input("Enter the path to the email file: ")
            loading_animation("Analyzing file...")
            email_content = read_email_from_file(file_path)
            if email_content:
                keywords = check_phishing_keywords(email_content)
                urls = extract_urls(email_content)
                suspicious_urls = analyze_urls(urls)

                print(Fore.GREEN + "\nAnalysis Results:" + Style.RESET_ALL)
                if keywords:
                    print(Fore.YELLOW + "Phishing Keywords Found:" + Style.RESET_ALL, keywords)
                else:
                    print(Fore.GREEN + "No Phishing Keywords Found." + Style.RESET_ALL)

                if suspicious_urls:
                    print(Fore.RED + "Suspicious URLs Found:" + Style.RESET_ALL)
                    print(tabulate([[url] for url in suspicious_urls], headers=["Suspicious URLs"]))
                    results = []
                    for u in suspicious_urls:
                        info = check_url(u)
                        results.append(info)
                    print("\nThe reputation of the URL per VirusTotal:")
                    for r in results:
                        print(f"- malicious={r['malicious']} \n- suspicious={r['suspicious']}")

                else:
                    print(Fore.GREEN + "No Suspicious URLs Found." + Style.RESET_ALL)

                # AI Analysis
                analyze_with_ai(email_content)

        elif choice == "2":
            print(Fore.BLUE + "\nTrusted Domains:" + Style.RESET_ALL)
            print(tabulate([[domain] for domain in TRUSTED_DOMAINS], headers=["Trusted Domains"]))

        elif choice == "3":
            new_domain = input("Enter a new trusted domain: ")
            if new_domain not in TRUSTED_DOMAINS:
                TRUSTED_DOMAINS.append(new_domain)
                save_trusted_domains(TRUSTED_DOMAINS)
                print(Fore.GREEN + f"Domain '{new_domain}' added to trusted domains." + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + "Domain already exists in the trusted list." + Style.RESET_ALL)

        elif choice == "4":
            file_name = input("Enter the email file name for the report: ")
            email_content = read_email_from_file(file_name)
            if email_content:
                keywords = check_phishing_keywords(email_content)
                urls = extract_urls(email_content)
                suspicious_urls = analyze_urls(urls)
                generate_report(file_name, keywords, suspicious_urls)

        elif choice == "5":
            print(Fore.CYAN + "\n--- Help Menu ---" + Style.RESET_ALL)
            print("1. Analyze an Email File: Checks for phishing keywords and suspicious URLs.")
            print("2. View Trusted Domains: Lists domains considered safe.")
            print("3. Add a Trusted Domain: Add a new domain to the trusted list.")
            print("4. Generate a Report: Creates a PDF report of the analysis.")
            print("5. Exit: Closes the tool.")

        elif choice == "6":
            print(Fore.CYAN + "Exiting. Goodbye!" + Style.RESET_ALL)
            break

        else:
            print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)

# Run the CLI
if __name__ == "__main__":
    TRUSTED_DOMAINS = load_trusted_domains()  # Load trusted domains
    cli_menu()
