import re
import sqlite3
from email.utils import parsedate_to_datetime
from google_auth_oauthlib.flow import InsatlledAppFlow, InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import pickle
import os
import base64
from bs4 import BeautifulSoup

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def normalize_date(date_str):
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        return None

def clean_email(text):
    text = re.split(r'\n--\s*\n', text)[0]   # signature separator
    text = re.split(r'Sent from my', text, flags=re.IGNORECASE)[0]
    text = re.sub(r'\n+', '\n', text)
    return text.strip()

def authenticate():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle','rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)

        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)

def get_body(payload):
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                return base64.urlsafe_b64decode(
                    part['body']['data']).decode('utf-8', errors='ignore')
            if part['mimeType'] == 'text/html':
                html = base64.urlsafe_b64decode(
                    part['body']['data']).decode('utf-8', errors='ignore')
                return BeautifulSoup(html, "html.parser").get_text()
    else:
        return base64.urlsafe_b64decode(
            payload['body']['data']).decode('utf-8', errors='ignore')
    return ""

def fetch_last_50_emails(service):
    results = service.users().messages().list(
        userId='me', maxResults=50).execute()

    messages = results.get('messages', [])

    emails = []

    for msg in messages:
        data = service.users().messages().get(
            userId='me', id=msg['id'], format='full').execute()

        headers = data['payload']['headers']
        subject = from_email = date = ""

        for h in headers:
            if h['name'] == 'Subject':
                subject = h['value']
            if h['name'] == 'From':
                from_email = h['value']
            if h['name'] == 'Date':
                date = h['value']

        body = get_body(data['payload'])

        emails.append({
            "id": msg['id'],
            "subject": subject,
            "from": from_email,
            "date": date,
            "snippet": data.get('snippet'),
            "body": body
        })

    return emails

if __name__ == "__main__":
    service = authenticate()
    emails = fetch_last_50_emails(service)

    for e in emails:
        print("="*60)
        print("FROM:", e['from'])
        print("SUBJECT:", e['subject'])
        print("DATE:", e['date'])
        print("SNIPPET:", e['snippet'])

def classify_priority(email):
    text = (email['subject'] + " " + email['body']).lower()

    # 1️ SECURITY ALWAYS WINS
    SECURITY_KEYWORDS = [
        "security alert", "unusual activity",
        "new sign-in", "password",
        "verification", "confirm identity",
        "suspicious", "login attempt"
    ]

    if any(k in text for k in SECURITY_KEYWORDS):
        return "HIGH"

    # 2️ TIME-SENSITIVE / IMPORTANT
    HIGH_KEYWORDS = [
        "deadline", "last day", "only",
        "hours left", "today", "tonight",
        "interview", "offer",
        "payment failed",
        "exam", "submission",
        "certificate", "due tomorrow"
    ]

    if any(k in text for k in HIGH_KEYWORDS):
        return "HIGH"

    # 3️ MARKETING / NOISE
    LOW_KEYWORDS = [
        "newsletter", "unsubscribe",
        "promo", "sale", "discount",
        "offers", "digest", "update"
    ]

    if any(k in text for k in LOW_KEYWORDS):
        return "LOW"

    # 4️ DEFAULT
    return "MEDIUM"

# 1. connect
conn = sqlite3.connect("emails.db")
cursor = conn.cursor()

# 2. create table
if __name__ == "__main__":
    service = authenticate()

    emails = fetch_last_50_emails(service)
    print("Fetched emails:", len(emails))

    conn = sqlite3.connect("emails.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id TEXT PRIMARY KEY,
        sender TEXT,
        subject TEXT,
        date TEXT,
        snippet TEXT,
        body TEXT,
        priority TEXT
    )
    """)

    for e in emails:
        priority = classify_priority(e)
        cursor.execute("""
            INSERT OR IGNORE INTO emails
            (id, sender, subject, date, snippet, body, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            e['id'],
            e['from'],
            e['subject'],
            normalize_date(e['date']),
            e['snippet'],
            e['body'],
            priority
        ))

    conn.commit()

    cursor.execute("""
        SELECT subject, priority FROM emails
        ORDER BY date DESC LIMIT 10
    """)
    print(cursor.fetchall())

    conn.close()





