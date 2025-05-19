import msal
from msal import ConfidentialClientApplication 
import requests 
import json

from dotenv import load_dotenv
import os
load_dotenv()

CLIENT_SECRET = os.getenv("CLIENT_SECRET")
CLIENT_ID = os.getenv("CLIENT_ID")
TENANT_ID = os.getenv("TENANT_ID")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["https://graph.microsoft.com/.default"]  

app = msal.ConfidentialClientApplication(
    client_id=CLIENT_ID,
    client_credential=CLIENT_SECRET,
    # authority=AUTHORITY,
)

# Acquire token using client credentials flow
result = app.acquire_token_for_client(scopes=SCOPE)

if "access_token" in result:
    print("✅ Access token acquired.")
    access_token = result["access_token"]
else:
    print(f"❌ Failed to acquire token: {result.get('error_description')}")
	

# Extract the sender's name from the email
def get_name_from_email(email):
    # Strip the domain part of the email to get the name
    name = email.split('@')[0]
    return name.capitalize()

# Define sender email (change this to the actual sender email you're using for the app)

sender_email = "technical_user@ielektron.com"
#recipient_email = "gopalakrishna@ielektron.com"
recipient_email ="anuragsingh.bisen@ielektron.com"

# Create email body with sender's name
email_body = f"Hello {get_name_from_email(recipient_email)}! This is a test email from DigiVidya team"

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

email_msg = {
    "message": {
        "subject": "DigiVidya",
        "body": {
            "contentType": "Text",
            "content": email_body
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": recipient_email
                }
            }
        ]
    }
}

# Use the correct endpoint with the sender email
response = requests.post(
    f"https://graph.microsoft.com/v1.0/users/{sender_email}/sendMail",  # Sender email here
    headers=headers,
    json=email_msg
)

if response.status_code == 202:
    print("✅ Email sent successfully!")
else:
    print(f"❌ Failed to send email: {response.status_code}")
    print(response.json())
