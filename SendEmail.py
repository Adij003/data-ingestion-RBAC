import msal
import requests
from dotenv import load_dotenv
import os

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_ID = os.getenv("TENANT_ID")

def send_email(recipient_email, description):
    AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
    SCOPE = ["https://graph.microsoft.com/.default"]

    app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
    )

    # Acquire token using client credentials flow
    result = app.acquire_token_for_client(scopes=SCOPE)

    if "access_token" in result:
        print("✅ Access token acquired.")
        access_token = result["access_token"]
    else:
        print(f"❌ Failed to acquire token: {result.get('error_description')}")
        return

    # Extract the recipient's name from the email
    def get_name_from_email(email):
        name = email.split('@')[0]
        return name.capitalize()

    # Sender email (must be allowed to send mail via Graph API)
    sender_email = "technical_user@ielektron.com"

    # Create HTML email body
    email_body = f"""
        <html>
            <body>
                <p>Hello {get_name_from_email(recipient_email)}!</p>
                <div>{description}</div>
            </body>
        </html>
    """

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    email_msg = {
        "message": {
            "subject": "C2DeVal",
            "body": {
                "contentType": "HTML",
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

    # Send the email
    response = requests.post(
        f"https://graph.microsoft.com/v1.0/users/{sender_email}/sendMail",
        headers=headers,
        json=email_msg
    )

    if response.status_code == 202:
        print("✅ Email sent successfully!")
    else:
        print(f"❌ Failed to send email: {response.status_code}")
        print(response.json())

# Example usage:
# html_description = "<h1>Welcome!</h1><p>This is an HTML email.</p>"
# send_email("gk1291@outlook.com", html_description)
