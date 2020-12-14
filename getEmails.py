import imaplib
import email
from email.header import decode_header
import re
import html2text


def fetchHeaders(N):
    imap = imaplib.IMAP4_SSL("outlook.office365.com")

    username = "augusttollerup@hotmail.com"
    password = "Pompdelux47"

    imap.login(username, password)

    status, messages = imap.select("INBOX")

    messages = int(messages[0])

    lst = []

    for i in range(messages, messages-N, -1):
        # fetch the email message by ID
        res, msg = imap.fetch(str(i), "(RFC822)")
        for response in msg:
            if isinstance(response, tuple):
                msg = email.message_from_bytes(response[1])
                headers = dict(msg._headers)
                # print(headers)
                return_path = headers.get("Return-Path")
                from_ = headers.get("From").split(" ")[-1].replace("<","").replace(">","")
                origin = headers.get("X-OriginatorOrg")
                sender_ip = headers.get("X-Sender-IP")
                
                # if there are no authentication headers we are inherently suspicious
                spf = 1
                dkim = 1
                dmarc = 1
                return_from = 1

                auth = headers.get("Authentication-Results")
                if auth != None:
                    spf = re.findall(r"spf=(\w+)",auth)[0]
                    dkim = re.findall(r"dkim=(\w+)",auth)[0]
                    dmarc = re.findall(r"dmarc=(\w+)",auth)[0]
                    return_from = 0
                    if spf == "pass":
                        spf = 0
                    if dkim == "pass":
                        dkim = 0
                    if dmarc == "None":
                        dmarc = 0
                if return_path != None:
                    return_path = return_path.replace("\n", "").replace("\r","")
                    if from_ != return_path:
                        return_from = 1



        lst.append((return_from,return_path,from_,origin,sender_ip,spf,dkim,dmarc))
    imap.close()
    imap.logout()

    return(lst)

def fetchBodies(N):

    imap = imaplib.IMAP4_SSL("outlook.office365.com")

    username = "augusttollerup@hotmail.com"
    password = "Pompdelux47"

    imap.login(username, password)

    status, messages = imap.select("INBOX")

    messages = int(messages[0])
    
    for i in range(messages, messages-N, -1):
        res, msg = imap.fetch(str(i), "(RFC822)")
        for response in msg:
            if isinstance(response, tuple):
                msg = email.message_from_bytes(response[1])
                
                if msg.is_multipart():
                    for part in msg.walk():
                        # extract content type of email
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))

                        if content_type == "text/plain" and "attachment" not in content_disposition:
                        # print text/plain emails and skip attachments
                            print(part.get_payload(decode=True))
                        elif content_type == "text/html" and "attachment" not in content_disposition:
                            print(part.get_payload(decode=True))

    imap.close()
    imap.logout()

fetchBodies(5)

