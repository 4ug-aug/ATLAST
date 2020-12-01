""" 
Utility Functions

TODO: Analyse the Email Source

Format:
- DKIM
- SPF
- DMARC
- URLS (URL-SCAN-IO)
- tokenize mailbody (text)
- Return-path equal to sender?

Roadblocks: 
- Convert from html to plaintext if HTML and not plain present (otherwise stick with plaintext)
- Images???
"""
import requests, json, time, re, glob

def get_mails(n):
    import imaplib
    import email
    from email.header import decode_header
    configs = open("config.txt")
    configs = configs.read()
    host = re.findall(r"host_outlook:(.+)", configs)[0]
    email_ = re.findall(r"user:(.+)", configs)[0]
    pword = re.findall(r"password:(.+)",configs)[0]
    connection = imaplib.IMAP4_SSL(host)
    connection.login(email_, pword)

    connection.select("Inbox")
    amount_of_recent_mails = n
    raw_mail_headers = []
    result, data = connection.uid('search', None, "ALL")
    if result == 'OK':
        for num in data[0].split()[:amount_of_recent_mails]:
            result, data = connection.uid('fetch', num, '(RFC822)')
            if result == 'OK':
                email_message = email.message_from_bytes(data[0][1])
                # print(email_message.__dict__)
                print(str(email_message._headers))
                raw_mail_headers.append(str(email_message._headers))
    connection.close()
    connection.logout()

    return raw_mail_headers


def scanURL(urls):
    score = 0
    maliciousnes = 0
    uuids = []
    for url in urls:
        print(url)
        headers = {'API-Key':'920f2c76-d675-429c-8de5-8bfd04470847','Content-Type':'application/json'}
        data = {"url": str(url), "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
        uuid = response.json()["uuid"]
        uuids.append(uuid)
        print("https://urlscan.io/api/v1/result/"+str(uuid))
        r = requests.get("https://urlscan.io/api/v1/result/"+str(uuid))
        print(r.json())


    time.sleep(16)
    for uuid in uuids:
        while True:
            url = "https://urlscan.io/api/v1/result/"+str(uuid)
            print(url)
            r = requests.get(url)
            if "message" in r.json().keys():
                if r.json()["message"] == "Not Found" or r.json()["message"] == "notdone":
                    time.sleep(5)
                    continue
            else:
                # Can add more data
                data = r.json()
                score += data["verdicts"]["overall"]["score"]
                if data["verdicts"]["overall"]["malicious"] == "false":
                    pass
                elif data["verdicts"]["overall"]["malicious"] == "true":
                    maliciousnes += 1
                break
            
    # Calculate mean of score and overall verdict of maliciousnes
    m_score = (score/len(uuids))

    return (m_score, maliciousnes)


class identifier(object):

    def __init__(self, object, live):
        if live:
            import win32com.client
            import pythoncom

        import re

        self.source = object.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001F")
        self.mailbody = object.Body
        f = open("email_source.txt", "w")
        f.write(self.source + "\n\n\n" + self.mailbody)
        f.close()
        self.sender = object.SenderEmailAddress
        

    # Fetch DKIM from the mail body
    # If it is passed return 1 else 0
    def dkim(self):
        try:
            if re.findall(r"dkim=(pass)", self.source)[0]:
                print("Found DKIM Pass")
                return 1
            else:
                print("no DKIM found")
                return 0
        except Exception:
            return 0

    # Fetch DMARC from the mail body
    # If it is none return 1 else 0
    def dmarc(self):
        try:
            if re.findall(r"dmarc=(none)", self.source)[0]:
                print("Found DMARC none")
                return 1
            else:
                print("no DMARC found")
                return 0
        except Exception:
            return 0

    # Fetch SPF from the mail body
    # If it is passed return 1 else 0
    def spf(self):
        try:
            if re.findall(r"spf=(pass)", self.source)[0]:
                print("Found SPF Pass")
                return 1
            else:
                print("no SPF found")
                return 0
        except Exception:
            return 0

    # Fetch all URLS from the mail body
    def urls(self):
        regex = r"<https:\/\/eur05.safelinks.protection.outlook.com\/\?url=3?D?(\S)>"
        regex_no_safelink = r"<(https?:\/\/\S+)>"
        urls = re.findall(regex, self.mailbody)
        urls += re.findall(regex_no_safelink, self.mailbody)
        if len(urls) > 0:
            print("Found {} urls".format(len(urls)))

            return urls
        else:
            return False

    # Find a use for Okpai BM25 instead!

    def ratio_char(self):
        mailbody = self.mailbody.replace(" ", "").replace("\n", "")
        characters = [char for char in mailbody]
        v, c = 0, 0
        for i in characters:
            if i in ["a","e","i","o","u","y"]:
                v += 1
            else:
                c += 1

        # Might need to be improved
        v_ratio, c_ratio = v/len(characters), c/len(characters)
        print("Found ratios v_ratio {}, c_ratio {}".format(v_ratio, c_ratio))
        return (v_ratio, c_ratio)


    # Obsolete for now
    def return_sender(self):
        regex_from_adress = r"From:\s\S+\s?<(\S+\@\S+)>"
        regex_return_path = r"Return-Path:\s?(.+)"
        pass

    def sender_address(self):
        print("Found sender: {}".format(self.sender))
        return self.sender

    #################################
    # Add function to detect grammar errors. Wrongly spelled words, syntax (very complex)
    #################################


