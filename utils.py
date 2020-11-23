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
import re, requests, json


def scanURL(url):
    headers = {'API-Key':'$apikey','Content-Type':'application/json'}
    data = {"url": "https://urlyouwanttoscan.com/path/", "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))


class identifier(object):

    def __init__(self, source):

        # For future functionality this should fetch from MIME object, nok via regex
        regex = r"Content-type: text\/plain;\s+\S+\nContent-transfer-encoding: \S+\n\n((.|\n)*)Content-type:"

        self.source = source
        self.mailbody = max(re.findall(regex, self.source)[0])
        

    # Fetch DKIM from the mail body
    # If it is passed return 1 else 0
    def dkim(self):
        try:
            if re.findall(r"dkim=(pass)", self.source)[0]:
                print("Found DKIM Pass")
                return 1
            else:
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
                return 0
        except Exception:
            return 0

    # Fetch all URLS from the mail body
    def urls(self):
        regex = r'"https:\/\/eur05.safelinks.protection.outlook.com\/\?url=3?D?(\S)"'
        urls = re.findall(regex, self.source)

        return urls

    # Needs to be tokenized on the mailbody and not the source

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
        
        return (v_ratio, c_ratio)


    # Obsolete for now
    def return_sender(self):
        regex_from_adress = r"From:\s\S+\s?<(\S+\@\S+)>"
        regex_return_path = r"Return-Path:\s?(.+)"
        pass

    pass


class formatter(object):

    def __init__(self):
        pass



    pass
