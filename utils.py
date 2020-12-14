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


TODO:
Der skal seriøst fixes hvordan emailobjectet bliver modtaget.
Der skal tages højde for om mailbodien er encoded eller ej. Mailbodien skal desuden konverteres til plain text og der skal findes urler i den.

"""
import requests, json, time, re, glob, base64

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
        self.source = object.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x007D001F")
        self.mailbody = object.Body
        f = open("email_source.txt", "w")
        f.write(self.source + "\n\n\n" + self.mailbody)
        f.close()
        self.sender = object.SenderEmailAddress

        

    # Fetch DKIM from the mail body
    # If it is passed return 1 else 0
    def dkim(self):
        if re.findall(r"dkim=(pass)", self.source)[0]:
            print("Found DKIM Pass")
            return 1
        else:
            print("no DKIM found")
            return 0

    # Fetch DMARC from the mail body
    # If it is none return 1 else 0
    def dmarc(self):
        if re.findall(r"dmarc=(none)", self.source)[0]:
            print("Found DMARC none")
            return 1
        else:
            print("no DMARC found")
            return 0


    # Fetch SPF from the mail body
    # If it is passed return 1 else 0
    def spf(self):
        if re.findall(r"spf=(pass)", self.source)[0]:
            print("Found SPF Pass")
            return 1
        else:
            print("no SPF found")
            return 0

    # Fetch all URLS from the mail body
    def urls(self):
        if self.mailbody:
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
        if self.mailbody:
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
        else:
            return (0,0)


    # Obsolete for now
    def return_sender(self):
            regex_from_adress = r"From:\s\S+\s?<(\S+\@\S+)>"
            regex_return_path = r"Return-Path:\s?(.+)"
            

    def sender_address(self):
        if self.sender != None:
            print("Found sender: {}".format(self.sender))
            return self.sender
        else:
            return None

    #################################
    # Add function to detect grammar errors. Wrongly spelled words, syntax (very complex)
    #################################


class identify_notlive(object):


    def __init__(self, object):

        # print(object.__dict__)

        spf, dkim, return_sender, sender, urls = 0, 0, 0, "", []
        import re
        import html2text, quopri
        h = html2text.HTML2Text()

        print(object.get_payload(decode=True))

        self.source = object._headers
        # self.mailbody = object._payload[0].set_charset("utf-8").__str__()
        if object.__getitem__("_default_type") == "text/html":
            self.mailbody = h.handle(base64.b64decode(object._payload[0]))


        unquoted = quopri.decodestring(self.mailbody)
        tmp_unicode = unquoted.decode('latin-1', errors='ignore')
        u8 = tmp_unicode.encode('utf-8')
        print(u8)

        self.sender = object.__getitem__("from")
        self.Auth = object.__getitem__("Authentication-Results")

        if "pass" in re.findall(r"spf=(\w+)",self.Auth):
            spf = 1
        if "none" in re.findall(r"dkim=(\w+)", self.Auth):
            dkim = 1
        
        if object.__getitem__("from") != object.__getitem__("Return-Path"):
            return_sender = 1

        # return (spf, dkim, return_sender, sender, urls)
        