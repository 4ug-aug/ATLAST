imap_host = "outlook.office365.com"
imap_user = "augusttollerup@hotmail.com"
imap_pass = "Pompdelux47"

connection = imaplib.IMAP4_SSL(imap_host)
connection.login(imap_user, imap_pass)

connection.select("Inbox")

amount_of_recent_mails = 100

result, data = connection.uid('search', None, "ALL")
if result == 'OK':
    for num in data[0].split()[:amount_of_recent_mails]:
        result, data = connection.uid('fetch', num, '(RFC822)')
        if result == 'OK':
            email_message = email.message_from_bytes(data[0][1])
            # print(email_message.__dict__)
            print(str(email_message._headers))
connection.close()
connection.logout()