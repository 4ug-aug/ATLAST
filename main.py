"""
Author: August Tollerup

Feature to add:
*
Client based database and a combined database.

Run the Anomaly detection on client based database and run visualising on the combined database.
Allow the user/corporation to visualise their threat sources and where to reinforce deffence.
*

Collect the last 150 mails from a client and run Neural Network for Anomaly detection on these.
Afterwards the systems should analyse each mail parallel to the clients operations.

"""
from utils import identifier as identify
from getEmails import fetchHeaders
import utils
import commit
import pandas as pd
import platform

live = False
if platform.system() == "Windows":
    live = True
    import win32com.client
    import pythoncom

def parse_live(mailobject):
    
    x = identify(mailobject, live)

    spf, dkim, dmarc, v_ratio, c_ratio, sender = x.spf(), x.dkim(), x.dmarc(), x.ratio_char()[0], x.ratio_char()[1], x.sender_address()

    urls = x.urls()

    m_score = None
    maliciousnes = None

    if urls:
        urlScan = utils.scanURL(urls)
        m_score = urlScan[0]
        maliciousnes = urlScan[1]

    df = pd.read_csv('data.csv', index_col=0)

    new_observation = [spf, dkim, dmarc, v_ratio, c_ratio, sender, m_score, maliciousnes]

    df.loc[len(df)+1] = new_observation
    print("Added new observation to row: {} in dataframe".format(len(df)))

    df.to_csv('data.csv')


    print("pushing new database to github")
    commit.commit_database()

def parse(MailsToGet):

    df = pd.read_csv('data.csv', index_col=0)

    emails = fetchHeaders(MailsToGet)

    for tuple_ in emails:

        new_observation = [tuple_[-3], tuple_[-2], tuple_[-1], 0, 0,tuple_[2],tuple_[1], tuple_[-4], tuple_[0], 0, 0]

        df.loc[len(df)+1] = new_observation
        print("Added new observation to row: {} in dataframe".format(len(df)))

        df.to_csv('data.csv')


    print("pushing new database to github")
    commit.commit_database()

parse(15)

def run_live():
    class Handler_Class(object):
        """Endless outlook hook for fetching new emails from main inbox

        Args:
            Mail Object

        Returns:
            returns None
        """

        def OnNewMailEx(self, receivedItemsIDs):
            for ID in receivedItemsIDs.split(","):
                mail = outlook.Session.GetItemFromID(ID)
                
                print("parsing new email to database")
                parse_live(mail)

    outlook = win32com.client.DispatchWithEvents("Outlook.Application", Handler_Class)

    #and then an infinit loop that waits from events.
    pythoncom.PumpMessages()



