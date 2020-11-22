from utils import identifier as identify
import numpy as np
import pandas as pd

with open("email_source.txt", "r") as f:
    source = f.read()
    f.close()

x = identify(source)

spf, dkim, dmarc, v_ratio, c_ratio = x.spf(), x.dkim(), x.dmarc(), x.ratio_char()[0], x.ratio_char()[1]

# dataset = {"SPF": [1.], "DKIM": [1.], "DMARC": [1.], "Vowel Ratio": [0.29683698], "Consonant Ratio": [0.70316302]}

# df = pd.DataFrame (dataset, columns = ['SPF','DKIM', "DMARC", "Vowel Ratio", "Consonant Ratio"])

df = pd.read_csv('data.csv', index_col=0)

new_observation = [spf, dkim, dmarc, v_ratio, c_ratio]

df.loc[len(df)] = new_observation

df.to_csv('data.csv')