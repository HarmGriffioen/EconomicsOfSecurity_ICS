import pandas as pd

df = pd.read_json('bacnet.json', lines=True)
df['timestamp'] = pd.to_datetime(df['timestamp'], infer_datetime_format = True)
print df['org'].value_counts().head()

att = df[df['org']=='AT&T Internet Services']
atttime = att['timestamp']

atttime.groupby(atttime.dt.month).count().plot(kind="line")