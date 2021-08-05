import datetime

def tprint(text):
  stamp = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
  print(stamp + ': ' + str(text))

