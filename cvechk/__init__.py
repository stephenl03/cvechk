from flask import Flask
from datetime import datetime
import logging
import os

app = Flask(__name__)
app.config.from_object('config')

logdir = './logs'
logfile = os.path.join(logdir, 'cvechk.log') 

if not os.path.exists(logdir):
    os.mkdir(logdir)

cvelogger = logging.getLogger('cvelogger')
cvelogger.setLevel(logging.INFO)
logformatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s',
                                 datefmt='%Y-%m-%d %H:%M:%S')
# # use current date and time for log file name for clarity
timenow = datetime.now().strftime('%Y%m%d-%H%M')
fh = logging.FileHandler(logfile)
fh.setFormatter(logformatter)
cvelogger.addHandler(fh)

from cvechk import views
