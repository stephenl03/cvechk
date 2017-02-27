from flask import Flask
from os import urandom

app = Flask(__name__)
app.config.from_object('config')
app.config['SECRET_KEY'] = urandom(32)

from cvechk import views