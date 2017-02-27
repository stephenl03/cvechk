from flask import render_template, flash, redirect, session, url_for, request

from cvechk import app
from cvechk.forms import CVEInputForm


@app.route('/')
def display_index():
    return render_template('index.html', form=CVEInputForm())


@app.route('/submit_check', methods=['POST'])
def submit_check():
    pass
