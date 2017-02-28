from flask import render_template, flash, redirect, session, url_for, request

from cvechk import app
from cvechk.forms import CVEInputForm, ResultsForm
from cvechk.osmods import mod_rhel


@app.route('/')
def display_index():
    return render_template('index.html', form=CVEInputForm())


@app.route('/submit_check', methods=['POST'])
def submit_check():
    form_cveinput = CVEInputForm()
    form_results = ResultsForm()

    oschoice = form_cveinput.uos.data
    cvetext = form_cveinput.uinputtext.data.strip()

    return render_template('results.html', form=ResultsForm())
