from flask import (flash, jsonify, make_response, render_template, redirect,
                   request, url_for)

import logging

from cvechk import app
from cvechk.forms import CVEInputForm, ResultsForm
from cvechk.osmods import mod_rhel, mod_ubuntu
from cvechk.utils import get_cve_text, redis_get_data

viewlogger = logging.getLogger('cvelogger.views')


@app.route('/')
def display_index():
    return render_template('index.html', form=CVEInputForm())


@app.route('/privacy')
def display_privacy():
    return render_template('privacy.html')


@app.route('/results', methods=['POST'])
def results():
    form_cveinput = CVEInputForm()
    data = {}

    if form_cveinput.validate_on_submit():
        oschoice = form_cveinput.uos.data
        cvetext = form_cveinput.uinputtext.data.strip()

        cves = get_cve_text(cvetext)
        try:
            data = redis_get_data(oschoice, cves)
        except:
            viewlogger.exception('Unable to connect to Redis instance')

        if not data:
            for cve in cves:
                if oschoice.startswith('EL'):
                    data = mod_rhel.rh_get_data(oschoice, cve)
                if oschoice.startswith('UBU'):
                    data = mod_ubuntu.get_cve_data(cve, oschoice)

        return render_template('results.html', form=ResultsForm(),
                               data=data, os=oschoice)
    else:
        flash('No data entered, please enter some data in the field above.')
        return redirect(url_for('display_index'))
