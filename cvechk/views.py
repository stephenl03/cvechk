from flask import flash, render_template, redirect, url_for, request, \
                  jsonify

from cvechk import app
from cvechk.forms import CVEInputForm, ResultsForm
from cvechk.osmods import mod_rhel
from cvechk.utils import get_cve_text, redis_get_data


@app.route('/')
def display_index():
    return render_template('index.html', form=CVEInputForm())


@app.route('/results', methods=['POST'])
def results():
    form_cveinput = CVEInputForm()

    if form_cveinput.validate_on_submit():
        oschoice = form_cveinput.uos.data
        cvetext = form_cveinput.uinputtext.data.strip()

        cves = get_cve_text(cvetext)

        data = redis_get_data(oschoice, cves)
        if not data:
            data = mod_rhel.rh_get_data(oschoice, cves)

        return render_template('results.html', form=ResultsForm(),
                               data=data, os=oschoice)
    else:
        flash('No data entered, please enter some data in the field above.')
        return redirect(url_for('display_index'))


@app.route('/', subdomain='api', methods=['GET'])
def api_cvelist():
    data = {}
    cves = get_cve_text(request.args['cvelist'])
    os = request.args['os']

    data = redis_get_data(os, cves)
    if not data:
        data = mod_rhel.rh_get_data(os, cves)

    return jsonify(data)
