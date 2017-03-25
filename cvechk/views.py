from flask import render_template

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

    oschoice = form_cveinput.uos.data
    cvetext = form_cveinput.uinputtext.data.strip()

    cves = get_cve_text(cvetext)

    data = redis_get_data(oschoice, cves)
    if not len(data) > 0:
        data = mod_rhel.rh_get_pkgs(oschoice, cves)

    return render_template('results.html', form=ResultsForm(),
                           data=data, os=oschoice)
