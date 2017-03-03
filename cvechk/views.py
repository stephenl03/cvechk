from flask import render_template

from cvechk import app
from cvechk.forms import CVEInputForm, ResultsForm
from cvechk.osmods import mod_rhel
from cvechk.utils import get_cve_text, redis_get_data, redis_set_data


@app.route('/')
def display_index():
    return render_template('index.html', form=CVEInputForm())


@app.route('/submit_check', methods=['POST'])
def submit_check():
    form_cveinput = CVEInputForm()

    oschoice = form_cveinput.uos.data
    cvetext = form_cveinput.uinputtext.data.strip()

    cves = get_cve_text(cvetext)

    print(app.config['ENABLE_CACHE'])

    if oschoice.startswith('rhel'):
        rhdata = mod_rhel.rh_get_pkgs(cves, oschoice)

        if app.config['ENABLE_CACHE']:
            print('setting data')
            redis_set_data(oschoice, rhdata)

        return render_template('results.html', form=ResultsForm(), data=rhdata)
    else:
        return render_template('index.html', form=form_cveinput)
