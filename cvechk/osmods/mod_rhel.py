from cvechk import app
from cvechk.utils import redis_set_data

import requests

enable_cache = app.config['ENABLE_CACHE']


def rh_get_data(cvenum):
    query = 'https://access.redhat.com/labs/securitydataapi/cve/{}.json'.format(cvenum)  # noqa

    r = requests.get(query)

    if r.status_code != 200 or not r.json:
        return None
    else:
        return r.json()


def rh_get_pkgs(os, cve):
    os_list = {'rhel6': 'Red Hat Enterprise Linux 6',
               'rhel7': 'Red Hat Enterprise Linux 7'}
    cve_urls = []
    rhsa_urls = []
    packages = []

    cve_url = 'https://access.redhat.com/security/cve/'
    errata_url = 'https://rhn.redhat.com/errata/'

    cvedata = {}

    rhdata = rh_get_data(cve)['affected_release']
    for i in rhdata:
        cve_urls.append(cve_url + cve)
        if i['product_name'] == os_list[os]:
            advisory = i['advisory'].replace(':', '-')
            rhsa_urls.append(errata_url + advisory + '.html')
            packages.append(i['package'])

            cvedata = dict(cveurls=sorted(set(cve_urls)),
                           rhsa=sorted(set(rhsa_urls)),
                           pkgs=sorted(set(packages)))
    redis_set_data('{}:{}'.format(os, cve), cvedata)

    return cvedata
