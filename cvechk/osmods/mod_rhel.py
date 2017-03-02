from platform import python_version

import re
import requests
import sys



def rh_get_data(cvenum):
    query = 'https://access.redhat.com/labs/securitydataapi/cve/{}.json'.format(cvenum)  # noqa

    r = requests.get(query)

    if r.status_code != 200:
        return None

    if not r.json():
        return None

    return r.json()


def rh_get_pkgs(cve, os):
    os_list = {'rhel6': 'Red Hat Enterprise Linux 6',
               'rhel7': 'Red Hat Enterprise Linux 7'}
    cve_urls = []
    rhsa_urls = []
    packages = []

    errata_url = 'https://rhn.redhat.com/errata/'

    for c in cve:
        try:
            for i in rh_get_data(c)['affected_release']:
                cve_urls.append('https://access.redhat.com/security/cve/{}'.format(c))
                if i['product_name'] == os_list[os]:
                    rhsa_urls.append(errata_url + i['advisory'].replace(':', '-') + '.html')
                    packages.append(i['package'])
        except TypeError:
            continue

    # Use set() here to avoid duplicate output.
    return dict(cveurls=sorted(set(cve_urls)), rhsa=sorted(set(rhsa_urls)), pkgs=sorted(set(packages)))
