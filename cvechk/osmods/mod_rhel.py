from platform import python_version

import re
import requests
import sys



def rh_get_data(cvenum):
    query = 'https://access.redhat.com/labs/securitydataapi/cve/{}.json'.format(cvenum)  # noqa

    r = requests.get(query)

    if r.status_code != 200:
        print('ERROR: Invalid request; returned {} for the following '
              'query:\n{}'.format(r.status_code, query))
        sys.exit(1)

    if not r.json():
        print('No data returned with the following query:')
        print(query)
        sys.exit(0)

    return r.json()


def rh_get_pkgs(cve, os):
    os_list = {'rhel6': 'Red Hat Enterprise Linux 6',
               'rhel7': 'Red Hat Enterprise Linux 7'}
    rhsa_urls = []
    packages = []

    errata_url = 'https://rhn.redhat.com/errata/'

    for c in cve:
        for i in rh_get_data(c)['affected_release']:
            if i['product_name'] == os_list[os]:
                rhsa_urls.append(errata_url + i['advisory'] + '.html')
                packages.append(i['package'])

    # Use set() here to avoid duplicate output.
    return dict(rhsa=sorted(set(rhsa_urls)), pkgs=sorted(set(packages)))


def get_cve_file(filename):
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4}')
    file_data = []
    cve_matches = []
    with open(filename, 'r') as infile:
        file_data = infile.readlines()
    for line in file_data:
        cve = cve_pattern.search(line)
        if cve:
            cve_matches.append(cve.group())

    return cve_matches
