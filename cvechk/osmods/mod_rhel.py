from cvechk.utils import redis_set_data

import requests


def rh_get_data(cvenum):
    query = 'https://access.redhat.com/labs/securitydataapi/cve/{}.json'.format(cvenum)  # noqa

    r = requests.get(query)

    if r.status_code != 200 or not r.json:
        empty_data = {'cve_urls': ['https://access.redhat.com/security/cve/{}'.format(cvenum)],  # noqa
                      'rhsa_urls': '', 'pkgs': '', 'applicable': False}
        return empty_data
    else:
        return r.json()


def rh_get_pkgs(os, cve):
    os_list = {'RHEL_6': 'Red Hat Enterprise Linux 6',
               'RHEL_7': 'Red Hat Enterprise Linux 7'}
    cve_urls = []
    rhsa_urls = []
    packages = []

    cve_url = 'https://access.redhat.com/security/cve/'
    errata_url = 'https://rhn.redhat.com/errata/'

    cvedata = {}

    try:
        rhdata = rh_get_data(cve)['affected_release']

        for i in rhdata:
            cve_urls.append(cve_url + cve)
            try:
                if i['product_name'] == os_list[os]:
                    advisory = i['advisory'].replace(':', '-')
                    rhsa_urls.append(errata_url + advisory + '.html')
                    packages.append(i['package'])

                    cvedata = dict(cve_urls=sorted(set(cve_urls)),
                                   rhsa_urls=sorted(set(rhsa_urls)),
                                   pkgs=sorted(set(packages)))
                    cvedata['applicable'] = True;
            except:
                raise KeyError

    except KeyError:
        r = requests.get('https://access.redhat.com/security/cve/{}'.format(cve))
        if r.status_code == 404:
            cvedata = {'cve_urls': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name={}'.format(cve)],  # noqa
                       'rhsa_urls': '', 'pkgs': '', 'applicable': False}
        else:
            cvedata = {'cve_urls': ['https://access.redhat.com/security/cve/{}'.format(cve)],  # noqa
                       'rhsa_urls': '', 'pkgs': '', 'applicable': False}
    redis_set_data('cvechk:{}:{}'.format(os, cve), cvedata)

    return cvedata
