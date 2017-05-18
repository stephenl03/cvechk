from cvechk.utils import redis_set_data

import logging
import requests

rhellogger = logging.getLogger('cvelogger.mod_rhel')


def rh_api_data(cvenum):
    query = f'https://access.redhat.com/labs/securitydataapi/cve/{cvenum}.json'

    r = requests.get(query)

    if r.status_code != 200 or not r.json:
        return   {'cveurl': f'https://access.redhat.com/security/cve/{cvenum}',  # noqa
                  'state': 'Not applicable'}
    else:
        return r.json()


def rh_get_data(os, cve):
    """ Utilize Red Hat API to get specific data on provided CVE. """

    rhdata = rh_api_data(cve)
    cvedata = {}

    if rhdata:
        cvedata = check_affected_rel(rhdata, cve, os)
    if not cvedata:
        cvedata = check_release_data(rhdata, cve, os)
    if not cvedata:
        testurl = requests.get(f'https://access.redhat.com/security/cve/{cve}')
        if testurl.status_code == 404:
            rhellogger.warning(f'{cve} data not available from Red Hat API')
            cvedata = {'cveurl': f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}',  # noqa
                       'state': 'Not found in Red Hat database'}
        else:
            rhellogger.info(f'{cve} found but not applicable for {os}')
            cvedata = {'cveurl': f'https://access.redhat.com/security/cve/{cve}'} # noqa

    redis_set_data(f'cvechk:{os}:{cve}', cvedata)
    return cvedata


def check_affected_rel(rhdata, cve, os):
    os_list = {'EL_6': 'Red Hat Enterprise Linux 6',
               'EL_7': 'Red Hat Enterprise Linux 7'}

    cve_url = 'https://access.redhat.com/security/cve/'
    errata_url = 'https://rhn.redhat.com/errata/'

    cvedata = {}
    try:
        for ar in rhdata['affected_release']:
            if ar['product_name'] == os_list[os]:
                ''' Fix the advisory URL here to be a proper URL format. '''
                advisory = ar['advisory'].replace(':', '-')
                rhsa_url = f'{errata_url}{advisory}.html'
                package = ar['package']

                cvedata = dict(cveurl=cve_url + cve, rhsaurl=rhsa_url,
                               pkg=package)
                cvedata['state'] = 'Affected'
                break

        return cvedata
    except KeyError:
        rhellogger.warning(f'No affected release found for {cve} ({os})')
        return None


def check_release_data(rhdata, cve, os):
    os_list = {'EL_6': 'Red Hat Enterprise Linux 6',
               'EL_7': 'Red Hat Enterprise Linux 7'}

    cve_url = 'https://access.redhat.com/security/cve/'

    cvedata = {}
    for ar in rhdata['package_state']:
        if ar['product_name'] == os_list[os]:
            cvedata = dict(cveurl=cve_url + cve)
            cvedata['state'] = ar['fix_state']

    return cvedata
