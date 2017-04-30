from cvechk.utils import redis_set_data

import requests


def rh_api_data(cvenum):
    query = 'https://access.redhat.com/labs/securitydataapi/cve/{}.json'.format(cvenum)  # noqa

    r = requests.get(query)

    if r.status_code != 200 or not r.json:
        return   {'cve_url': ['https://access.redhat.com/security/cve/{}'.format(cvenum)],  # noqa
                  'state': 'Not applicable'}
    else:
        return r.json()


def rh_get_data(os, cve):
    """ Utilize Red Hat API to get specific data on provided CVE. """

    os_list = {'EL_6': 'Red Hat Enterprise Linux 6',
               'EL_7': 'Red Hat Enterprise Linux 7'}

    cve_url = 'https://access.redhat.com/security/cve/'
    errata_url = 'https://rhn.redhat.com/errata/'

    cvedata = {}

    rhdata = rh_api_data(cve)

    ''' Attempt to first get applicable packages, if not available then get
        the Red Hat set state, including will not fix, otherwise skip the CVE.
    '''
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
    except KeyError:
        try:
            for ar in rhdata['package_state']:
                if ar['product_name'] == os_list[os]:
                    cvedata = dict(cveurls=cve_urls)
                    cvedata['state'] = ar['fix_state']
                    break
        except KeyError:
            ''' If CVE is not found check for a valid URL anyway for additional
                information. Provide alternative link and warning if URL is not
                valid for Red Hat operating systems. '''
            r = requests.get('https://access.redhat.com/security/cve/{}'.format(cve))  # noqa
            if r.status_code == 404:
                cvedata = {'cveurl': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name={}'.format(cve)],  # noqa
                           'state': 'Not found in Red Hat database'}
            else:
                cvedata = {'cveurl': ['https://access.redhat.com/security/cve/{}'.format(cve)]}  # noqa
        except Exception as e:
            print(e)
    except Exception as e:
        print(e)

    print(cvedata)

    try:
        redis_set_data('cvechk:{0}:{1}'.format(os, cve), cvedata)
    except:
        pass

    return cvedata
