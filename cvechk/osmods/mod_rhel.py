# This script is part of cvechk.net used to pull and process CVE data
# from the Red Hat API https://access.redhat.com/labs/securitydataapi
#
# Copyright (C) 2017 evitalis
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from cvechk.utils import redis_set_data

import logging
import requests
import time

rhellogger = logging.getLogger('cvelogger.mod_rhel')


def rh_api_data(cvenum):
    query = f'https://access.redhat.com/labs/securitydataapi/cve/{cvenum}.json'

    retry = 1
    while retry >= 0:
      r = requests.get(query)
      if r.status_code == 200:
          return r.json()
      elif r.status_code == 504:
          rhellogger.warning(f'Received {r.status_code}. Sleep 1 second, '
                              'then attempt again')
          retry -= 1
          time.sleep(1)
          continue
      else:
          break
    return {'cveurl': f'https://access.redhat.com/security/cve/{cvenum}',
            'state': 'Not applicable'}


def check_url(cve, os):
    """
        Helper to form proper URLs if there is an issue with the JSON data

        Return a Red Hat URL if CVE is valid for that platform, otherwise
        return generic link with additional information.
    """

    testurl = requests.get(f'https://access.redhat.com/security/cve/{cve}')
    if testurl.status_code == 404:
        rhellogger.warning(f'{cve} data not available from Red Hat API')
        return {'cveurl': f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}',  # noqa
                'state': 'Not found in Red Hat database'}
    else:
        rhellogger.info(f'{cve} found but not applicable for {os}')
        return {'cveurl': f'https://access.redhat.com/security/cve/{cve}',
                'state': 'Not applicable'}


def rh_get_data(os, cve):
    os_list = {'EL_6': 'Red Hat Enterprise Linux 6',
               'EL_7': 'Red Hat Enterprise Linux 7'}
    cve_url = 'https://access.redhat.com/security/cve/'

    rhdata = rh_api_data(cve)
    cvedata = {}

    if len(rhdata) > 2:
        affrel = rhdata.get('affected_release', None)
        if affrel and type(affrel) is list:
            for rel in affrel:
                if rel.get('product_name', None) == os_list[os]:
                    errata_url = 'https://rhn.redhat.com/errata/'

                    # Make advisory link URL safe.
                    advisory = rel['advisory'].replace(':', '-')
                    advurl = f'{errata_url}{advisory}.html'
                    package = rel['package']
                    cvedata = dict(cveurl=cve_url + cve, rhsaurl=advurl,
                                   pkg=package)
                    cvedata['state'] = 'Affected'
                else:
                    cvedata = check_url(cve, os)
        elif rhdata.get('package_state', None):
            states = rhdata['package_state']
            for state in states:
                if type(state) is dict:
                    if state.get('product_name', None) == os_list[os]:
                        cvedata = dict(cveurl=cve_url + cve)
                        cvedata['state'] = state.get('fix_state', None)
                    if not cvedata.get('state', None):
                        cvedata = check_url(cve, os)
        else:
            cvedata = check_url(cve, os)
    else:
        cvedata = check_url(cve, os)

    redis_set_data(f'cvechk:{os}:{cve}', cvedata)
    return cvedata
