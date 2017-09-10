# This script is part of cvechk.net used to pull and process CVE data
# from the Ubuntu CVE lookup (http://people.canonical.com/~ubuntu-security/cve/)
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

from bs4 import BeautifulSoup

import logging
import re
import requests

ubulogger = logging.getLogger('cvelogger.mod_ubuntu')


def get_cve_data(cvenum, rel):

    releases = {'UBU_1604': 'Xenial Xerus',
                'UBU_1404': 'Trusty Tahr'}

    securl = 'https://people.canonical.com/~ubuntu-security/'

    cveyear = cvenum.split('-')[1]
    cveurl = securl + f'cve/{cveyear}/{cvenum}.html'

    cvedata = {}
    cvedata['cveurl'] = cveurl
    cvedata['state'] = 'Not Affected'
    package = ''

    upstream_data = requests.get(cveurl).text

    pkgname = BeautifulSoup(upstream_data, 'html.parser').find_all('div')
    for item in pkgname:
        namematch = re.search(r'Source', item.get_text())
        if namematch:
            package = item.text.split()[1]

    pkgvers = BeautifulSoup(upstream_data, 'html.parser').find_all('tr')
    versregex = re.compile(r'\(\d:\d\.\d.*\)|\(\d\.\d\..*\)')
    for item in pkgvers:
        relmatch = re.search(releases[rel], item.text)
        if relmatch:
            cvedata['state'] = 'Affected'
            pkgmatch = re.search(versregex, item.text)
            if pkgmatch:
                cvedata['pkg'] = f'{package}-{pkgmatch.group().strip("()")}'

    redis_set_data(f'cvechk:{rel}:{cvenum}', cvedata)
    return cvedata
