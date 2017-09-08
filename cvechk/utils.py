# Helper utilities for storing/retrieving data used by cvechk.net

# Copyright (C) 2017 evitalis

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from cvechk import app
from cvechk.osmods import mod_rhel

import logging
import re
import redis


redis_host = app.config['REDIS_HOST']
redis_port = app.config['REDIS_PORT']
redis_pass = app.config['REDIS_PASS']
redis_db = app.config['REDIS_DB']

utillogger = logging.getLogger('cvelogger.utils')


def get_cve_text(intext):
    """
    Take arbitrary input and extract a list of all CVE numbers found.
    """

    cve_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}')
    return cve_pattern.findall(intext)


def redis_get_data(os, cvelist):
    """
    Attempt to gather any cached data from the configured Redis instance.
    If requested CVE is not found then proceed to check the Red Hat API.

    Return a dictionary of CVE data with URLs and packages.
    """
    redis_conn = redis.StrictRedis(host=redis_host, port=redis_port,
                                   password=redis_pass, db=redis_db,
                                   decode_responses=True)

    cvedata = {}
    extra = []

    for cve in cvelist:
        cached = redis_conn.hgetall('cvechk:{}:{}'.format(os, cve))
        if len(cached) > 0:
            try:
                cvedata[cve] = {'cveurl': cached['cveurl'],
                                'pkg': cached['pkg'],
                                'rhsaurl': cached['rhsaurl'],
                                'state': cached['state']}
            except KeyError:
                cvedata[cve] = {'cveurl': cached['cveurl'],
                                'state': cached['state']}
        else:
            cvedata[cve] = mod_rhel.rh_get_data(os, cve)

    # Get CVE data from Red Hat API if not found in existing cache data.
    extra = [x for x in cvelist if x not in cvedata.keys()]
    for cve in extra:
        cvedata[cve] = mod_rhel.rh_get_data(os, cve)

        redis_set_data(f'cvechk:{os}:{cve}', cvedata)
    return cvedata


def redis_set_data(key, cvedata):
    """
    Connect to the configured Redis instance and insert a hash of CVE data
    including URLS and package informaton if available.
    """

    if cvedata:
        try:
            redis_conn = redis.StrictRedis(host=redis_host, port=redis_port,
                                           password=redis_pass, db=redis_db)
            redis_conn.hmset(key, cvedata)

            # Expire keys after 8 hours.
            redis_conn.expire(key, 28800)
        except ConnectionError:
            utillogger.error(f'Unable to connect to Redis at {redis_host}')
