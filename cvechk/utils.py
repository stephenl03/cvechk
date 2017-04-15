from cvechk import app
from cvechk.osmods import mod_rhel

import re
import redis


redis_host = app.config['REDISHOST']
redis_port = app.config['REDISPORT']
redis_pass = app.config['REDISPASS']
redis_db = app.config['REDISDB']


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
                cvedata[cve] = {'cveurls': [u.strip("['] ") for u in cached['cveurls'].split(',')],  # noqa
                                'pkgs': [p.strip("['] ") for p in cached['pkgs'].split(',')],  # noqa
                                'rhsaurls': [r.strip("['] ") for r in cached['rhsaurls'].split(',')],  # noqa
                                'state': cached['state']}
            except KeyError:
                cvedata[cve] = {'cveurls': [u.strip("['] ") for u in cached['cveurls'].split(',')],  # noqa
                                'state': cached['state']}
        else:
            cvedata[cve] = mod_rhel.rh_get_data(os, cve)

    ''' Get CVE data from Red Hat API if not found in existing cache data. '''
    extra = [x for x in cvelist if x not in cvedata.keys()]
    for cve in extra:
        cvedata[cve] = mod_rhel.rh_get_data(os, cve)

    redis_set_data('cvechk:{0}:{1}'.format(os, cve), cvedata)
    return cvedata


def redis_set_data(key, cvedata):
    """
    Connect to the configured Redis instance and insert a hash of CVE data
    including URLS and package informaton if available.
    """

    redis_conn = redis.StrictRedis(host=redis_host, port=redis_port,
                                   password=redis_pass, db=redis_db)
    redis_conn.hmset(key, cvedata)
    redis_conn.expire(key, 28800)
