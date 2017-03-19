from cvechk import app
from cvechk.osmods import mod_rhel

import re
import redis


redis_host = app.config['REDISHOST']
redis_port = app.config['REDISPORT']
redis_pass = app.config['REDISPASS']
redis_db = app.config['REDISDB']


def get_cve_text(intext):
    cve_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}')
    return cve_pattern.findall(intext)


def redis_get_data(os, cvelist):
    redis_conn = redis.StrictRedis(host=redis_host, port=redis_port,
                                   db=redis_db, decode_responses=True)

    cvedata = {}
    extra = []

    for cve in cvelist:
        cached = redis_conn.hgetall('cvechk:{}:{}'.format(os, cve))
        if len(cached) > 0:
            cvedata[cve] = {'cve_urls': [u.strip("['] ") for u in cached['cve_urls'].split(',')],  # noqa
                            'pkgs': [p.strip("['] ") for p in cached['pkgs'].split(',')],  # noqa
                            'rhsa_urls': [r.strip("['] ") for r in cached['rhsa_urls'].split(',')],  # noqa
                            'applicable': cached['applicable']}
        else:
            cvedata[cve] = mod_rhel.rh_get_pkgs(os, cve)
    extra = [x for x in cvelist if x not in cvedata.keys()]
    for cve in extra:
        cvedata[cve] = mod_rhel.rh_get_pkgs(os, cve)

    return cvedata


def redis_set_data(key, cvedata):
    redis_conn = redis.StrictRedis(host=redis_host, port=redis_port,
                                   db=redis_db)
    redis_conn.hmset(key, cvedata)
