from cvechk import app

import re
import redis


redis_host = app.config['REDISHOST']
redis_port = app.config['REDISPORT']
redis_pass = app.config['REDISPASS']
redis_db = app.config['REDISDB']


def get_cve_text(intext):
    cve_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{4,5}')
    return cve_pattern.findall(intext)


def redis_get_data(os, cvelist):
    redis_conn = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db)
    cvedata = {}

    for cve in cvelist:
        cache = redis_conn.hgetall(os + ':' + cve)
        cvedata[cve] = cache

    return cvedata


def redis_set_data(os, cvedata):
    redis_conn = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db)
    for cve in cvedata.keys():
        redis_conn.hmset(os + ':' + cve, cvedata[cve])
