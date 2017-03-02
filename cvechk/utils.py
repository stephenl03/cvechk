import re
import redis


def get_cve_text(intext):
    cve_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{4,5}')
    return cve_pattern.findall(intext)


def redis_get_data():
    pass


def redis_set_data():
    pass
