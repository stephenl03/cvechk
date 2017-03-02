import redis


def get_cve_text(intext):
    cve_pattern = re.compile(r'CVE-[0-9]{4}-[0-9]{4,5}')
    file_data = []
    cve_matches = []
    cve = cve_pattern.search(line)
    if cve:
        cve_matches.append(cve.group())

    return cve_matches


def redis_get_data():
    pass


def redis_set_data():
    pass
