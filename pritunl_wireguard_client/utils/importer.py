import requests


def download_profile(profile_uri):
    url = profile_uri.replace('pritunl:', 'https:')
    url = url.replace('/k/', '/ku/')

    strict_ssl = (re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) is None) \
        and (re.match(r'\[[a-fA-F0-9:]*\]', url) is None)

    res = requests.get(
        url,
        verify=strict_ssl,
        timeout=12000,
        headers={
            'User-Agent': 'pritunl'
        }
    )

    content = res.json()
    
    # write config to file
    for file_name, value in content.items():
        with open(file_name, 'w') as f:
            f.write(value)

    return res.status_code == 200
