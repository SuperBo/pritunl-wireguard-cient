import argparse
from os import path
import hashlib

from pritunl_wireguard_client import utils
from pritunl_wireguard_client.profile import Profile
from pritunl_wireguard_client.pritunl_client import PritunlClient

def start_profile(profile_path):
    if not path.isfile(profile_path):
        print('{} is not a valid file'.format(profile_path))
        return -1
    
    name = hashlib.sha1(profile_path.encode('utf-8')).hexdigest()
    prfl = Profile(name)
    prfl.read_config_ovpn(profile_path)

    client = PritunlClient(prfl)
    client.sync_profile()
    client.loop_wireguard()


def download_profile(link):
    print('Downloading profile')
    ret = utils.download_profile(link)
    if ret:
        print('Finished')
    else:
        print('Failed to download profile!')


def run():
    parser = argparse.ArgumentParser(prog='pritunl-wireguard-client')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-p',
        '--profile',
        metavar='config_file',
        help='start listening pritunl wireguard config'
    )
    group.add_argument(
        '-d',
        '--download',
        metavar='link',
        help='download ovpn file from server'
    )
    args = parser.parse_args()

    if args.profile:
        start_profile(args.profile)
    elif args.download:
        download_profile(args.download)
