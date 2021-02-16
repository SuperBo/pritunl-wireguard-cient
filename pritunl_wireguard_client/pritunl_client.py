from pritunl_wireguard_client import utils
from pritunl_wireguard_client.wireguard import WgConfig, WgKey

import base64
import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import time
import random
import segno
import signal
import os


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = logging.getLogger('PritunlClient')


class PritunlClient:
    '''Pritunl Client to interact with Pritunl Server
    '''
    TOKENS = utils.Tokens() # Token store for all profiles

    def __init__(self, profile):
        self.profile = profile
        self.stop = True
        signal.signal(signal.SIGTERM, self.signal_handler)

    def sync_profile(self):
        '''Sync profile with server'''
        sync_hosts = self.profile.config['sync_hosts']
        for host in sync_hosts:
            self.__sync_profile_host(host)

    def __sync_profile_host(self, host):
        path = '/key/sync/{:s}/{:s}/{:s}/{:s}'.format(
            self.profile.config['organization_id'],
            self.profile.config['user_id'],
            self.profile.config['server_id'],
            self.profile.config['sync_hash']
        )
        url = host + path

        sync_secret = self.profile.sync_secret()
        auth_headers = utils.pritunl_auth(
            self.profile.sync_token(),
            self.profile.sync_secret(),
            'GET',
            path
        )
        auth_headers['User-Agent'] = 'pritunl'
        
        # make request to server
        res = requests.get(
            url,
            headers=auth_headers,
            verify=False
        )

        if res.status_code == 480:
            print('Nothing to sync')
            return
        if res.status_code != 200:
            print('profile: Bad status {:d} code from server'.format(res.status_code))
            return
         
        sync_data = res.json()
        config = sync_data.get('conf', '')
        if config == '':
            logger.info('Empty conf')
            return

        matched = utils.verify_signature(
            self.profile.sync_secret(),
            sync_data['signature'],
            config
        )
        if not matched:
            logger.error('profile: Sync profile signature invalid')
            return
        # update profile
        self.profile.config.update(config)


    def request_wireguard(self):
        '''Request wireguard config from server'''
        token = self.TOKENS.get(self.profile.name, self.profile.token_ttl())
        token_nonce = utils.rand_str(16)
        wg_keypair = WgKey()
        wg_box_data = json.dumps({
            'device_id': self.profile.device_id,
            'device_name': self.profile.device_name,
            'platform': self.profile.platform,
            'mac_addr': self.profile.mac,
            'mac_addrs': self.profile.macs,
            'token': token,
            'nonce': token_nonce,
            'password': '',
            'timestamp': int(time.time()),
            'wg_public_key': wg_keypair.public_key
        })

        box = utils.ClientBox(self.profile.server_box_public_key())
        ciphertext64, nonce64 = box.encrypt_base64(wg_box_data)
        sender_pubkey64 = box.public_key_base64()
        rsa_sig64 = utils.pritunl_sign(
            self.profile.private_key, 
            ciphertext64,
            nonce64,
            sender_pubkey64
        )
        wgreq = {
           'data': ciphertext64,
           'nonce': nonce64,
           'public_key': sender_pubkey64,
           'signature': rsa_sig64
        }
        wgreq_data = json.dumps(wgreq)

        req_path = '/key/wg/{:s}/{:s}/{:s}'.format(
            self.profile.config['organization_id'],
            self.profile.config['user_id'],
            self.profile.config['server_id']
        )
        
        remotes = self.profile.remotes
        remote = remotes[random.randint(0, len(remotes)-1)]
        if ':' in remote:
            remote = '[' + remote + ']'
        url = 'https://' + remote + req_path

        auth_headers = utils.pritunl_auth(
            self.profile.sync_token(),
            self.profile.sync_secret(),
            'POST',
            req_path,
            wgreq['data'],
            wgreq['nonce'],
            wgreq['public_key'],
            wgreq['signature']
        )
        auth_headers['Content-Type']=  'application/json'
   
        res = requests.post(
            url=url,
            data=wgreq_data,
            headers=auth_headers,
            verify=False
        )

        if res.status_code != 200:
            print('profile: Bad status {:d} code from server'.format(res.status_code))
            print(res.text)
            return

        print('profile: ok')
        wgres = res.json()

        matched = utils.verify_signature(
            self.profile.sync_secret(),
            wgres['signature'],
            wgres['data'],
            wgres['nonce']
        )
        if not matched:
            logger.error('profile: Response signature invalid')
            return

        wg_config = box.decrypt_base64(wgres['data'], wgres['nonce'])
        wg_config = json.loads(wg_config)
        if not wg_config['allow']:
            logger.error('profile: Failed to authenticate wg')
            logger.error('reason: {}'.format(wg_config['reason']))
            return

        return wg_config['configuration'], wg_keypair

    def ping_wireguard(self, remote, wg_keypair):
        '''Ping wireguard config with server'''
        wg_box_data = json.dumps({
             'device_id': self.profile.device_id,
             'device_name': self.profile.device_name,
             'platform': self.profile.platform,
             'mac_addr': self.profile.mac,
             'mac_addrs': self.profile.macs,
             'timestamp': int(time.time()),
             'wg_public_key': wg_keypair.public_key
        })

        box = utils.ClientBox(self.profile.server_box_public_key())
        ciphertext64, nonce64 = box.encrypt_base64(wg_box_data)
        sender_pubkey64 = box.public_key_base64()
        rsa_sig64 = utils.pritunl_sign(
            self.profile.private_key, 
            ciphertext64,
            nonce64,
            sender_pubkey64
        )
        wgreq = {
           'data': ciphertext64,
           'nonce': nonce64,
           'public_key': sender_pubkey64,
           'signature': rsa_sig64
        }
        wgreq_data = json.dumps(wgreq)
    
        req_path = '/key/wg/{:s}/{:s}/{:s}'.format(
             self.profile.config['organization_id'],
             self.profile.config['user_id'],
             self.profile.config['server_id']
        )

        if ':' in remote:
             remote = '[' + remote + ']'
        url = 'https://' + remote + req_path

        auth_headers = utils.pritunl_auth(
             self.profile.sync_token(),
             self.profile.sync_secret(),
             'PUT',
             req_path,
             wgreq['data'],
             wgreq['nonce'],
             wgreq['public_key'],
             wgreq['signature']
        )
        auth_headers['Content-Type']=  'application/json'
  
        res = requests.put(
             url=url,
             data=wgreq_data,
             headers=auth_headers,
             verify=False
        )

        if res.status_code != 200:
             print('profile: Bad status {:d} code from server'.format(res.status_code))
             print(res.text)
             if res.status_code < 400 or res.status_code >= 500:
                 return 'retry'
             return

        wgres = res.json()
       
        matched = utils.verify_signature(
            self.profile.sync_secret(),
            wgres['signature'],
            wgres['data'],
            wgres['nonce']
        )
        if not matched:
             print('profile: Response signature invalid')
             return
   
        wg_ping = box.decrypt_base64(wgres['data'], wgres['nonce'])
        wg_ping = json.loads(wg_ping)
        self.wg['status'] = wg_ping['status']
        logger.info('Ping {:s} status: {}'.format(remote, wg_ping['status']))
        return wg_ping['status']

    def watch_wireguard(self):
        time.sleep(1)
        for i in range(31):
            if self.stop:
                break
            if i % 10 == 0:
                ping = self.ping_wireguard(self.wg['gateway'], self.wg['key'])
            time.sleep(1)
            if ping is not None and ping != 'retry':
                break
        # keep alive
        while True:
            for i in range(10):
                if self.stop:
                    break
                time.sleep(1)
            for i in range(3):
                ping = self.ping_wireguard(self.wg['gateway'], self.wg['key'])
                if ping != 'retry':
                    break
                time.sleep(0.001)
            if ping is None:
                logger.error('profile: Keepalive failed')
                self.restart_wireguard()
            if self.stop:
                break

    def restart_wireguard(self):
        self.wg = None
        # Request new config
        logger.info('profile: Trying to get new config')
        ret = self.request_wireguard()
        if ret is None:
            logger.error('profile: failed to get new config')
            self.stop = True
            return
        wg_config, wg_keypair = ret
        self.wg = {
            'config': wg_config,
            'key': wg_keypair,
            'gateway': wg_config['hostname']
        }
        self.save_wireguard()

    def loop_wireguard(self):
        """Run wireguard loop"""
        self.profile.get_inet_address()
        ret = self.request_wireguard()
        if ret is None:
            return
        wg_config, wg_keypair = ret
        self.wg = {
            'config': wg_config,
            'key': wg_keypair,
            'gateway': wg_config['hostname']
        }
        self.save_wireguard()
        self.stop = False
        print('Profile {} is up'.format(self.profile.name))
        #TODO write to pidfile
        try:
            self.watch_wireguard()
        except KeyboardInterrupt:
            logger.info('Stop Program')
            self.release()
           
    def save_wireguard(self):
        conf = WgConfig.gen_wgquick(self.wg['config'], self.wg['key'])
        with open(self.profile.name + '.conf', 'w') as f:
            f.write(conf)
        conf_qr = segno.make_qr(conf)
        conf_qr.save(self.profile.name + '.png', border=2, scale=4)

    def __exit__(self, exc_type, exc_value, exc_traceback):  
        self.release()
        
    def signal_handler(self, signum, frame):
        self.release()
        
    def release(self):
        self.stop = True
        # clean config file
        conf = self.profile.name + '.conf'
        qr = self.profile.name + '.png'
        if os.path.isfile(conf):
            os.remove(conf)
        if os.path.isfile(qr):
            os.remove(qr)
