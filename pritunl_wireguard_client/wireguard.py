from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import base64
from configparser import ConfigParser
import io


class WgKey:
    """Helper class for generating wireguard KeyError
    """
    @staticmethod
    def gen_key():
        '''Generate X25519 key pair'''
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # key to bytes
        private_key_b = private_key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption()
        )
        public_key_b = public_key.public_bytes(
            Encoding.Raw,
            PublicFormat.Raw
        )

        return private_key_b, public_key_b

    def __init__(self):
        private_key, public_key = self.gen_key()
        self.private_key = base64.b64encode(private_key).decode()
        self.public_key = base64.b64encode(public_key).decode()


class WgConfig:
    """Generate wg-quick configuration
    """
    @staticmethod
    def gen_wgquick(pritunl_wg_data, wg_key):
        """Convert pritunl wg config info to wgquick config
        """
        data = pritunl_wg_data
        routes = data['routes'] + data['routes6']
        allow_ips = ','.join(r['network'] for r in routes)

        addr = pritunl_wg_data['address']
        if 'address6' in data:
            addr += data['address6']

        if 'dns_servers' in data and len(data['dns_servers']) > 0:
            dns = ','.join(data['dns_servers'])

        endpoint = '{:s}:{:d}'.format(data['hostname'], data['port'])
        
        config = ConfigParser()
        interface = {
            'Address': addr,
            'PrivateKey': wg_key.private_key
        }
        if dns:
            interface['DNS'] = dns
        config['Interface'] = interface
        config['Peer'] = {
            'PublicKey': data['public_key'],
            'AllowedIPs': allow_ips,
            'Endpoint': endpoint
        }
                                              
        with io.StringIO() as f:
            config.write(f)
            f.seek(0)
            content = f.read()

        return content
