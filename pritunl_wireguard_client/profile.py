import json
import platform
import base64


class Profile:
    """Pritunl profile 
    """
    def __init__(self, name: str):
        self.name = name
        self.device_name = ''
        self.device_id = ''
        self.config = dict()
        self.private_key = ''
        self.remotes = []
        self.platform = self.get_platform()

    def get_platform(self):
        system = platform.system()
        if system == 'Linux':
            return 'linux'
        if system == 'Darwin':
            return 'mac'
        if system == 'Windows':
            return 'win'
        return 'unknown'

    def get_inet_address(self):
        #TODO get if mac address
        self.mac = ''
        self.macs = ['']

    def parse_pritunl_ovpn(self, content: str):
        '''Parse profile from raw profile ovpn data'''
        # read config
        config_text = ''
        lines = content.split('\n')

        for i, line in enumerate(lines):
            if line.startswith('#'):
                config_text += line[1:].lstrip()
                config_text += '\n'
            if line == '#}':
                break
        self.config = json.loads(config_text)
        end_section = i
        
        # read device id and name and key
        for i, line in enumerate(lines[end_section:]):
            if line.startswith('setenv UV_ID'):
                self.device_id = line.split(' ')[2].strip()
            elif line.startswith('setenv UV_NAME'):
                self.device_name = line.split(' ')[2].strip()
            elif line.startswith('remote'):
                line_splits = line.split(' ')
                if len(line_splits) < 4:
                    continue
                self.remotes.append(line_splits[1])
            elif line.startswith('<ca>'):
                break
        end_section = i
            
        # read private key    
        for i, line in enumerate(lines[end_section:]):
            if line.strip() == '<key>':
                start_key = end_section + i
            elif line.strip() == '</key>':
                end_key = end_section + i
                break
        private_key_lines = lines[start_key+1:end_key]
        self.private_key = '\n'.join(private_key_lines)
        
    def read_config_ovpn(self, config_file):
        with open(config_file, 'r') as f:
            content = f.read()
        self.parse_pritunl_ovpn(content)

    def sync_secret(self):
        return self.config['sync_secret'].encode('ascii')

    def sync_token(self):
        return self.config['sync_token']

    def token_ttl(self):
        return self.config['token_ttl']

    def server_box_public_key(self):
        '''Return base64 decode of server box key'''
        key = self.config['server_box_public_key']
        return base64.b64decode(key)
