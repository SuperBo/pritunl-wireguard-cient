import time
import pritunl_wireguard_client.utils.random as utils


class Tokens:
    def __init__(self):
        self.store = dict()

    def get(self, profile_id: str, ttl: int):
        """Return token for profile_id"""
        if profile_id not in self.store:
            self.init(profile_id, ttl)
        self.update()
        return self.store[profile_id]['token']

    def update(self):
        """Update out of time token"""
        now = time.time()
        to_update = []
        for profile_id, token in self.store.items():
            ttl = token['ttl']
            if now - token['timestamp'] > ttl:
                to_update.append(profile_id)

        for profile_id in to_update:
            self.init(profile_id)

    def init(self, profile_id: str, ttl=None):
        """Generate new token for profile_id"""
        if ttl is None:
            ttl = self.store[profile_id]['ttl']

        token = {
            'token': utils.rand_str_complex(16),
            'timestamp': time.time(),
            'ttl': ttl
        }
        self.store[profile_id] = token
