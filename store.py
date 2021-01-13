import redis


class Store(object):
    _r = None

    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Store, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        if self._r is None:
            self._r = redis.Redis(host='localhost', port=6379, db=0, max_connections=10)

    def del_key(self, key):
        return self._r.delete(key)

    def set(self, key, value):
        for v in value:
            self._r.lpush(key, v)

    def get(self, key):
        if self._r.exists(key):
            if self._r.lrange(key, 1, -1):
                return self._r.lrange(key, 1, -1)

    def cache_get(self, key):
        if self._r.exists(key):
            return self._r.get(key).decode("utf-8")

    def cache_set(self, key, value, time):
        return self._r.setex(key, time, value)
