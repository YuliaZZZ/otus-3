import redis


class Store(object):
    _r = None

    def __init__(self):
        if self._r is None:
            self._r = redis.Redis(host='localhost', port=6379, db=0, max_connections=10,
                                  socket_connect_timeout=2)

    def del_key(self, key):
        return self._r.delete(key)

    def set(self, key, value):
        for v in value:
            self._r.lpush(key, v)

    def get(self, key):
        if self._r.exists(key):
            return self._r.get(key).decode("utf-8")
        raise ValueError('По указанному ключу не существует значения.')

    def cache_get(self, key):
        if self._r.exists(key):
            return self._r.get(key).decode("utf-8")

    def cache_set(self, key, value, time):
        return self._r.setex(key, time, value)
