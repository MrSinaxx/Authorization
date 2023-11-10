import redis


class RedisDB:
    def __init__(self) -> None:
        self.redis = redis.StrictRedis(host="localhost", port=6379, db=1)

    def set_data(self, key: str, value: str, timeout):
        self.redis.setex(key, timeout, value)
        return "data is stored"

    def get_data(self, key: str):
        result = self.redis.get(key)
        return result.decode("utf-8") if result else None

    def delete_data(self, key: str):
        self.redis.delete(key)
        return f"{key} was deleted"
