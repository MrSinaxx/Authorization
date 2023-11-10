from datetime import datetime, timedelta
from jose import JWTError, ExpiredSignatureError
from typing import Union, Any
from jose import jwt
from uuid import uuid4
import jose
from app.db.db import RedisDB
from app.core.config import settings
from fastapi import HTTPException, status


def generate_jti():
    return str(uuid4().hex)


jti = generate_jti()


def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + timedelta(expires_delta)
    else:
        expires_delta = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    iat = datetime.utcnow()
    payload = {"user_id": subject, "exp": expires_delta, "iat": iat, "jti": jti}
    encode_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY, settings.ALGORITHM)
    return encode_jwt


def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + timedelta(expires_delta)
    else:
        expires_delta = datetime.utcnow() + timedelta(
            minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES
        )

    iat = datetime.utcnow()
    payload = {"user_id": subject, "exp": expires_delta, "iat": iat, "jti": jti}
    encoded_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY, settings.ALGORITHM)
    return encoded_jwt


async def refresh_token_store(refresh_token):
    payload = jwt.decode(refresh_token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
    user_id = payload.get("user_id")
    jti = payload.get("jti")
    exp_date = payload.get("exp")
    iat = payload.get("iat")
    timeout = exp_date - iat
    redis = RedisDB()
    result = redis.set_data(
        key=f"user_{user_id} | {jti}", value=exp_date, timeout=timeout
    )
    return result


async def delete_refresh_token(token):
    payload = jwt.decode(
        token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM]
    )
    user_id = payload["user_id"]
    jti = payload["jti"]
    redis = RedisDB()
    result = redis.get_data(key=f"user_{user_id} | {jti}")
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User was logged out !!")
    redis.delete_data(key=f"user_{user_id} | {jti}")


def get_user_id_from_token(token: str) -> Union[str, None]:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        return payload.get("user_id")
    except jose.ExpiredSignatureError:
        return None
    except jose.JWTError:
        return None


def is_access_token_valid(token: str) -> bool:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM]
        )

        expiration_time = datetime.utcfromtimestamp(payload["exp"])
        if expiration_time <= datetime.utcnow():
            return False

        user_id = payload.get("user_id")
        jti = payload.get("jti")
        redis = RedisDB()
        refresh_token_valid = redis.get_data(key=f"user_{user_id} | {jti}")

        return bool(refresh_token_valid)
    except ExpiredSignatureError:
        return False
    except JWTError:
        return False
