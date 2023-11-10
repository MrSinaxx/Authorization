from pydantic import BaseModel
from typing import Optional


class UserRequest(BaseModel):
    username: str
    password: str
    firstname: Optional[str] = None
    lastname: Optional[str] = None


class UserRequestLogin(BaseModel):
    username: str
    password: str
    totp_code: str


class UserResponse(BaseModel):
    id: str
    username: str
    firstname: Optional[str] = None
    lastname: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str


class Otp(BaseModel):
    otp: str
