from fastapi import HTTPException, status, Request, Depends
from fastapi.routing import APIRouter
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import FileResponse
from app.core.config import settings
from app.jwt.utils import (
    create_access_token,
    create_refresh_token,
    refresh_token_store,
    delete_refresh_token,
    get_user_id_from_token,
    is_access_token_valid,
)
from app.schema.schemas import Otp, UserRequest, TokenResponse, UserRequestLogin
import httpx


router = APIRouter(tags=["authorization"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="")


@router.post("/login", status_code=status.HTTP_200_OK)
async def send_otp(user: UserRequestLogin):
    """
    Endpoint to initiate the login process and send OTP.

    Args:
        user (UserRequestLogin): User login information.

    Returns:
        JSON: Result of sending OTP.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.ACCOUNT_ENDPOINT}/verify_account", json=user.dict()
        )
        if response.status_code == status.HTTP_404_NOT_FOUND:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User was not found"
            )
        elif response.status_code == status.HTTP_401_UNAUTHORIZED:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Password or TOTP code",
            )

    async with httpx.AsyncClient() as client:
        result = await client.post(settings.CREATE_OTP_ENDPOINT, json=response.json())

    return result.json()


@router.post(
    "/verify_otp", status_code=status.HTTP_200_OK, response_model=TokenResponse
)
async def verify_otp(otp: Otp):
    """
    Endpoint to verify OTP and generate access and refresh tokens.

    Args:
        otp (Otp): OTP information.

    Returns:
        TokenResponse: Access and refresh tokens.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(settings.VERIFY_OTP_ENDPOINT, json=otp.dict())
        if response.status_code == status.HTTP_404_NOT_FOUND:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Invalid OTP")

    access_token = create_access_token(response.json())
    refresh_token = create_refresh_token(response.json())
    await refresh_token_store(refresh_token)

    return {"access_token": access_token, "refresh_token": refresh_token}


@router.post("/signup", status_code=status.HTTP_200_OK)
async def signup(user: UserRequest):
    """
    Endpoint to sign up a new user.

    Args:
        user (UserRequest): User information.

    Returns:
        FileResponse or JSON: QR code image or signup response.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.ACCOUNT_ENDPOINT}/signup", json=user.dict()
        )
        response_json = response.json()

        totp_qr_code_path = response_json.get("totp_qr_code")
    if totp_qr_code_path:
        return FileResponse(totp_qr_code_path, media_type="image/png")
    return response.json()


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(request: Request):
    """
    Endpoint to log out a user.

    Args:
        request (Request): FastAPI Request object.

    Returns:
        JSON: Logout response.
    """
    bearer = request.headers.get("Authorization")
    token = bearer.split(" ")[1]
    await delete_refresh_token(token)
    return {"detail": "logout"}


@router.post("/profile", status_code=status.HTTP_200_OK)
async def profile(request: Request, token: str = Depends(oauth2_scheme)):
    """
    Endpoint to retrieve user profile.

    Args:
        request (Request): FastAPI Request object.
        token (str): OAuth2 token.

    Returns:
        JSON: User profile response.
    """
    if not is_access_token_valid(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token"
        )

    user_id = get_user_id_from_token(token)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.ACCOUNT_ENDPOINT}/user_profile", json={"user_id": user_id}
        )

    return response.json()
