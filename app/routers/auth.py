from datetime import timedelta, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel

import env
from store import get_user_by_username, UserInDB, create_new_user, User

router = APIRouter(prefix="/auth")

SECRET_KEY = env.secret_key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REGISTER_EMAIL_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def validate_username(username: str) -> str | None:
    if len(username) < 6:
        return "Username must contain at least 6 characters"


def validate_password(password: str) -> str | None:
    if len(password) < 6:
        return "Password must contain at least 6 characters"


class Token(BaseModel):
    accessToken: str
    tokenType: str


def create_jwt_token(
        data: dict,
        expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(username: str, password: str) -> UserInDB | None:
    user = get_user_by_username(username)
    if user is None:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def get_current_user(
        token: Annotated[str, Depends(oauth2_scheme)]
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload["sub"]
    except JWTError:
        raise credentials_exception

    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception

    return user


def create_access_token(username: str) -> Token:
    access_token = create_jwt_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return Token(accessToken=access_token, tokenType="bearer")


@router.post("/token", response_model=Token)
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return create_access_token(user.username)


def generate_registration_link(email: str):
    register_token = create_jwt_token(
        data={"email": email},
        expires_delta=timedelta(minutes=REGISTER_EMAIL_TOKEN_EXPIRE_MINUTES)
    )

    return f"{env.fe_url}/register?token={register_token}"


class TryRegisterBody(BaseModel):
    email: str


@router.post("/try-register", response_model=str)
async def try_register(data: TryRegisterBody):
    registration_link = generate_registration_link(data.email)
    return registration_link


class FinishRegisterBody(BaseModel):
    registerToken: str
    username: str
    password: str


@router.post("/finish-register", response_model=Token)
async def finish_register(data: FinishRegisterBody):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate register token",
    )

    try:
        payload = jwt.decode(data.registerToken, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload["email"]
    except JWTError:
        raise credentials_exception

    if message := validate_username(data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    if message := validate_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    user = create_new_user(data.username, get_password_hash(data.password), email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )

    return create_access_token(user.username)


AuthorizedUser = Annotated[User, Depends(get_current_user)]


@router.get("/me", response_model=User)
async def get_me(current_user: AuthorizedUser):
    return current_user


__all__ = [
    "router",
    "AuthorizedUser",
]
