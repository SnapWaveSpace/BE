from pydantic import BaseModel


class User(BaseModel):
    username: str
    email: str


class UserInDB(User):
    hashed_password: str


db = {
    "johndoe": UserInDB(
        username="johndoe",
        email="johndoe@example.com",
        hashed_password="$2b$12$zWjSyVPlN1Lzh/ip5VXnouYuxLKrrNcEmvfbtORths/RpR4QG7rJa",
    ),
    "alice": UserInDB(
        username="alice",
        email="alice@example.com",
        hashed_password="$2b$12$zWjSyVPlN1Lzh/ip5VXnouYuxLKrrNcEmvfbtORths/RpR4QG7rJa",
    ),
}


def get_user_by_username(username: str) -> UserInDB | None:
    return db.get(username, None)


def create_new_user(username: str, hashed_password: str, email: str) -> UserInDB | None:
    if username in db:
        return None

    new_user = UserInDB(username=username, hashed_password=hashed_password, email=email)
    db[username] = new_user
    return new_user
