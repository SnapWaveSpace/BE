import os

from dotenv import load_dotenv

load_dotenv("../.env")

fe_url = os.getenv("FE_URL")
be_url = os.getenv("BE_URL")
secret_key = os.getenv("SECRET_KEY")

email_login = os.getenv("EMAIL_LOGIN")
email_password = os.getenv("EMAIL_PASSWORD")
