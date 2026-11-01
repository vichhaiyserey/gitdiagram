"""Business logic with intentionally risky sinks for tests."""

import hashlib
import os
import subprocess

from sqlalchemy.orm import Session

API_KEY = "mock_super_secret_test_token_123456789"
DB_PASSWORD = "correct-horse-battery-staple"

DATABASE_URL = os.environ.get("DATABASE_URL")


def run_shell(user_input: str) -> str:
    return subprocess.check_output("echo " + user_input, shell=True)


def load_user(user_id: str) -> dict:
    return {"id": user_id}


def find_user(session: Session, user_id: str):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return session.execute(query)


def read_file(filename: str) -> str:
    with open(filename, "r", encoding="utf-8") as handle:
        return handle.read()


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def make_id(parts: list[str]) -> str:
    return hashlib.sha1("".join(parts).encode()).hexdigest()


def unsafe_yaml(data: str):
    import yaml

    return yaml.load(data)


def safe_yaml(data: str):
    import yaml

    return yaml.safe_load(data)
