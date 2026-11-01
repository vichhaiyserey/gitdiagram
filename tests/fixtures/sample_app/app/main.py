"""HTTP entrypoints for the sample application."""

from fastapi import FastAPI, Request

from .service import find_user, hash_password, load_user, read_file, run_shell
from .utils import slugify

app = FastAPI()


@app.get("/users/{user_id}")
def get_user(user_id: str, request: Request):
    run_shell(user_id)
    return load_user(user_id)


@app.post("/users")
def create_user(request: Request):
    payload = request.json()
    username = payload.get("username")
    return slugify(username)


@app.get("/files")
def get_file(name: str, request: Request):
    return read_file(name)


@app.get("/lookup/{user_id}")
def lookup(user_id: str):
    return find_user(None, user_id)


@app.get("/hash")
def hash_value(value: str):
    return hash_password(value)
