"""Domain models."""

from dataclasses import dataclass


class Base:
    def save(self) -> None:
        raise NotImplementedError


@dataclass
class User(Base):
    identifier: str

    def label(self) -> str:
        return self.identifier

    def save(self) -> None:
        super().save()


class Repo:
    def store(self) -> str:
        return "stored"


class Store:
    def __init__(self) -> None:
        self.repo = Repo()

    def persist(self) -> str:
        return self.repo.store()


def build_store() -> Store:
    return Store()


def use_store() -> str:
    store = build_store()
    return store.persist()
