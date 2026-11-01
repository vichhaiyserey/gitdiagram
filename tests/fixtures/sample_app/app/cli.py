"""Command line entrypoint."""

import click


@click.command()
@click.option("--name")
def main(name: str) -> None:
    click.echo(name)
