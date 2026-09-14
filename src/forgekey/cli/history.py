"""CLI for browsing the local encrypted password history."""

from __future__ import annotations

import getpass

import click

from forgekey.core.vault import Vault, VaultNotInitialized, WrongMasterPassword


@click.group()
def history_cli() -> None:
    """Gestiona el historial cifrado de contrasenas generadas con forgekey."""


@history_cli.command("list")
def list_command() -> None:
    """Lista sitio, usuario y fecha de cada entrada (no requiere contrasena maestra)."""
    vault = Vault()
    entries = vault.list_entries()
    if not entries:
        click.echo("no hay entradas en el historial")
        return

    for entry in entries:
        date = entry.created_at.split("T")[0]
        username = entry.username or "-"
        click.echo(
            f"{entry.id}  {date}  {entry.site:<28}  {username:<20}  "
            f"{entry.bits:.1f} bits ({entry.label})"
        )


@history_cli.command("show")
@click.argument("entry_id")
def show_command(entry_id: str) -> None:
    """Descifra y muestra la contrasena de una entrada (pide la contrasena maestra)."""
    vault = Vault()
    master = getpass.getpass("Contrasena maestra: ")
    try:
        password = vault.reveal(entry_id, master)
    except WrongMasterPassword:
        raise click.ClickException("contrasena maestra incorrecta")
    except VaultNotInitialized:
        raise click.ClickException("no hay historial guardado todavia")
    except KeyError:
        raise click.ClickException(f"no existe una entrada con id {entry_id}")
    click.echo(password)


@history_cli.command("delete")
@click.argument("entry_id")
def delete_command(entry_id: str) -> None:
    """Elimina una entrada del historial (no requiere contrasena maestra)."""
    vault = Vault()
    vault.delete(entry_id)
    click.echo("entrada eliminada")


if __name__ == "__main__":
    history_cli()
