"""Command-line entry point for atalaya.

Strings here are kept accent-free on purpose: Windows terminals default to a
non-UTF-8 codepage (cp1252/cp437), and accented characters piped through
Click's help formatter come out as mojibake there.
"""

from __future__ import annotations

import getpass
import sys

import click

from atalaya.core import entropy, hibp, passphrase
from atalaya.core.generator import PASSWORD_LENGTH, GeneratorOptions, generate_password
from atalaya.core.vault import Vault, WrongMasterPassword


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--no-uppercase", is_flag=True, help="Excluir mayusculas (A-Z).")
@click.option("--no-lowercase", is_flag=True, help="Excluir minusculas (a-z).")
@click.option("--no-digits", is_flag=True, help="Excluir digitos (0-9).")
@click.option("--no-symbols", is_flag=True, help="Excluir simbolos.")
@click.option(
    "--exclude-ambiguous", is_flag=True, help="Excluir caracteres ambiguos (0/O, 1/l/I, |)."
)
@click.option(
    "--passphrase",
    "use_passphrase",
    is_flag=True,
    help="Generar passphrase Diceware en vez de contrasena de caracteres.",
)
@click.option("--words", default=6, show_default=True, help="Numero de palabras (solo con --passphrase).")
@click.option("--count", default=1, show_default=True, help="Cuantas contrasenas generar.")
@click.option("--check-pwned", is_flag=True, help="Consultar Have I Been Pwned (k-anonimato, opt-in).")
@click.option("--copy", "copy_to_clipboard", is_flag=True, help="Copiar el primer resultado al portapapeles.")
@click.option(
    "--save-site",
    default=None,
    metavar="SITIO",
    help="Guardar el resultado en el historial cifrado, asociado a este sitio/servicio.",
)
@click.option(
    "--save-user",
    default=None,
    metavar="USUARIO",
    help="Usuario asociado a la entrada guardada (usar junto con --save-site).",
)
@click.option("--quiet", is_flag=True, help="Salida minima: solo la(s) contrasena(s), una por linea.")
def main(
    no_uppercase: bool,
    no_lowercase: bool,
    no_digits: bool,
    no_symbols: bool,
    exclude_ambiguous: bool,
    use_passphrase: bool,
    words: int,
    count: int,
    check_pwned: bool,
    copy_to_clipboard: bool,
    save_site: str | None,
    save_user: str | None,
    quiet: bool,
) -> None:
    """Genera contrasenas (16 caracteres en 4 bloques, formato fijo) o passphrases Diceware."""

    results: list[tuple[str, entropy.EntropyRating]] = []

    if use_passphrase:
        pool_size = passphrase.wordlist_size()
        for _ in range(count):
            phrase = passphrase.generate_passphrase(word_count=words)
            rating = entropy.bits_from_wordlist(pool_size, words)
            results.append((phrase, rating))
    else:
        options = GeneratorOptions(
            use_uppercase=not no_uppercase,
            use_lowercase=not no_lowercase,
            use_digits=not no_digits,
            use_symbols=not no_symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
        pool_size = len("".join(options.active_pools()))
        try:
            for _ in range(count):
                pwd = generate_password(options)
                rating = entropy.bits_from_pool(pool_size, PASSWORD_LENGTH)
                results.append((pwd, rating))
        except ValueError as exc:
            raise click.ClickException(str(exc))

    if copy_to_clipboard and results:
        _copy(results[0][0])

    for value, rating in results:
        if quiet:
            click.echo(value)
        else:
            click.echo(f"{value}   [{rating.bits:.1f} bits | {rating.label}]")

    if check_pwned:
        if not quiet:
            click.echo("")
            click.echo("Consultando Have I Been Pwned (k-anonimato, solo prefijo SHA-1)...")
        for value, _ in results:
            result = hibp.check_password(value)
            if result.error:
                click.echo(f"  no se pudo comprobar: {result.error}", err=True)
            elif result.is_pwned:
                click.echo(
                    f"  EXPUESTA - vista {result.times_seen} veces en filtraciones conocidas",
                    err=True,
                )
            elif not quiet:
                click.echo("  sin coincidencias en filtraciones conocidas")

    if copy_to_clipboard and results and not quiet:
        click.echo("")
        click.echo("(primer resultado copiado al portapapeles)")

    if save_site and results:
        _save_to_history(results, save_site, save_user or "", use_passphrase, quiet)


def _save_to_history(
    results: list[tuple[str, entropy.EntropyRating]],
    site: str,
    username: str,
    use_passphrase: bool,
    quiet: bool,
) -> None:
    vault = Vault()
    master = getpass.getpass("Contrasena maestra del historial: ")
    if not vault.exists():
        confirm = getpass.getpass("Confirma la contrasena maestra (se crea el historial ahora): ")
        if confirm != master:
            raise click.ClickException("las contrasenas maestras no coinciden")

    mode = "passphrase" if use_passphrase else "password"
    try:
        for value, rating in results:
            vault.add_entry(
                master,
                site=site,
                username=username,
                password=value,
                bits=rating.bits,
                label=rating.label,
                mode=mode,
            )
    except WrongMasterPassword:
        raise click.ClickException("contrasena maestra incorrecta")

    if not quiet:
        click.echo(f"guardado en el historial ({site})")


def _copy(text: str) -> None:
    try:
        import pyperclip

        pyperclip.copy(text)
    except Exception as exc:  # pragma: no cover - depends on OS clipboard tooling
        click.echo(f"no se pudo copiar al portapapeles: {exc}", err=True)


if __name__ == "__main__":
    sys.exit(main())
