# forgekey

Generador de contraseñas y passphrases criptográficamente seguro, con una
consola de escritorio de estilo panel industrial y una CLI completa para
scripting.

> Añade aquí una captura de `forgekey-gui` una vez la ejecutes en tu máquina
> (`docs/screenshot-gui.png`) — se referencia más abajo en la sección de uso.

## Por qué existe esto

La mayoría de generadores de contraseñas que se ven en portfolios usan
`random.choice()`. Este proyecto es, en el fondo, un ejercicio sobre por qué
eso es un error criptográfico y cómo evitarlo correctamente en cada parte del
flujo: generación, verificación de exposición en filtraciones, y cálculo
honesto de entropía.

## Fundamentos criptográficos

### Por qué `secrets` y no `random`

El módulo `random` de Python usa **Mersenne Twister**, un generador
determinista diseñado para simulaciones y muestreo estadístico, no para
seguridad. Con solo 624 salidas consecutivas de `random.random()` es posible
reconstruir todo su estado interno y predecir cualquier salida futura o
pasada. Si una contraseña se genera con `random`, y un atacante consigue ver
suficiente salida del mismo proceso (por ejemplo, otras contraseñas
generadas en la misma sesión), el espacio de búsqueda deja de ser el que
promete la longitud nominal.

`secrets` (PEP 506, Python 3.6+) resuelve esto usando `os.urandom` como
fuente: entropía real recolectada por el sistema operativo, sin estado
interno reconstruible. Cada llamada a `secrets.choice()` o
`secrets.randbelow()` es independiente de las anteriores desde el punto de
vista de un atacante. Es la única fuente de aleatoriedad usada en todo este
proyecto — no hay una sola llamada a `random` en el código de generación.

### Cómo se garantizan las categorías sin sesgar el resto

Un error común al forzar "al menos un símbolo, un número..." es insertar esos
caracteres obligatorios en posiciones fijas o predecibles (por ejemplo,
siempre al final), lo cual reduce artificialmente la entropía real de esas
posiciones. `forgekey` genera un carácter obligatorio por cada categoría
activa, rellena el resto de la longitud eligiendo uniformemente de la unión
de todas las categorías activas, y después aplica un **shuffle de
Fisher-Yates** completo usando `secrets.randbelow()` como fuente de índices.
El resultado es que cualquier permutación de posiciones es equiprobable: no
hay forma de saber, mirando la contraseña final, cuál carácter fue "el
obligatorio" de su categoría.

### Cómo funciona el k-anonimato con Have I Been Pwned

La comprobación de contraseñas filtradas usa la
[API pública de HIBP](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange),
diseñada específicamente para que el servicio nunca vea la contraseña en
claro:

1. La contraseña se hashea localmente con SHA-1.
2. Se envían a la API únicamente los **primeros 5 caracteres hexadecimales**
   del hash (el "prefijo").
3. HIBP responde con **todos** los sufijos de hash que comparten ese
   prefijo en su base de datos de filtraciones, junto al número de veces
   que cada uno ha sido visto.
4. La comparación del sufijo completo se hace localmente, en la máquina del
   usuario.

Un prefijo de 5 caracteres hex corresponde a un espacio de 16^5 = 1.048.576
posibilidades, así que cada consulta suele devolver cientos de sufijos
candidatos — HIBP nunca sabe cuál de ellos era la contraseña real, y mucho
menos ve el texto plano. Esta comprobación es **opt-in**: no se ejecuta
ninguna petición de red a menos que el usuario active explícitamente el
interruptor (GUI) o pase `--check-pwned` (CLI).

### Cálculo de entropía

La entropía se calcula sobre el **espacio de búsqueda configurado**, no
sobre los caracteres observados en la salida:

```
bits = longitud × log2(tamaño_del_conjunto_de_caracteres)
```

Para passphrases, el mismo principio aplica sustituyendo caracteres por
palabras del diccionario EFF (7776 palabras, `log2(7776) ≈ 12.9` bits por
palabra):

```
bits = número_de_palabras × log2(7776)
```

Medir la entropía a partir del texto generado (contando qué tipos de
caracteres aparecen realmente) sobrestimaría contraseñas cortas que, por
azar, no repiten ningún carácter — el método correcto es medir el espacio de
posibilidades que el atacante enfrenta *antes* de ver el resultado.

### Formato fijo: 16 caracteres, 4 bloques, sin configurar

El modo de caracteres genera siempre 16 caracteres reales agrupados en 4
bloques de 4, separados por 3 guiones (`aB3!-kP9x-Qz2m-7Ht$`, 19 caracteres
en pantalla). Esto no es un valor por defecto que se pueda cambiar: la
longitud no es un parámetro de `GeneratorOptions`, no existe un flag
`--length` en la CLI, y no hay ningún control en la GUI para modificarla —
literalmente no hay ningún camino en el código que acepte una longitud
distinta, así que no hay nada que "bypassear". Los bloques nunca esconden un
guion generado al azar como separador: el conjunto de símbolos excluye
explícitamente el carácter `-`, así que los únicos guiones que aparecen son
los tres estructurales. La entropía se calcula siempre sobre los 16
caracteres reales (`PASSWORD_LENGTH`), nunca sobre la longitud del texto
mostrado, para que los separadores no infravaloren ni sobrevaloren el
resultado.

### Historial cifrado (vault)

forgekey puede recordar dónde y para qué usuario se generó cada contraseña,
sin caer en el error de guardarlas en texto plano:

- **Sitio y usuario** se guardan sin cifrar — no son secretos por sí mismos
  y consultarlos no debería requerir desbloquear nada.
- **La contraseña** solo se persiste como un token cifrado con
  [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128 en modo CBC +
  HMAC-SHA256 para autenticidad).
- La clave de cifrado se deriva de una **contraseña maestra** mediante
  PBKDF2-HMAC-SHA256 con 480.000 iteraciones (la recomendación de OWASP para
  2023) y una sal aleatoria de 16 bytes generada una vez por historial. La
  contraseña maestra en sí **nunca se escribe a disco**.
- Para detectar una contraseña maestra incorrecta sin necesidad de intentar
  descifrar cada entrada, el historial guarda además un pequeño "token de
  verificación" cifrado con la misma clave: si no puede descifrarse, se
  rechaza la operación antes de tocar ninguna entrada real.

El historial vive en `~/.forgekey/vault.json`. Sitio, usuario, fecha y
entropía son legibles sin contraseña maestra desde la GUI o con
`forgekey-history list`; revelar o copiar la contraseña real siempre la pide.

## Estructura del proyecto

```
forgekey/
├── src/forgekey/
│   ├── core/
│   │   ├── generator.py     # generación de contraseñas (secrets únicamente)
│   │   ├── entropy.py       # cálculo de entropía en bits
│   │   ├── passphrase.py    # modo Diceware con wordlist EFF
│   │   ├── hibp.py          # verificación k-anónima contra HIBP
│   │   ├── vault.py         # historial cifrado (Fernet + PBKDF2)
│   │   └── charsets.py      # pools de caracteres y exclusión de ambiguos
│   ├── gui/
│   │   ├── app.py           # ventana principal (PySide6)
│   │   ├── widgets.py       # medidor de entropía y switch a medida
│   │   ├── style.qss        # tema "consola de seguridad industrial"
│   │   └── assets/          # tipografía JetBrains Mono empaquetada
│   ├── cli/
│   │   ├── main.py          # interfaz de línea de comandos (Click)
│   │   └── history.py       # subcomandos para el historial (list/show/delete)
│   └── data/                # wordlist EFF large (7776 palabras)
├── tests/                   # pytest: generación, entropía, passphrase, HIBP
├── docs/                    # capturas de pantalla
├── pyproject.toml
├── requirements.txt
└── LICENSE
```

## Instalación

```bash
git clone https://github.com/<tu-usuario>/forgekey.git
cd forgekey
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Uso — interfaz gráfica

```bash
forgekey-gui
# o, sin instalar el paquete:
python -m forgekey
```

La consola muestra en tiempo real la contraseña generada, un medidor de
entropía segmentado (no una barra continua — cada segmento representa un
tramo del espacio de bits), y un interruptor físico separado para la
comprobación opcional contra HIBP, con su explicación de k-anonimato visible
junto al control.

## Uso — línea de comandos

```bash
# Contraseña: 16 caracteres en 4 bloques, todas las categorías activas
forgekey

# Sin símbolos, excluyendo caracteres ambiguos
forgekey --no-symbols --exclude-ambiguous

# Passphrase Diceware de 8 palabras
forgekey --passphrase --words 8

# Generar 5 contraseñas de golpe y copiar la primera al portapapeles
forgekey --count 5 --copy

# Comprobar exposición en filtraciones conocidas (opt-in)
forgekey --check-pwned

# Salida mínima para scripting (una contraseña por línea, sin metadatos)
forgekey --count 10 --quiet
```

Ejemplo de salida:

```
$ forgekey
zz0D-d5BL-rNi!-p3GB   [104.6 bits | excelente]

$ forgekey --passphrase --words 6
correa-abdomen-tundra-jinete-fibra-manto   [77.5 bits | muy fuerte]
```

La longitud del modo de caracteres es fija (16 caracteres reales, 4 bloques
de 4) y no es configurable — no existe un flag `--length` a proposito, ver
[Formato fijo](#formato-fijo-16-caracteres-4-bloques-sin-configurar).

Todas las flags disponibles: `--no-uppercase`, `--no-lowercase`,
`--no-digits`, `--no-symbols`, `--exclude-ambiguous`, `--passphrase`,
`--words`, `--count`, `--check-pwned`, `--copy`, `--save-site`,
`--save-user`, `--quiet`.

### Historial

```bash
# Generar y guardar en el historial cifrado (pide la contrasena maestra)
forgekey --save-site github.com --save-user mi_usuario

# Listar entradas (sitio, usuario, fecha, entropia — sin contrasena maestra)
forgekey-history list

# Revelar y copiar la contrasena de una entrada (pide la contrasena maestra)
forgekey-history show <id>

# Eliminar una entrada
forgekey-history delete <id>
```

Desde la GUI, el panel "GUARDAR EN HISTORIAL" hace lo mismo con un par de
campos y un botón, y el botón "HISTORIAL" del encabezado abre una tabla con
las entradas guardadas y acciones para verlas/copiarlas o eliminarlas.

## Tests

```bash
pytest
```

La suite cubre: formato de salida fijo (19 caracteres, 4 bloques de 4, 16
caracteres reales), que ningún conjunto de caracteres pueda producir un
guion al azar que se confunda con un separador, presencia garantizada de
cada categoría seleccionada, ausencia de caracteres excluidos,
no-degeneración de la distribución a lo largo de muchas generaciones,
corrección del cálculo de entropía para ambos modos, integridad de la
wordlist EFF, el contrato de k-anonimato de HIBP (verificando explícitamente
que el sufijo del hash nunca viaja en la petición de red), y el historial
cifrado (que la contraseña nunca queda en texto plano en disco, que una
contraseña maestra incorrecta se rechaza tanto al leer como al añadir
entradas, y que borrar una entrada la elimina de verdad).

## Licencia

MIT — ver [LICENSE](LICENSE).
