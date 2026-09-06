from __future__ import annotations

#Mascara de 64 bits para limitar el tamaño de la llave a 8 bytes (64 bits)
MASCARA_64 = (1 << 64) - 1

def _llave_a_bytes(llave: int) -> bytes:
    return llave.to_bytes(8, "big")


def _rotar_izq_8(b: int, r: int) -> int:
    r &= 7
    b &= 0xFF
    return ((b << r) | (b >> (8 - r))) & 0xFF


def _rotar_der_8(b: int, r: int) -> int:
    return _rotar_izq_8(b, 8 - (r & 7))


#funciones reversibles de cifrado (FR1..FR5) y sus inversas
def fr0_xor(datos: bytes, llave: int) -> bytes:
    kb = _llave_a_bytes(llave)
    return bytes(b ^ kb[i % 8] for i, b in enumerate(datos))

fr0_xor_inv = fr0_xor  # XOR es su propia inversa

def fr1_suma(datos: bytes, llave: int) -> bytes:
    kb = _llave_a_bytes(llave)
    return bytes((b + kb[i % 8]) & 0xFF for i, b in enumerate(datos))


def fr1_suma_inv(datos: bytes, llave: int) -> bytes:
    kb = _llave_a_bytes(llave)
    return bytes((b - kb[i % 8]) & 0xFF for i, b in enumerate(datos))


def fr2_rotar(datos: bytes, llave: int) -> bytes:
    kb = _llave_a_bytes(llave)
    return bytes(_rotar_izq_8(b, kb[i % 8] % 8) for i, b in enumerate(datos))


def fr2_rotar_inv(datos: bytes, llave: int) -> bytes:
    kb = _llave_a_bytes(llave)
    return bytes(_rotar_der_8(b, kb[i % 8] % 8) for i, b in enumerate(datos))


def fr3_sustitucion(datos: bytes, llave: int) -> bytes:
    sbox = _sbox_desde_llave(llave)
    return bytes(sbox[b] for b in datos)


def fr3_sustitucion_inv(datos: bytes, llave: int) -> bytes:
    sbox = _sbox_desde_llave(llave)
    inversa = [0] * 256
    for i, v in enumerate(sbox):
        inversa[v] = i
    return bytes(inversa[b] for b in datos)


def fr4_intercambio(datos: bytes, llave: int) -> bytes:
    """Intercambia bytes por pares (autoinversa)."""
    ba = bytearray(datos)
    for i in range(0, len(ba) - 1, 2):
        ba[i], ba[i + 1] = ba[i + 1], ba[i]
    return bytes(ba)


fr4_intercambio_inv = fr4_intercambio  # autoinversa


def fr5_xor_posicion(datos: bytes, llave: int) -> bytes:
    kb = _llave_a_bytes(llave)
    return bytes(b ^ kb[i % 8] ^ (i & 0xFF) for i, b in enumerate(datos))


fr5_xor_posicion_inv = fr5_xor_posicion  # autoinversa


def _sbox_desde_llave(llave: int):
    estado = llave & MASCARA_64
    tabla = list(range(256))
    for i in range(255, 0, -1):
        estado = (estado * 6364136223846793005 + 1442695040888963407) & MASCARA_64
        j = estado % (i + 1)
        tabla[i], tabla[j] = tabla[j], tabla[i]
    return tabla


# Banco de funciones donde se guarda el cifrado y su inversa. Se encadenan varias de estas funciones para cifrar un mensaje.
BANCO_FUNCIONES = [
    (fr0_xor, fr0_xor_inv),
    (fr1_suma, fr1_suma_inv),
    (fr2_rotar, fr2_rotar_inv),
    (fr3_sustitucion, fr3_sustitucion_inv),
    (fr4_intercambio, fr4_intercambio_inv),
    (fr5_xor_posicion, fr5_xor_posicion_inv),
]

LONGITUD_SECUENCIA = 3  # cuántas funciones se encadenan por mensaje (mutación polimórfica)


def psn_a_secuencia(psn: int) -> list[int]:
    psn &= 0x0F
    estado = (psn * 2654435761 + 0xABCDEF) & 0xFFFFFFFF
    secuencia = []
    for _ in range(LONGITUD_SECUENCIA):
        estado = (estado * 1103515245 + 12345) & 0xFFFFFFFF
        secuencia.append(estado % len(BANCO_FUNCIONES))
    return secuencia


def seleccionar_llave(tabla: list[int], psn: int) -> int:
    return tabla[psn % len(tabla)]


def cifrar_payload(payload: bytes, tabla: list[int], psn: int) -> bytes:
    llave = seleccionar_llave(tabla, psn)
    secuencia = psn_a_secuencia(psn)
    datos = payload
    for idx in secuencia:
        funcion_cifrado, _ = BANCO_FUNCIONES[idx]
        datos = funcion_cifrado(datos, llave)
    return datos


def descifrar_payload(cifrado: bytes, tabla: list[int], psn: int) -> bytes:
    llave = seleccionar_llave(tabla, psn)
    secuencia = psn_a_secuencia(psn)
    datos = cifrado
    for idx in reversed(secuencia):
        _, funcion_descifrado = BANCO_FUNCIONES[idx]
        datos = funcion_descifrado(datos, llave)
    return datos


def siguiente_psn_desde_cifrado(texto_cifrado: bytes, respaldo: int) -> int:
    if not texto_cifrado:
        return respaldo & 0x0F
    return texto_cifrado[-1] & 0x0F
