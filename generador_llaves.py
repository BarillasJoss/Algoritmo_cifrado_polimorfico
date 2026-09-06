from __future__ import annotations
import random

# Máscara para limitar los datos a enteros de 64 bits sin signo
MASCARA_64 = (1 << 64) - 1

# Constantes impares de mezcla tipo splitmix para difusión de bits (no secretas)
_C1 = 0x9E3779B97F4A7C15
_C2 = 0xBF58476D1CE4E5B9
_C3 = 0x94D049BB133111EB
_C4 = 0xD6E8FEB86659FD93


def rotar_izq_64(x: int, r: int) -> int:
    """Aplica una rotación de bits hacia la izquierda (rol) en 64 bits."""
    r &= 63
    x &= MASCARA_64
    return ((x << r) | (x >> (64 - r))) & MASCARA_64


def fs(x: int, y: int) -> int:
    """Función de mezcla (scrambled): combina primo y semilla para crear un embrión (P0/Q0)."""
    x &= MASCARA_64
    y &= MASCARA_64
    v = (x ^ rotar_izq_64(y, 17)) * (_C1 | 1)
    v &= MASCARA_64
    v ^= (v >> 31)
    return v & MASCARA_64


def fg(p0: int, q: int) -> int:
    """Función de generación: procesa el embrión y un primo para derivar una llave final."""
    p0 &= MASCARA_64
    q &= MASCARA_64
    v = (p0 + rotar_izq_64(q, 29)) * (_C2 | 1)
    v &= MASCARA_64
    v ^= rotar_izq_64(v, 11)
    v = (v * (_C3 | 1)) & MASCARA_64
    return v & MASCARA_64


def fm(semilla: int, otro_primo: int) -> int:
    """Función de mutación: altera la semilla actual para la siguiente ronda del algoritmo."""
    semilla &= MASCARA_64
    otro_primo &= MASCARA_64
    v = rotar_izq_64(semilla, 13) ^ ((otro_primo * _C4) & MASCARA_64)
    v = (v + 0x1234567890ABCDEF) & MASCARA_64
    return v & MASCARA_64


def generar_tabla_llaves(primo_p: int, primo_q: int, semilla: int, num_llaves: int) -> list[int]:
    """Genera de forma determinista una lista de llaves alternando P y Q mediante fs, fg y fm."""
    if num_llaves <= 0:
        return []

    llaves: list[int] = []
    embrion_anterior = None
    semilla_actual = semilla & MASCARA_64
    usar_p_como_base = True  # alterna P/Q 
    primo_a, primo_b = primo_p & MASCARA_64, primo_q & MASCARA_64

    # Bucle principal de generación de llaves por alternancia
    while len(llaves) < num_llaves:
        primo_base = primo_a if usar_p_como_base else primo_b
        otro_primo = primo_b if usar_p_como_base else primo_a

        # 1. Crear embrión con la semilla y el primo actual
        embrion = fs(primo_base, semilla_actual)

        # 2. Generar llave combinando con el embrión previo u otro primo
        mezclar_con = embrion_anterior if embrion_anterior is not None else otro_primo
        llave = fg(embrion, mezclar_con)

        # 3. Mutar la semilla para la siguiente iteración
        semilla_actual = fm(semilla_actual, otro_primo)

        llaves.append(llave & MASCARA_64)
        embrion_anterior = embrion
        usar_p_como_base = not usar_p_como_base

    return llaves[:num_llaves]


def generar_semilla_pseudoaleatoria() -> int:
    """
    Simula la obtención de P, Q, S. En esta simulación por software se
    reemplaza por el generador aleatorio del sistema operativo.
    """
    return random.SystemRandom().getrandbits(64) & MASCARA_64


def primo_aleatorio_64() -> int:
    """Genera un número primo probable de 64 bits utilizando el test de Miller-Rabin."""
    def es_primo_probable(n: int, rondas: int = 12) -> bool:
        """Aplica el test para verificar primalidad."""
        if n < 2:
            return False
        # Descarte rápido por primos pequeños
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
            if n % p == 0:
                return n == p

        # Extrae cuántas veces se puede dividir entre 2 hasta que quede un número impar
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1

        rng = random.SystemRandom()
        # Rondas de prueba
        for _ in range(rondas):
            a = rng.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    rng = random.SystemRandom()
    # Busca un entero impar aleatorio hasta encontrar un primo probable
    while True:
        candidato = rng.getrandbits(64) | 1  # forzar impar
        candidato &= MASCARA_64
        if es_primo_probable(candidato):
            return candidato
