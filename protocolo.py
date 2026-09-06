from __future__ import annotations
import struct
import json
import socket

# --- Tipos de mensaje (4 bits: 0-15) ---
MSG_FCM = 0x0
MSG_RM = 0x1
MSG_KUM = 0x2
MSG_LCM = 0x3

# Mapeo de identificadores a nombres legibles
NOMBRES_TIPO = {MSG_FCM: "FCM", MSG_RM: "RM", MSG_KUM: "KUM", MSG_LCM: "LCM"}


class Trama:
    """Estructura de la trama binaria personalizada para la red IoT."""

    def __init__(self, id_nodo: int, tipo_mensaje: int, payload: bytes, psn: int):
        # Valida los límites de bits requeridos por el encabezado
        assert 0 <= id_nodo <= 0x3F, "NodeID debe caber en 6 bits (0-63)"
        assert 0 <= tipo_mensaje <= 0xF, "Type debe caber en 4 bits (0-15)"
        assert 0 <= psn <= 0xF, "PSN debe caber en 4 bits (0-15)"
        self.id_nodo = id_nodo
        self.tipo_mensaje = tipo_mensaje
        self.payload = payload
        self.psn = psn

    def __repr__(self):
        """Retorna una representación legible de la trama en texto."""
        return (f"Trama(NodeID={self.id_nodo}, Type={NOMBRES_TIPO.get(self.tipo_mensaje,'?')}, "
                f"PSN={self.psn}, largo_payload={len(self.payload)})")

    # Empaquetado a nivel de bits
    def empaquetar(self) -> bytes:
        # Empaqueta NodeID y Type en un entero de 16 bits
        encabezado = (self.id_nodo << 10) | (self.tipo_mensaje << 6)
        # Empaqueta el PSN en los 4 bits superiores del byte de cola
        cola = (self.psn << 4) & 0xFF

        # Construye la trama binaria: Encabezado (2B) + Longitud (2B) + Payload + Cola (1B)
        salida = struct.pack("!H", encabezado)
        salida += struct.pack("!H", len(self.payload))
        salida += self.payload
        salida += struct.pack("!B", cola)
        return salida

    @classmethod
    def desempaquetar(cls, datos: bytes) -> "Trama":
        """Reconstruye un objeto Trama desde una secuencia de bytes."""
        # Extrae NodeID y Type del encabezado
        encabezado = struct.unpack("!H", datos[0:2])[0]
        id_nodo = (encabezado >> 10) & 0x3F
        tipo_mensaje = (encabezado >> 6) & 0xF

        # Extrae el tamaño y el contenido del payload
        largo_payload = struct.unpack("!H", datos[2:4])[0]
        payload = datos[4:4 + largo_payload]

        # Extrae el número de secuencia PSN del byte final
        cola = datos[4 + largo_payload]
        psn = (cola >> 4) & 0xF
        return cls(id_nodo, tipo_mensaje, payload, psn)


# ---------------------------------------------------------------------
# Envío / recepción con framing por longitud sobre TCP
# ---------------------------------------------------------------------

def enviar_trama(sock: socket.socket, trama: Trama) -> None:
    """Empaqueta la trama y la envía adjuntando su tamaño total al inicio."""
    crudo = trama.empaquetar()
    sock.sendall(struct.pack("!I", len(crudo)) + crudo)


def recibir_exacto(sock: socket.socket, n: int) -> bytes:
    """Lee del socket en un bucle hasta completar exactamente 'n' bytes."""
    buffer = b""
    while len(buffer) < n:
        fragmento = sock.recv(n - len(buffer))
        if not fragmento:
            raise ConnectionError("Conexión cerrada por el otro extremo")
        buffer += fragmento
    return buffer


def recibir_trama(sock: socket.socket) -> Trama:
    """Lee el encabezado de longitud TCP y desempaqueta la trama recibida."""
    (longitud,) = struct.unpack("!I", recibir_exacto(sock, 4))
    crudo = recibir_exacto(sock, longitud)
    return Trama.desempaquetar(crudo)


# ---------------------------------------------------------------------
# Payloads auxiliares (FCM y KUM viajan como JSON con los parámetros
# necesarios para reconstruir la tabla de llaves)
# ---------------------------------------------------------------------

def construir_payload_fcm(id_nodo: int, p: int, q: int, semilla: int, num_llaves: int) -> bytes:
    """Serializa en JSON los parámetros de inicio (P, Q, S, N) para sincronizar llaves."""
    return json.dumps({"id_nodo": id_nodo, "P": p, "Q": q, "S": semilla, "N": num_llaves}).encode()


def parsear_payload_fcm(payload: bytes) -> dict:
    """Deserializa un payload JSON a un diccionario de Python."""
    return json.loads(payload.decode())
