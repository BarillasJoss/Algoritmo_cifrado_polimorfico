from __future__ import annotations
import argparse
import socket
import random

import protocolo as proto
from sesion_par import SesionPar


def ejecutar_servidor(anfitrion: str, puerto: int, id_nodo: int) -> None:
    sesion = SesionPar(id_nodo_local=id_nodo)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((anfitrion, puerto))
    srv.listen(1)
    print(f"[SERVIDOR id_nodo={id_nodo}] Escuchando en {anfitrion}:{puerto} ...")

    conexion, direccion = srv.accept()
    print(f"[SERVIDOR] Conexión entrante de {direccion}")

    try:
        with conexion:
            while True:
                trama = proto.recibir_trama(conexion)

                if trama.tipo_mensaje == proto.MSG_FCM:
                    print(f"[SERVIDOR] <- FCM recibido de NodeID={trama.id_nodo}. Construyendo tabla de llaves...")
                    respuesta = sesion.completar_fcm_como_receptor(trama)
                    proto.enviar_trama(conexion, respuesta)
                    print(f"[SERVIDOR] -> FCM de confirmación enviado. Tabla de {sesion.N} llaves de 64 bits lista. "
                          f"PSN inicial={sesion.psn_actual}")

                elif trama.tipo_mensaje == proto.MSG_RM:
                    texto_plano = sesion.recibir_rm(trama)
                    print(f"[SERVIDOR] <- RM (PSN={trama.psn}, {len(trama.payload)} bytes cifrados) "
                          f"=> texto recuperado: {texto_plano!r}")
                    # Eco de confirmación cifrado, para que el cliente valide
                    # que el servidor recuperó exactamente el mismo mensaje.
                    ack = sesion.construir_rm(b"ACK:" + texto_plano)
                    proto.enviar_trama(conexion, ack)

                elif trama.tipo_mensaje == proto.MSG_KUM:
                    sesion.recibir_kum(trama)
                    print(f"[SERVIDOR] <- KUM recibido. Tabla de llaves regenerada. "
                          f"Nuevo PSN base={sesion.psn_actual}")
                    ack = proto.Trama(sesion.id_nodo_local, proto.MSG_KUM, b"KUM-OK", sesion.psn_actual)
                    proto.enviar_trama(conexion, ack)

                elif trama.tipo_mensaje == proto.MSG_LCM:
                    mensaje = sesion.recibir_lcm(trama)
                    print(f"[SERVIDOR] <- LCM recibido ({mensaje!r}). Cerrando sesión y borrando "
                          f"tabla de llaves / identificador de par.")
                    break

    except (ConnectionError, OSError) as e:
        print(f"[SERVIDOR] Conexión finalizada: {e}")
    finally:
        srv.close()
        print("[SERVIDOR] Socket cerrado.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--anfitrion", default="0.0.0.0")
    ap.add_argument("--puerto", type=int, default=9090)
    ap.add_argument("--id-nodo", type=int, default=random.randint(0, 63))
    args = ap.parse_args()
    ejecutar_servidor(args.anfitrion, args.puerto, args.id_nodo)
