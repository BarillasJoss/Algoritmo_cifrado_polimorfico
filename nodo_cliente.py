from __future__ import annotations
import argparse
import socket
import time
import random

import protocolo as proto
from sesion_par import SesionPar

PAYLOADS_SENSORES = [
    b"Sensor2: 0",
    b"Sensor2: 1",
    b"Hello World",
    b"142354.98",
    b"Analog Sensor: 25C",
    b"Puerta: ABIERTA",
    b"Temp: 31.4C Hum: 55%",
]


def ejecutar_cliente(anfitrion: str, puerto: int, id_nodo: int) -> None:
    sesion = SesionPar(id_nodo_local=id_nodo)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((anfitrion, puerto))
    print(f"[CLIENTE id_nodo={id_nodo}] Conectado a {anfitrion}:{puerto}")

    enviados, correctos, discrepancias = 0, 0, 0

    try:
        # ---------------- FCM ----------------
        fcm = sesion.iniciar_fcm_como_iniciador()
        print(f"[CLIENTE] -> FCM enviado (P,Q,S generados localmente, N={sesion.N} llaves)")
        proto.enviar_trama(sock, fcm)

        respuesta = proto.recibir_trama(sock)
        sesion.completar_fcm_como_iniciador(respuesta)
        print(f"[CLIENTE] <- FCM confirmado por NodeID={sesion.id_nodo_par}. "
              f"Tabla de {sesion.N} llaves de 64 bits lista. PSN inicial={sesion.psn_actual}")

        # ---------------- RM (tanda 1) ----------------
        for payload in PAYLOADS_SENSORES[:4]:
            trama = sesion.construir_rm(payload)
            proto.enviar_trama(sock, trama)
            enviados += 1
            print(f"[CLIENTE] -> RM PSN={trama.psn} original={payload!r} "
                  f"cifrado={trama.payload.hex()}")

            trama_ack = proto.recibir_trama(sock)
            ack_plano = sesion.recibir_rm(trama_ack)
            esperado = b"ACK:" + payload
            if ack_plano == esperado:
                correctos += 1
                print(f"[CLIENTE] <- ACK verificado correctamente: {ack_plano!r}")
            else:
                discrepancias += 1
                print(f"[CLIENTE] !! ACK NO coincide. Esperado={esperado!r} recibido={ack_plano!r}")
            time.sleep(0.05)

        # ---------------- KUM ----------------
        trama_kum = sesion.construir_kum()
        proto.enviar_trama(sock, trama_kum)
        print("[CLIENTE] -> KUM enviado (nueva semilla cifrada con la tabla anterior)")
        kum_ack = proto.recibir_trama(sock)
        print(f"[CLIENTE] <- KUM confirmado por el servidor ({kum_ack.payload!r}). "
              f"Nueva tabla de llaves activa. PSN base={sesion.psn_actual}")

        # ---------------- RM (tanda 2, con la tabla nueva) ----------------
        for payload in PAYLOADS_SENSORES[4:]:
            trama = sesion.construir_rm(payload)
            proto.enviar_trama(sock, trama)
            enviados += 1
            print(f"[CLIENTE] -> RM PSN={trama.psn} original={payload!r} "
                  f"cifrado={trama.payload.hex()}")

            trama_ack = proto.recibir_trama(sock)
            ack_plano = sesion.recibir_rm(trama_ack)
            esperado = b"ACK:" + payload
            if ack_plano == esperado:
                correctos += 1
                print(f"[CLIENTE] <- ACK verificado correctamente: {ack_plano!r}")
            else:
                discrepancias += 1
                print(f"[CLIENTE] !! ACK NO coincide. Esperado={esperado!r} recibido={ack_plano!r}")
            time.sleep(0.05)

        # ---------------- LCM ----------------
        lcm = sesion.construir_lcm(b"fin de sesion")
        proto.enviar_trama(sock, lcm)
        print("[CLIENTE] -> LCM enviado. Sesión cerrada, tabla de llaves destruida.")

    finally:
        sock.close()
        print("\n===== RESUMEN =====")
        print(f"Mensajes RM enviados : {enviados}")
        print(f"ACKs verificados OK  : {correctos}")
        print(f"Discrepancias        : {discrepancias}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--anfitrion", default="127.0.0.1")
    ap.add_argument("--puerto", type=int, default=9090)
    ap.add_argument("--id-nodo", type=int, default=random.randint(0, 63))
    args = ap.parse_args()
    ejecutar_cliente(args.anfitrion, args.puerto, args.id_nodo)
