from __future__ import annotations
import argparse

from sesion_par import SesionPar


def principal(mensaje: str, veces: int) -> None:
    nodo_a = SesionPar(id_nodo_local=1)  # transmisor
    nodo_b = SesionPar(id_nodo_local=2)  # receptor

    # Primer contacto (FCM) -> ambos nodos calculan la MISMA tabla de llaves de 64 bits de forma local, sin transmitirla.
    fcm = nodo_a.iniciar_fcm_como_iniciador()
    respuesta = nodo_b.completar_fcm_como_receptor(fcm)
    nodo_a.completar_fcm_como_iniciador(respuesta)

    print(f"FCM completado. Tabla de {nodo_a.N} llaves de 64 bits sincronizada "
          f"entre NodeID={nodo_a.id_nodo_local} y NodeID={nodo_b.id_nodo_local}.\n")

    print(f'Enviando el mismo mensaje "{mensaje}" {veces} veces seguidas:\n')
    print(f"{'#':<4}{'PSN':<6}{'Cifrado (hex)':<50}{'Recuperado':<20}")
    print("-" * 80)

    payload = mensaje.encode()
    todos_ok = True
    cifrados_vistos = set()

    for i in range(1, veces + 1):
        trama = nodo_a.construir_rm(payload)        # nodo A cifra y envía
        recuperado = nodo_b.recibir_rm(trama)        # nodo B recibe y descifra

        ok = recuperado == payload
        todos_ok = todos_ok and ok
        cifrados_vistos.add(trama.payload.hex())

        marca = "OK" if ok else "FALLÓ"
        print(f"{i:<4}{trama.psn:<6}{trama.payload.hex():<50}{recuperado.decode()!r:<20} [{marca}]")

    print("-" * 80)
    print(f"\nTextos cifrados distintos observados : {len(cifrados_vistos)} de {veces}")
    print(f"Mensaje recuperado correctamente en todos los envíos: {'SÍ' if todos_ok else 'NO'}")

    if len(cifrados_vistos) == veces:
        print("\n=> Polimorfismo confirmado: cada envío del mismo mensaje produjo "
              "un texto cifrado distinto.")
    else:
        print("\n=> Atención: se repitió algún texto cifrado (posible con mensajes "
              "muy cortos, pocos envíos, o el espacio de 16 valores de PSN, por "
              "coincidencia).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mensaje", default="Temp: 25C", help="Mensaje a repetir")
    ap.add_argument("--veces", type=int, default=5, help="Cuántas veces enviarlo")
    args = ap.parse_args()
    principal(args.mensaje, args.veces)
