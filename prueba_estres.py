import random
import string

from sesion_par import SesionPar


def payload_aleatorio(generador: random.Random) -> bytes:
    """Genera una cadena de texto aleatoria de longitud variable (1 a 40 bytes)."""
    n = generador.randint(1, 40)
    return "".join(generador.choice(string.ascii_letters + string.digits + " .:%") for _ in range(n)).encode()


def principal(total_mensajes: int = 2000, kum_cada: int = 250, semilla: int = 42):
    """Ejecuta una simulación masiva de envío de mensajes y renovaciones de llaves para validar la sesión."""
    # Inicializa el generador aleatorio con semilla fija para reproducibilidad
    generador = random.Random(semilla)

    # Crea dos instancias de nodos simétricos
    nodo_a = SesionPar(id_nodo_local=12)
    nodo_b = SesionPar(id_nodo_local=5)

    # Simula el intercambio de saludo inicial (Handshake FCM) en memoria
    fcm = nodo_a.iniciar_fcm_como_iniciador()
    respuesta = nodo_b.completar_fcm_como_receptor(fcm)
    nodo_a.completar_fcm_como_iniciador(respuesta)

    # Contadores para estadísticas de la prueba
    correctos = 0
    fallos = 0
    contador_kum = 0

    # Bucle principal de prueba intensiva de envío
    for i in range(total_mensajes):
        # Ejecuta una actualización de llaves (KUM) según el intervalo configurado
        if kum_cada and i > 0 and i % kum_cada == 0:
            trama_kum = nodo_a.construir_kum()
            nodo_b.recibir_kum(trama_kum)
            contador_kum += 1

        # Genera, cifra, envía y descifra un mensaje regular (RM)
        payload = payload_aleatorio(generador)
        trama = nodo_a.construir_rm(payload)
        recuperado = nodo_b.recibir_rm(trama)

        # Valida que el texto descifrado coincida con el original
        if recuperado == payload:
            correctos += 1
        else:
            fallos += 1

    # Despliega los resultados en consola
    print("===== RESULTADOS DE LA PRUEBA DE ESTRÉS =====")
    print(f"Mensajes enviados             : {total_mensajes}")
    print(f"Descifrados correctamente     : {correctos}")
    print(f"Errores                       : {fallos}")
    print(f"Actualizaciones de llave (KUM): {contador_kum}")
    print(f"Tasa de éxito                 : {100.0 * correctos / total_mensajes:.4f} %")


if __name__ == "__main__":
    principal()
