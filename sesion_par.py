from __future__ import annotations
import json

import generador_llaves as llaves
import cifrado
import protocolo as proto


class SesionPar:
    """Mantiene el estado y la lógica de cifrado/sincronización entre dos nodos."""
    def __init__(self, id_nodo_local: int):
        # Inicializa identificadores, parámetros criptográficos (P, Q, S) y la tabla
        self.id_nodo_local = id_nodo_local
        self.id_nodo_par: int | None = None
        self.P: int | None = None
        self.Q: int | None = None
        self.S: int | None = None
        self.N: int = 16  # tamaño de la tabla de llaves
        self.tabla_llaves: list[int] = []
        self.psn_actual: int = 0
        self.establecida = False

    # -------------------------------------------------------------
    # FCM: primer contacto
    # -------------------------------------------------------------
    def iniciar_fcm_como_iniciador(self) -> proto.Trama:
        """Genera P, Q, S y arma el FCM inicial sin cifrar."""
        self.P = llaves.primo_aleatorio_64()
        self.Q = llaves.primo_aleatorio_64()
        self.S = llaves.generar_semilla_pseudoaleatoria()
        payload = proto.construir_payload_fcm(self.id_nodo_local, self.P, self.Q, self.S, self.N)
        return proto.Trama(self.id_nodo_local, proto.MSG_FCM, payload, psn=self.S & 0xF)

    def completar_fcm_como_receptor(self, trama: proto.Trama) -> proto.Trama:
        """El receptor recibe P, Q, S del iniciador, construye su tabla,
        y responde con un FCM propio (para que el iniciador conozca su NodeID)."""
        datos = proto.parsear_payload_fcm(trama.payload)
        self.id_nodo_par = datos["id_nodo"]
        self.P, self.Q, self.S, self.N = datos["P"], datos["Q"], datos["S"], datos["N"]
        self._construir_tabla()
        payload_respuesta = proto.construir_payload_fcm(self.id_nodo_local, self.P, self.Q, self.S, self.N)
        return proto.Trama(self.id_nodo_local, proto.MSG_FCM, payload_respuesta, psn=self.psn_actual)

    def completar_fcm_como_iniciador(self, trama: proto.Trama) -> None:
        """Registra el NodeID del receptor y finaliza la construcción de la tabla local."""
        datos = proto.parsear_payload_fcm(trama.payload)
        self.id_nodo_par = datos["id_nodo"]
        self._construir_tabla()

    def _construir_tabla(self) -> None:
        """Deriva la tabla de llaves determinista y habilita la sesión activa."""
        self.tabla_llaves = llaves.generar_tabla_llaves(self.P, self.Q, self.S, self.N)
        self.psn_actual = self.S & 0xF
        self.establecida = True

    # -------------------------------------------------------------
    # RM: mensajes regulares (cifrados)
    # -------------------------------------------------------------
    def construir_rm(self, texto_plano: bytes) -> proto.Trama:
        """Cifra un mensaje de datos usando la llave del PSN actual y actualiza el puntero."""
        psn = self.psn_actual
        texto_cifrado = cifrado.cifrar_payload(texto_plano, self.tabla_llaves, psn)
        self.psn_actual = cifrado.siguiente_psn_desde_cifrado(texto_cifrado, psn)
        return proto.Trama(self.id_nodo_local, proto.MSG_RM, texto_cifrado, psn)

    def recibir_rm(self, trama: proto.Trama) -> bytes:
        """Descifra una trama de datos recibida y actualiza el puntero PSN."""
        psn = trama.psn
        texto_plano = cifrado.descifrar_payload(trama.payload, self.tabla_llaves, psn)
        self.psn_actual = cifrado.siguiente_psn_desde_cifrado(trama.payload, psn)
        return texto_plano

    # -------------------------------------------------------------
    # KUM: actualización de llaves (nueva semilla viaja cifrada )
    # -------------------------------------------------------------
    def construir_kum(self) -> proto.Trama:
        """Genera una nueva semilla, la envía cifrada y regenera la tabla local."""
        nueva_semilla = llaves.generar_semilla_pseudoaleatoria()
        psn = self.psn_actual
        cuerpo = json.dumps({"S": nueva_semilla}).encode()
        texto_cifrado = cifrado.cifrar_payload(cuerpo, self.tabla_llaves, psn)
        trama = proto.Trama(self.id_nodo_local, proto.MSG_KUM, texto_cifrado, psn)

        # Actualiza el estado criptográfico local
        self.S = nueva_semilla
        self._construir_tabla()
        return trama

    def recibir_kum(self, trama: proto.Trama) -> None:
        """Descifra la nueva semilla enviada por el par y regenera la tabla de llaves."""
        psn = trama.psn
        cuerpo = cifrado.descifrar_payload(trama.payload, self.tabla_llaves, psn)
        nueva_semilla = json.loads(cuerpo.decode())["S"]
        self.S = nueva_semilla
        self._construir_tabla()

    # -------------------------------------------------------------
    # LCM: fin de la comunicación (borra tabla e identificador de par)
    # -------------------------------------------------------------
    def construir_lcm(self, motivo: bytes = b"fin") -> proto.Trama:
        """Construye un mensaje de cierre cifrado indicando la finalización de la sesión."""
        psn = self.psn_actual
        texto_cifrado = cifrado.cifrar_payload(motivo, self.tabla_llaves, psn)
        return proto.Trama(self.id_nodo_local, proto.MSG_LCM, texto_cifrado, psn)

    def recibir_lcm(self, trama: proto.Trama) -> bytes:
        """Descifra el motivo de cierre y elimina las credenciales de la sesión."""
        texto_plano = cifrado.descifrar_payload(trama.payload, self.tabla_llaves, trama.psn)
        self.cerrar()
        return texto_plano

    def cerrar(self) -> None:
        """Limpia la tabla de llaves de la memoria y deshabilita la sesión."""
        self.tabla_llaves = []
        self.id_nodo_par = None
        self.establecida = False
