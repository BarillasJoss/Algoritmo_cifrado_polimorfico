# Algoritmo de Cifrado Polimórfico (Implementación Modalidad B)

Implementación en Python de dos nodos IoT (cliente/transmisor y servidor/receptor)
que se comunican mediante **sockets TCP**, protegiendo el payload con el modelo
criptográfico polimórfico descrito en:

> Bran, C., Flores, D., Hernández, C. *"Cryptography model to secure IoT device
> endpoints, based on polymorphic cipher OTP"*.

Trabajo de investigación — Diseño de sistemas de seguridad en redes de datos
(DSS101), Universidad Don Bosco, ciclo 02-2026.

## Escenario utilizado

- **Modalidad B — Simulación por software.** Cada nodo es un proceso Python
  independiente. La comunicación se realiza sobre **TCP** (sockets nativos de
  Python), en `localhost` o entre dos máquinas de una misma red.
- No se usan librerías criptográficas externas: el cifrado, la generación de
  llaves de 64 bits y la selección polimórfica de funciones están implementados
  desde cero según el modelo del paper.
- Todos los nombres de archivos, funciones, variables y comentarios están en
  español. Se conservan únicamente las siglas propias del paper y de la
  consigna de la tarea: **NodeID, Type, Payload, PSN, FCM, RM, KUM, LCM**.

## Estructura del repositorio

| Archivo                | Contenido                                                                 |
|--------------------------|----------------------------------------------------------------------------|
| `generador_llaves.py`    | Generación dinámica de tablas de llaves de 64 bits (funciones `fs`, `fg`, `fm`, Fig. 3 del paper). |
| `cifrado.py`             | Banco de 6 funciones reversibles y selección de secuencia/llave a partir del PSN (Fig. 4 del paper). |
| `protocolo.py`           | Encapsulado de trama NodeID(6 bits)/Type(4 bits)/Payload/PSN(4 bits) (Fig. 2) + framing sobre TCP. |
| `sesion_par.py`          | Estado de un par IoT: maneja FCM, RM, KUM, LCM usando `generador_llaves.py` y `cifrado.py`. |
| `nodo_servidor.py`       | Nodo receptor (servidor TCP).                                             |
| `nodo_cliente.py`        | Nodo transmisor (cliente TCP, inicia siempre la comunicación).            |
| `prueba_estres.py`       | Prueba de carga (miles de mensajes) sin red, para medir tasa de éxito.    |
| `demo_polimorfismo.py`   | Envía el mismo mensaje varias veces y muestra que el texto cifrado cambia cada vez. |

## Requisitos

- Python 3.10+ (usa solo librería estándar: `socket`, `struct`, `json`, `random`).

## Instrucciones de ejecución

### 1. Terminal 1 — levantar el nodo servidor (receptor)

```bash
python3 nodo_servidor.py --anfitrion 0.0.0.0 --puerto 9090 --id-nodo 5
```

### 2. Terminal 2 — levantar el nodo cliente (transmisor)

```bash
python3 nodo_cliente.py --anfitrion 127.0.0.1 --puerto 9090 --id-nodo 12
```

El cliente:
1. Genera `P`, `Q`, `S` localmente y envía el mensaje **FCM**.
2. Recibe la confirmación FCM del servidor; ambos calculan (sin transmitirla)
   la misma tabla de 16 llaves de 64 bits.
3. Envía 4 mensajes **RM** (lecturas simuladas de sensores), cada uno cifrado
   con una llave y secuencia de funciones distinta (el PSN cambia cada vez), y
   valida el ACK cifrado que regresa el servidor.
4. Envía un **KUM** para rotar la tabla de llaves a mitad de sesión.
5. Envía 3 mensajes **RM** más, ya con la tabla nueva.
6. Envía un **LCM** para cerrar la sesión (ambos nodos destruyen su tabla de
   llaves y el identificador del par).

Al final el cliente imprime un resumen con mensajes enviados, ACKs verificados
y discrepancias (equivalente a la Tabla I "Simulation results" del paper).

### 3. Prueba de carga

```bash
python3 prueba_estres.py
```

Corre 2000 mensajes RM con rotaciones de llave periódicas y reporta la tasa de
éxito de descifrado (en nuestras pruebas: **100.00 %**, 0 errores).

### 4. Demostración de polimorfismo

```bash
python3 demo_polimorfismo.py --mensaje "Temp: 25C" --veces 8
```

Envía el mismo mensaje varias veces seguidas y muestra que el texto cifrado
resultante cambia en cada envío (porque el PSN, la llave y la secuencia de
funciones cambian con cada mensaje), aunque el mensaje recuperado siempre sea
el original.

## Notas de diseño (decisiones tomadas para completar el modelo)

El paper describe la arquitectura y el flujo del algoritmo, pero no publica
las expresiones exactas de `fs`, `fg`, `fm`, ni el banco completo de funciones
reversibles ni la tabla de mapeo PSN→secuencia (son detalles de
implementación abiertos al diseñador). Para esta implementación:

- `fs`, `fg`, `fm` se implementaron como mezcladores de 64 bits tipo
  *splitmix* (multiplicaciones con constantes impares + rotaciones + XOR),
  cumpliendo el requisito del paper de ser "lo más ligeras posible".
- El banco de funciones reversibles incluye 6 operaciones (XOR, suma/resta
  modular, rotación de bits, sustitución tipo S-box derivada de la llave,
  intercambio de bytes y XOR dependiente de posición); el PSN determina de
  forma determinista una secuencia de 3 de ellas y su orden.
- El siguiente PSN se deriva del nibble menos significativo del último byte
  del texto cifrado enviado, tal como indica el paper ("the PSN includes the
  pointer to the part of the next message to be used as PSN").

Estas decisiones están documentadas también en el documento de investigación
entregado junto con este repositorio.
