from scapy.all import sniff, IP, TCP, UDP
import requests
import json
from datetime import datetime, timedelta

# Configuración del bot de Telegram
TELEGRAM_TOKEN = "TuTokenBot"
CHAT_ID = "TuCharId"
TELEGRAM_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/"

# Puertos importantes para monitorear
PUERTOS_SOSPECHOSOS = [
    22,    # SSH
    23,    # Telnet
    21,    # FTP
    80,    # HTTP
    443,   # HTTPS
    445,   # Samba
    8080,  # HTTP alternativo
    8443,  # HTTPS alternativo
    3389   # Escritorio remoto (RDP)
]

# Cache para deduplicación
EVENTOS_RECIENTES = {}
CACHE_EXPIRATION = timedelta(minutes=1)  # Tiempo para olvidar eventos repetidos 1 minuto por defecto.

# Historial de conexiones
HISTORIAL_CONEXIONES = {}
ULTIMO_ENVIO = datetime.now()

# Whitelist (IPs, puertos, combinaciones permitidas)
WHITELIST_FILE = "whitelist.json"
try:
    with open(WHITELIST_FILE, "r") as f:
        WHITELIST = json.load(f)
except FileNotFoundError:
    WHITELIST = []

# Funciones auxiliares

def guardar_whitelist():
    with open(WHITELIST_FILE, "w") as f:
        json.dump(WHITELIST, f, indent=4)

def esta_en_whitelist(clave_evento):
    ip_origen, ip_destino, puerto = clave_evento
    for entrada in WHITELIST:
        if isinstance(entrada, list) and len(entrada) == 3:
            if (ip_origen, ip_destino, puerto) == tuple(entrada):
                return True
        elif isinstance(entrada, str):
            if ip_origen == entrada or ip_destino == entrada:
                return True
    return False

def calcular_duracion(inicio):
    ahora = datetime.now()
    delta = ahora - inicio
    dias, resto = divmod(delta.total_seconds(), 86400)
    horas, resto = divmod(resto, 3600)
    minutos, segundos = divmod(resto, 60)
    return f"{int(dias)}d {int(horas)}h {int(minutos)}m {int(segundos)}s"

def enviar_mensajes_individuales():
    global ULTIMO_ENVIO
    ahora = datetime.now()
    if ahora - ULTIMO_ENVIO < timedelta(minutes=1):
        return

    ULTIMO_ENVIO = ahora

    for clave_evento, datos in HISTORIAL_CONEXIONES.items():
        ip_origen, ip_destino, puerto = clave_evento
        if esta_en_whitelist(clave_evento):
            continue

        duracion = calcular_duracion(datos["inicio"])
        contador = datos["contador"]

        mensaje = (
            f"🚨 *Tráfico Detectado* 🚨\n"
            f"📅 Hora: {ahora.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"📥 Origen: {ip_origen}\n"
            f"📤 Destino: {ip_destino}\n"
            f"🔐 Puerto: {puerto}\n"
            f"⏳ Tiempo conectado: {duracion}\n"
        )

        callback_data = f"whitelist|{ip_origen}|{ip_destino}|{puerto}"
        enviar_alerta_con_boton(mensaje, callback_data)

def enviar_alerta_con_boton(mensaje, callback_data):
    payload = {
        "chat_id": CHAT_ID,
        "text": mensaje,
        "parse_mode": "Markdown",
        "reply_markup": {
            "inline_keyboard": [
                [{"text": "➕ Añadir a Whitelist", "callback_data": callback_data}]
            ]
        }
    }
    try:
        response = requests.post(TELEGRAM_URL + "sendMessage", json=payload)
        if response.status_code != 200:
            print(f"Error al enviar mensaje a Telegram: {response.text}")
    except Exception as e:
        print(f"Error de conexión: {e}")

def manejar_callback():
    try:
        response = requests.get(TELEGRAM_URL + "getUpdates")
        if response.status_code == 200:
            updates = response.json().get("result", [])
            for update in updates:
                callback_query = update.get("callback_query")
                if callback_query:
                    data = callback_query.get("data")
                    if data and data.startswith("whitelist|"):
                        _, ip_origen, ip_destino, puerto = data.split("|")
                        clave_evento = [ip_origen, ip_destino, int(puerto)]
                        WHITELIST.append(clave_evento)
                        guardar_whitelist()
                        mensaje_confirmacion = (
                            f"✅ Tráfico permitido:\n"
                            f"📥 Origen: {ip_origen}\n"
                            f"📤 Destino: {ip_destino}\n"
                            f"🔐 Puerto: {puerto}\n\n"
                            "No se enviarán más alertas para este tráfico."
                        )
                        payload = {
                            "chat_id": CHAT_ID,
                            "text": mensaje_confirmacion,
                            "parse_mode": "Markdown"
                        }
                        requests.post(TELEGRAM_URL + "sendMessage", json=payload)
    except Exception as e:
        print(f"Error al manejar callbacks: {e}")

# Función para procesar paquetes
def procesar_paquete(paquete):
    if IP in paquete:
        ip_origen = paquete[IP].src
        ip_destino = paquete[IP].dst

        # Verificar si el paquete es TCP o UDP
        if TCP in paquete or UDP in paquete:
            puerto_destino = paquete[TCP].dport if TCP in paquete else paquete[UDP].dport

            # Filtrar por puertos sospechosos
            if puerto_destino not in PUERTOS_SOSPECHOSOS:
                return  # Ignorar puertos no relevantes

            # Filtrar solo tráfico entrante (hacia la máquina monitoreada)
            if paquete[IP].dst != "TUIPDEMAQUINA":
                return

            clave_evento = (ip_origen, ip_destino, puerto_destino)

            # Verificar si el tráfico está en la whitelist
            if esta_en_whitelist(clave_evento):
                return  # Ignorar tráfico permitido

            ahora = datetime.now()

            # Actualizar historial de conexiones
            if clave_evento not in HISTORIAL_CONEXIONES:
                HISTORIAL_CONEXIONES[clave_evento] = {
                    "inicio": ahora,
                    "contador": 0
                }
            HISTORIAL_CONEXIONES[clave_evento]["contador"] += 1

# Función para limpiar eventos antiguos
def limpiar_cache():
    ahora = datetime.now()
    expirados = [k for k, v in EVENTOS_RECIENTES.items() if ahora - v > CACHE_EXPIRATION]
    for k in expirados:
        del EVENTOS_RECIENTES[k]

# Función principal para iniciar el monitoreo
def iniciar_monitoreo():
    try:
        print("Iniciando monitoreo en todas las interfaces...")
        while True:
            sniff(iface=None, prn=procesar_paquete, store=False, timeout=60)
            enviar_mensajes_individuales()
            manejar_callback()
            limpiar_cache()
    except Exception as e:
        print(f"Error al iniciar el monitoreo: {e}")

if __name__ == "__main__":
    iniciar_monitoreo()
