# WatchPort: Monitor de Tráfico de Red con Telegram

Este proyecto es un monitor de tráfico de red que utiliza Scapy para capturar paquetes y un bot de Telegram para notificar eventos relevantes, como conexiones sospechosas o actividad en puertos importantes.

## Características

- Monitorea el tráfico entrante en puertos específicos.
- Filtra eventos repetidos mediante un sistema de cache.
- Envía alertas a un bot de Telegram con detalles del evento.
- Permite agregar excepciones (whitelist) a través de un bot para ignorar conexiones conocidas.
- Mantiene un registro interno de conexiones activas y sus duraciones.

## Requisitos

- Python 3.6 o superior
- Bibliotecas de Python:
  - `scapy`
  - `requests`
  - `json`
- Acceso de administrador para monitorear interfaces de red.

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/FalconAkantor/WatchPort.git
   cd WatchPort
   ```
2. Instala las dependencias necesarias:
   ```bash
   pip install -r requirements.txt
   ```

3. Configura tu bot de Telegram:
   - Obtén un token desde [BotFather](https://t.me/botfather).
   - Reemplaza `TELEGRAM_TOKEN` y `CHAT_ID` en el código por tu token y el ID del chat donde recibirás las alertas.

## Configuración

### Puertos a monitorear

En la variable `PUERTOS_SOSPECHOSOS`, define los puertos que deseas monitorear:
```python
PUERTOS_SOSPECHOSOS = [
    21,    #FTP
    22,    # SSH
    23,    # Telnet
    80,    # HTTP
    443,   # HTTPS
    445,   # Samba
    8080,  # HTTP alternativo
    3389   # Escritorio remoto (RDP)
]
```

### Whitelist

El sistema incluye una lista blanca para ignorar conexiones conocidas. Esta lista se almacena en `whitelist.json` y se actualiza automáticamente al usar el bot de Telegram.

## Uso

1. Ejecuta el script:
   ```bash
   sudo python3 watchport.py
   ```
2. Recibirás alertas en Telegram con los detalles de cada conexión sospechosa, incluyendo:
   - IP de origen
   - IP de destino
   - Puerto involucrado
   - Tiempo de conexión

3. Si una conexión es segura, puedes agregarla a la whitelist desde el bot haciendo clic en el botón:
   - `➕ Añadir a Whitelist`

## Estructura del Código

### 1. Configuración Inicial

- Define las variables para el bot de Telegram, los puertos a monitorear y la duración de la caché, ademas de la IP local de tu máquina:
  ```python
  TELEGRAM_TOKEN = "<TU_TOKEN>"
  CHAT_ID = "<TU_CHAT_ID>"
  PUERTOS_SOSPECHOSOS = [22, 80, 443, ...]
  CACHE_EXPIRATION = timedelta(minutes=1)
  if paquete[IP].dst != "Tu maquina":
  ```

### 2. Captura de Paquetes

- Utiliza `scapy.sniff` para capturar paquetes en todas las interfaces:
  ```python
  sniff(iface=None, prn=procesar_paquete, store=False, timeout=60)
  ```

### 3. Procesamiento de Paquetes

- Extrae información como IPs de origen/destino y puerto.
- Filtra el tráfico según:
  - Tráfico entrante a la máquina monitoreada.
  - Puertos definidos en `PUERTOS_SOSPECHOSOS`.

### 4. Notificaciones de Telegram

- Envía un mensaje al bot con detalles del evento:
  ```python
  enviar_alerta_con_boton(mensaje, callback_data)
  ```
- Incluye un botón para agregar la conexión a la whitelist.

### 5. Whitelist

- Las conexiones permitidas no generan alertas.
- La whitelist se guarda en un archivo JSON y se actualiza automáticamente desde el bot.

## Ejemplo de Alerta

```
🚨 Tráfico Detectado 🚨
📅 Hora: 2025-01-26 14:45:25
📥 Origen: 192.168.1.10
📤 Destino: 192.168.1.42
🔐 Puerto: 443
🔄 Contador: 3
⏳ Tiempo conectado: 0d 0h 3m 12s
```

## Mejoras Futuras

- Compatibilidad con tráfico IPv6.
- Opciones para filtrar eventos por geolocalización.

## Contribuciones

Las contribuciones son bienvenidas..

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo `LICENSE` para más información.
