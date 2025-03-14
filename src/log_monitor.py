import os
import re
import time
from datetime import datetime
import threading

# Patrones para detectar posibles amenazas en logs
SUSPICIOUS_PATTERNS = [
    r'failed password',
    r'authentication failure',
    r'invalid user',
    r'unauthorized access',
    r'permission denied',
    r'access denied',
    r'brute force',
    r'injection',
    r'exploit',
    r'vulnerability'
]

def parse_log_line(line):
    """Analiza una línea de log para detectar patrones sospechosos"""
    line = line.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, line):
            return True
    return False

def monitor_log_file(log_file):
    """Monitorea un archivo de log en tiempo real"""
    try:
        with open(log_file, 'r') as f:
            # Ir al final del archivo
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                if parse_log_line(line):
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    print(f"[{timestamp}] ALERTA: Actividad sospechosa detectada: {line.strip()}")
                    
                    # Guardar la alerta en nuestro propio log
                    with open(os.path.join('c:\\Users\\pc123\\OneDrive\\Escritorio\\Defence\\logs', 'alerts.log'), 'a') as alert_log:
                        alert_log.write(f"[{timestamp}] {line}")
    
    except Exception as e:
        print(f"Error al monitorear el archivo {log_file}: {e}")

def monitor_logs():
    """Inicia el monitoreo de logs en múltiples archivos"""
    # Lista de archivos de log a monitorear (ajustar según el sistema)
    log_files = [
        'c:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log',
        # Añadir más archivos de log según sea necesario
    ]
    
    # Crear nuestro propio archivo de log si no existe
    os.makedirs('c:\\Users\\pc123\\OneDrive\\Escritorio\\Defence\\logs', exist_ok=True)
    if not os.path.exists('c:\\Users\\pc123\\OneDrive\\Escritorio\\Defence\\logs\\alerts.log'):
        with open('c:\\Users\\pc123\\OneDrive\\Escritorio\\Defence\\logs\\alerts.log', 'w') as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Inicio del monitoreo de logs\n")
    
    # Iniciar un hilo para cada archivo de log
    threads = []
    for log_file in log_files:
        if os.path.exists(log_file):
            thread = threading.Thread(target=monitor_log_file, args=(log_file,), daemon=True)
            thread.start()
            threads.append(thread)
            print(f"Monitoreando: {log_file}")
        else:
            print(f"Archivo de log no encontrado: {log_file}")
    
    # Si no se encontraron archivos de log, monitorear solo nuestro propio log
    if not threads:
        print("No se encontraron archivos de log del sistema. Monitoreando solo logs internos.")
        
    # Mantener el monitoreo activo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Monitoreo de logs detenido")