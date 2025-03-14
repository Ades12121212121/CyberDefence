import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import time

def check_port(host, port):
    """Verifica si un puerto específico está abierto"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return port if result == 0 else None

def scan_ports(host, start_port, end_port):
    """Escanea un rango de puertos en un host específico"""
    open_ports = []
    print(f"Escaneando puertos {start_port}-{end_port} en {host}...")
    start_time = time.time()
    
    # Usamos ThreadPoolExecutor para escanear puertos en paralelo
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(check_port, host, port) for port in range(start_port, end_port + 1)]
        for future in futures:
            result = future.result()
            if result:
                service = get_service_name(result)
                open_ports.append(result)
                print(f"Puerto {result} abierto - {service}")
    
    scan_time = time.time() - start_time
    print(f"Escaneo completado en {scan_time:.2f} segundos")
    return open_ports

def get_service_name(port):
    """Obtiene el nombre del servicio para un puerto conocido"""
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP Alternativo"
    }
    return common_ports.get(port, "Desconocido")