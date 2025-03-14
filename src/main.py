import argparse
import sys
import os
from datetime import datetime
import time

# Importamos los módulos de nuestra aplicación
from port_scanner import scan_ports
from log_monitor import monitor_logs
from intrusion_detection import check_intrusions
from alert_system import send_alert
from dashboard import start_dashboard

def setup_argparse():
    parser = argparse.ArgumentParser(description='Herramienta de Ciberseguridad para Protección de Servidores')
    parser.add_argument('--scan', '-s', help='Escanear puertos en un host específico', action='store_true')
    parser.add_argument('--host', '-H', help='Host objetivo para escaneo', default='127.0.0.1')
    parser.add_argument('--ports', '-p', help='Rango de puertos a escanear (ej: 20-100)', default='1-1024')
    parser.add_argument('--monitor', '-m', help='Monitorear logs del sistema', action='store_true')
    parser.add_argument('--check', '-c', help='Verificar intentos de intrusión', action='store_true')
    parser.add_argument('--dashboard', '-d', help='Iniciar panel de control', action='store_true')
    
    return parser.parse_args()

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════╗
    ║         SISTEMA DE DEFENSA CIBERNÉTICA    ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)

def show_menu():
    while True:
        os.system('cls')
        print_banner()
        print(f"\nIniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\nOpciones disponibles:")
        print("1. Escanear puertos")
        print("2. Monitorear logs del sistema")
        print("3. Verificar intentos de intrusión")
        print("4. Abrir panel de control (GUI)")
        print("5. Salir")
        
        choice = input("\nSeleccione una opción (1-5): ")
        
        if choice == "1":
            host = input("\nIngrese el host objetivo (default: 127.0.0.1): ") or "127.0.0.1"
            ports = input("Ingrese el rango de puertos (ej: 1-1024): ") or "1-1024"
            start_port, end_port = map(int, ports.split('-'))
            print(f"\n[+] Escaneando puertos en {host}...")
            scan_results = scan_ports(host, start_port, end_port)
            print(f"[+] Escaneo completado. {len(scan_results)} puertos abiertos encontrados.")
            input("\nPresione Enter para continuar...")
            
        elif choice == "2":
            print("\n[+] Iniciando monitoreo de logs...")
            print("[*] Presione Ctrl+C para detener el monitoreo")
            try:
                monitor_logs()
            except KeyboardInterrupt:
                print("\n[*] Monitoreo detenido")
            input("\nPresione Enter para continuar...")
            
        elif choice == "3":
            print("\n[+] Verificando intentos de intrusión...")
            intrusions = check_intrusions()
            if intrusions:
                print(f"[!] Se detectaron {len(intrusions)} posibles intentos de intrusión")
                send_alert("Intrusión detectada", f"Se detectaron {len(intrusions)} intentos de intrusión")
            else:
                print("[+] No se detectaron intentos de intrusión")
            input("\nPresione Enter para continuar...")
            
        elif choice == "4":
            print("\n[+] Iniciando panel de control...")
            start_dashboard()
            
        elif choice == "5":
            print("\n[*] Saliendo del sistema...")
            time.sleep(1)
            sys.exit(0)
        
        else:
            print("\n[!] Opción no válida")
            time.sleep(1)

def main():
    if len(sys.argv) > 1:
        # Si hay argumentos, usar el parser original
        args = setup_argparse()
        
        print("=" * 50)
        print("SISTEMA DE DEFENSA CIBERNÉTICA")
        print(f"Iniciado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        if args.scan:
            print(f"\n[+] Escaneando puertos en {args.host}...")
            start_port, end_port = map(int, args.ports.split('-'))
            scan_results = scan_ports(args.host, start_port, end_port)
            print(f"[+] Escaneo completado. {len(scan_results)} puertos abiertos encontrados.")
            
        if args.monitor:
            print("\n[+] Iniciando monitoreo de logs...")
            monitor_logs()
            
        if args.check:
            print("\n[+] Verificando intentos de intrusión...")
            intrusions = check_intrusions()
            if intrusions:
                print(f"[!] Se detectaron {len(intrusions)} posibles intentos de intrusión")
                send_alert("Intrusión detectada", f"Se detectaron {len(intrusions)} intentos de intrusión")
            else:
                print("[+] No se detectaron intentos de intrusión")
        
        if args.dashboard:
            print("\n[+] Iniciando panel de control...")
            start_dashboard()
        
        if not any([args.scan, args.monitor, args.check, args.dashboard]):
            print("\n[!] No se especificó ninguna acción. Use --help para ver las opciones disponibles.")
            
        print("\n" + "=" * 50)
    else:
        # Si no hay argumentos, mostrar el menú interactivo
        show_menu()

if __name__ == "__main__":
    main()