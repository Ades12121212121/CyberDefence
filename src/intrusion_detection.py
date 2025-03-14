import os
import re
import socket
import subprocess
import platform
from datetime import datetime

def check_active_connections():
    """Verifica las conexiones de red activas"""
    suspicious_connections = []
    
    try:
        if platform.system() == "Windows":
            # En Windows, usamos netstat
            output = subprocess.check_output("netstat -ano", shell=True).decode('utf-8')
            
            # Buscar conexiones establecidas desde IPs externas
            connections = re.findall(r'TCP\s+[\d\.]+:(\d+)\s+([\d\.]+):(\d+)\s+ESTABLISHED\s+(\d+)', output)
            
            for local_port, remote_ip, remote_port, pid in connections:
                # Verificar si la IP remota es sospechosa (ejemplo simple)
                if not remote_ip.startswith(('10.', '192.168.', '127.')):
                    # Obtener el nombre del proceso
                    try:
                        process_info = subprocess.check_output(f"tasklist /fi \"PID eq {pid}\"", shell=True).decode('utf-8')
                        process_name = re.search(r'(\w+\.exe)', process_info)
                        process_name = process_name.group(1) if process_name else "Desconocido"
                    except:
                        process_name = "Desconocido"
                    
                    suspicious_connections.append({
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'pid': pid,
                        'process': process_name
                    })
    
    except Exception as e:
        print(f"Error al verificar conexiones: {e}")
    
    return suspicious_connections

def check_unusual_processes():
    """Verifica procesos inusuales o sospechosos"""
    suspicious_processes = []
    
    try:
        if platform.system() == "Windows":
            # Lista de procesos potencialmente maliciosos o sospechosos
            suspicious_names = ['nc.exe', 'ncat.exe', 'mimikatz', 'psexec', 'powershell.exe']
            
            output = subprocess.check_output("tasklist /fo csv", shell=True).decode('utf-8')
            for line in output.splitlines()[1:]:  # Saltar la primera línea (encabezado)
                try:
                    parts = line.strip('"').split('","')
                    process_name = parts[0]
                    pid = parts[1]
                    
                    # Verificar si el nombre del proceso está en la lista de sospechosos
                    for susp_name in suspicious_names:
                        if susp_name.lower() in process_name.lower():
                            suspicious_processes.append({
                                'name': process_name,
                                'pid': pid
                            })
                            break
                except:
                    continue
    
    except Exception as e:
        print(f"Error al verificar procesos: {e}")
    
    return suspicious_processes

def check_login_attempts():
    """Verifica intentos de inicio de sesión fallidos"""
    failed_logins = []
    
    try:
        if platform.system() == "Windows":
            # Usar wevtutil para obtener eventos de inicio de sesión fallidos
            # Event ID 4625 corresponde a intentos de inicio de sesión fallidos
            cmd = 'wevtutil qe Security /q:"*[System[(EventID=4625)]]" /f:text /c:10'
            output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
            
            # Extraer información relevante
            login_attempts = re.findall(r'Account Name:\s+(\S+).+?Account Domain:\s+(\S+).+?Workstation Name:\s+(\S+).+?Source Network Address:\s+(\S+)', 
                                       output, re.DOTALL)
            
            for username, domain, workstation, ip in login_attempts:
                if ip and ip != '-':
                    failed_logins.append({
                        'username': username,
                        'domain': domain,
                        'workstation': workstation,
                        'ip': ip,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
    
    except Exception as e:
        print(f"Error al verificar intentos de inicio de sesión: {e}")
    
    return failed_logins

def check_file_integrity(directories_to_monitor=None):
    """Verifica cambios en archivos críticos del sistema"""
    if directories_to_monitor is None:
        directories_to_monitor = [
            'c:\\Windows\\System32\\drivers',
            'c:\\Windows\\System32\\config'
        ]
    
    modified_files = []
    
    try:
        # Verificar archivos modificados en las últimas 24 horas
        one_day_ago = (datetime.now() - datetime.timedelta(days=1)).strftime('%Y%m%d%H%M%S')
        
        for directory in directories_to_monitor:
            if os.path.exists(directory):
                cmd = f'forfiles /P "{directory}" /S /D +{one_day_ago} /C "cmd /c echo @path @fdate @ftime"'
                try:
                    output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
                    for line in output.splitlines():
                        if line and not line.startswith('ERROR:'):
                            modified_files.append({
                                'path': line.split()[0].strip('"'),
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            })
                except subprocess.CalledProcessError:
                    # No files found or other error
                    pass
    
    except Exception as e:
        print(f"Error al verificar integridad de archivos: {e}")
    
    return modified_files

def check_scheduled_tasks():
    """Verifica tareas programadas sospechosas"""
    suspicious_tasks = []
    
    try:
        output = subprocess.check_output("schtasks /query /fo csv /v", shell=True).decode('utf-8')
        
        # Buscar tareas que ejecuten PowerShell, cmd o scripts potencialmente peligrosos
        for line in output.splitlines()[1:]:  # Saltar la primera línea (encabezado)
            try:
                parts = line.strip('"').split('","')
                if len(parts) > 8:
                    task_name = parts[0]
                    task_command = parts[8] if len(parts) > 8 else ""
                    
                    # Verificar comandos sospechosos
                    suspicious_keywords = ['powershell -e', 'powershell.exe -e', 'cmd.exe /c', 'wget', 'curl', 
                                          'bitsadmin', 'certutil -urlcache', 'regsvr32', 'rundll32']
                    
                    for keyword in suspicious_keywords:
                        if keyword.lower() in task_command.lower():
                            suspicious_tasks.append({
                                'name': task_name,
                                'command': task_command,
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            })
                            break
            except:
                continue
    
    except Exception as e:
        print(f"Error al verificar tareas programadas: {e}")
    
    return suspicious_tasks

def check_intrusions():
    """Función principal para detectar posibles intrusiones"""
    intrusions = []
    
    # Verificar conexiones sospechosas
    suspicious_connections = check_active_connections()
    if suspicious_connections:
        print(f"[!] Se detectaron {len(suspicious_connections)} conexiones sospechosas:")
        for conn in suspicious_connections:
            print(f"    - {conn['remote_ip']}:{conn['remote_port']} -> Puerto local {conn['local_port']} (Proceso: {conn['process']}, PID: {conn['pid']})")
            intrusions.append({
                'type': 'suspicious_connection',
                'details': conn,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
    
    # Verificar procesos sospechosos
    suspicious_processes = check_unusual_processes()
    if suspicious_processes:
        print(f"[!] Se detectaron {len(suspicious_processes)} procesos sospechosos:")
        for proc in suspicious_processes:
            print(f"    - {proc['name']} (PID: {proc['pid']})")
            intrusions.append({
                'type': 'suspicious_process',
                'details': proc,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
    
    # Verificar intentos de inicio de sesión fallidos
    failed_logins = check_login_attempts()
    if failed_logins:
        print(f"[!] Se detectaron {len(failed_logins)} intentos de inicio de sesión fallidos:")
        for login in failed_logins:
            print(f"    - Usuario: {login['username']}, IP: {login['ip']}, Estación de trabajo: {login['workstation']}")
            intrusions.append({
                'type': 'failed_login',
                'details': login,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
    
    # Verificar cambios en archivos críticos
    modified_files = check_file_integrity()
    if modified_files:
        print(f"[!] Se detectaron {len(modified_files)} archivos críticos modificados:")
        for file in modified_files:
            print(f"    - {file['path']}")
            intrusions.append({
                'type': 'modified_file',
                'details': file,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
    
    # Verificar tareas programadas sospechosas
    suspicious_tasks = check_scheduled_tasks()
    if suspicious_tasks:
        print(f"[!] Se detectaron {len(suspicious_tasks)} tareas programadas sospechosas:")
        for task in suspicious_tasks:
            print(f"    - {task['name']}: {task['command']}")
            intrusions.append({
                'type': 'suspicious_task',
                'details': task,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
    
    # Guardar las intrusiones detectadas en un archivo
    if intrusions:
        log_file = os.path.join('c:\\Users\\pc123\\OneDrive\\Escritorio\\Defence\\logs', 'intrusions.log')
        with open(log_file, 'a') as f:
            for intrusion in intrusions:
                f.write(f"[{intrusion['timestamp']}] Tipo: {intrusion['type']}, Detalles: {intrusion['details']}\n")
    
    return intrusions