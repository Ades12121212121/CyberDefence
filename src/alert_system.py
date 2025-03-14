import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import platform
import subprocess
from datetime import datetime

def load_config():
    """Carga la configuración de alertas desde el archivo de configuración"""
    config_file = os.path.join('c:\\Users\\pc123\\OneDrive\\Escritorio\\Defence\\config', 'config.json')
    
    # Crear configuración por defecto si no existe
    if not os.path.exists(config_file):
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        default_config = {
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "username": "tu_correo@gmail.com",
                "password": "tu_contraseña_o_clave_de_app",
                "from_email": "tu_correo@gmail.com",
                "to_email": "destinatario@ejemplo.com"
            },
            "desktop_notifications": {
                "enabled": True
            },
            "log_alerts": {
                "enabled": True,
                "log_file": "c:\\Users\\pc123\\OneDrive\\Escritorio\\Defence\\logs\\alerts.log"
            },
            "severity_levels": {
                "low": {
                    "color": "blue",
                    "notify": false
                },
                "medium": {
                    "color": "yellow",
                    "notify": true
                },
                "high": {
                    "color": "red",
                    "notify": true
                },
                "critical": {
                    "color": "purple",
                    "notify": true
                }
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        
        print(f"[*] Archivo de configuración creado en {config_file}")
        print("[*] Por favor, edite el archivo para configurar las alertas por correo electrónico")
        
        return default_config
    
    # Cargar configuración existente
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error al cargar la configuración: {e}")
        return None

def send_email_alert(subject, message, severity="medium"):
    """Envía una alerta por correo electrónico"""
    config = load_config()
    
    if not config or not config.get("email", {}).get("enabled", False):
        print("[!] Las alertas por correo electrónico no están habilitadas")
        return False
    
    try:
        # Configurar el mensaje
        email_config = config["email"]
        msg = MIMEMultipart()
        msg['From'] = email_config["from_email"]
        msg['To'] = email_config["to_email"]
        msg['Subject'] = f"[ALERTA {severity.upper()}] {subject}"
        
        # Añadir el cuerpo del mensaje
        body = f"""
        <html>
        <body>
            <h2 style="color: red;">Alerta de Seguridad: {subject}</h2>
            <p><strong>Severidad:</strong> {severity}</p>
            <p><strong>Fecha y Hora:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Sistema:</strong> {platform.node()}</p>
            <hr>
            <pre>{message}</pre>
        </body>
        </html>
        """
        msg.attach(MIMEText(body, 'html'))
        
        # Conectar al servidor SMTP y enviar
        server = smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"])
        server.starttls()
        server.login(email_config["username"], email_config["password"])
        server.send_message(msg)
        server.quit()
        
        print(f"[+] Alerta enviada por correo electrónico a {email_config['to_email']}")
        return True
        
    except Exception as e:
        print(f"[!] Error al enviar alerta por correo electrónico: {e}")
        return False

def send_desktop_notification(title, message, severity="medium"):
    """Envía una notificación de escritorio"""
    config = load_config()
    
    if not config or not config.get("desktop_notifications", {}).get("enabled", False):
        return False
    
    try:
        if platform.system() == "Windows":
            # En Windows, usamos PowerShell para mostrar notificaciones
            ps_script = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

            $app = '{platform.node()}'
            $template = @"
            <toast>
                <visual>
                    <binding template='ToastText02'>
                        <text id='1'>[{severity.upper()}] {title}</text>
                        <text id='2'>{message}</text>
                    </binding>
                </visual>
            </toast>
            "@

            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xml.LoadXml($template)
            $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toast)
            """
            
            # Ejecutar el script de PowerShell
            subprocess.run(["powershell", "-Command", ps_script], capture_output=True)
            
            print(f"[+] Notificación de escritorio enviada: {title}")
            return True
            
    except Exception as e:
        print(f"[!] Error al enviar notificación de escritorio: {e}")
        return False

def log_alert(title, message, severity="medium"):
    """Registra una alerta en el archivo de log"""
    config = load_config()
    
    if not config or not config.get("log_alerts", {}).get("enabled", False):
        return False
    
    try:
        log_file = config["log_alerts"]["log_file"]
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        with open(log_file, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] [{severity.upper()}] {title}\n")
            f.write(f"{message}\n")
            f.write("-" * 80 + "\n")
        
        print(f"[+] Alerta registrada en {log_file}")
        return True
        
    except Exception as e:
        print(f"[!] Error al registrar alerta en log: {e}")
        return False

def send_alert(title, message, severity="medium", details=None):
    """Función principal para enviar alertas por diferentes canales"""
    # Formatear el mensaje con detalles adicionales si se proporcionan
    formatted_message = message
    if details:
        formatted_message += "\n\nDetalles:\n"
        if isinstance(details, dict):
            for key, value in details.items():
                formatted_message += f"- {key}: {value}\n"
        elif isinstance(details, list):
            for item in details:
                if isinstance(item, dict):
                    formatted_message += "\n"
                    for key, value in item.items():
                        formatted_message += f"- {key}: {value}\n"
                else:
                    formatted_message += f"- {item}\n"
        else:
            formatted_message += str(details)
    
    # Registrar la alerta en el log
    log_alert(title, formatted_message, severity)
    
    # Enviar notificación de escritorio
    send_desktop_notification(title, message, severity)
    
    # Enviar alerta por correo electrónico para severidades media, alta y crítica
    if severity in ["medium", "high", "critical"]:
        send_email_alert(title, formatted_message, severity)
    
    return True

# Función para probar el sistema de alertas
def test_alert_system():
    """Prueba el sistema de alertas"""
    print("[*] Probando sistema de alertas...")
    
    # Cargar configuración
    config = load_config()
    if not config:
        print("[!] No se pudo cargar la configuración")
        return False
    
    # Probar alerta de baja severidad
    send_alert(
        "Prueba de alerta de baja severidad",
        "Esta es una prueba del sistema de alertas con severidad baja.",
        "low",
        {"tipo": "prueba", "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    )
    
    # Probar alerta de severidad media
    send_alert(
        "Prueba de alerta de severidad media",
        "Esta es una prueba del sistema de alertas con severidad media.",
        "medium",
        {"tipo": "prueba", "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    )
    
    # Probar alerta de alta severidad
    send_alert(
        "Prueba de alerta de alta severidad",
        "Esta es una prueba del sistema de alertas con severidad alta.",
        "high",
        {"tipo": "prueba", "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    )
    
    print("[+] Pruebas de sistema de alertas completadas")
    return True

if __name__ == "__main__":
    # Si se ejecuta este archivo directamente, probar el sistema de alertas
    test_alert_system()