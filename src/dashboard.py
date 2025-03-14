import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import time
from datetime import datetime
import psutil
import os

class Dashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Defensa Cibernética - Panel de Control")
        self.root.geometry("800x600")
        
        # Cola para comunicación entre hilos
        self.event_queue = queue.Queue()
        
        self.setup_ui()
        self.start_monitoring()
    
    def setup_ui(self):
        # Panel principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Sistema de pestañas
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True)
        
        # Pestaña de resumen
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text='Resumen')
        
        # Monitor de sistema
        system_frame = ttk.LabelFrame(summary_frame, text="Estado del Sistema", padding="5")
        system_frame.pack(fill='x', pady=5)
        
        self.cpu_label = ttk.Label(system_frame, text="CPU: 0%")
        self.cpu_label.pack(side='left', padx=5)
        
        self.memory_label = ttk.Label(system_frame, text="Memoria: 0%")
        self.memory_label.pack(side='left', padx=5)
        
        # Log de eventos
        log_frame = ttk.LabelFrame(summary_frame, text="Log de Eventos", padding="5")
        log_frame.pack(fill='both', expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill='both', expand=True)
        
        # Pestaña de conexiones
        connections_frame = ttk.Frame(notebook)
        notebook.add(connections_frame, text='Conexiones')
        
        self.connections_text = scrolledtext.ScrolledText(connections_frame)
        self.connections_text.pack(fill='both', expand=True)
        
        # Pestaña de procesos
        processes_frame = ttk.Frame(notebook)
        notebook.add(processes_frame, text='Procesos')
        
        self.processes_text = scrolledtext.ScrolledText(processes_frame)
        self.processes_text.pack(fill='both', expand=True)
        
        # Botones de control
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=5)
        
        ttk.Button(control_frame, text="Escanear Puertos", 
                  command=self.scan_ports).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Verificar Intrusiones", 
                  command=self.check_intrusions).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Limpiar Logs", 
                  command=self.clear_logs).pack(side='left', padx=5)
    
    def start_monitoring(self):
        """Inicia el monitoreo del sistema en segundo plano"""
        def monitor():
            while True:
                # Actualizar uso de CPU y memoria
                cpu_percent = psutil.cpu_percent()
                memory_percent = psutil.virtual_memory().percent
                
                self.event_queue.put(('update_system', {
                    'cpu': cpu_percent,
                    'memory': memory_percent
                }))
                
                # Actualizar conexiones activas
                connections = []
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED':
                        connections.append(f"{conn.laddr.ip}:{conn.laddr.port} -> "
                                        f"{conn.raddr.ip if conn.raddr else 'N/A'}:"
                                        f"{conn.raddr.port if conn.raddr else 'N/A'}")
                
                self.event_queue.put(('update_connections', connections))
                
                # Actualizar procesos
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append(f"PID: {proc.info['pid']} - {proc.info['name']} "
                                      f"(CPU: {proc.info['cpu_percent']}%, "
                                      f"Mem: {proc.info['memory_percent']:.1f}%)")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                self.event_queue.put(('update_processes', processes))
                
                time.sleep(2)
        
        # Iniciar hilo de monitoreo
        threading.Thread(target=monitor, daemon=True).start()
        self.update_ui()
    
    def update_ui(self):
        """Actualiza la interfaz con los datos del monitoreo"""
        try:
            while True:
                event_type, data = self.event_queue.get_nowait()
                
                if event_type == 'update_system':
                    self.cpu_label.config(text=f"CPU: {data['cpu']}%")
                    self.memory_label.config(text=f"Memoria: {data['memory']}%")
                
                elif event_type == 'update_connections':
                    self.connections_text.delete('1.0', tk.END)
                    self.connections_text.insert(tk.END, '\n'.join(data))
                
                elif event_type == 'update_processes':
                    self.processes_text.delete('1.0', tk.END)
                    self.processes_text.insert(tk.END, '\n'.join(data))
                
                elif event_type == 'log':
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.log_text.insert(tk.END, f"[{timestamp}] {data}\n")
                    self.log_text.see(tk.END)
        
        except queue.Empty:
            pass
        
        self.root.after(1000, self.update_ui)
    
    def scan_ports(self):
        """Inicia un escaneo de puertos"""
        self.event_queue.put(('log', 'Iniciando escaneo de puertos...'))
        # Aquí se implementaría la lógica de escaneo
    
    def check_intrusions(self):
        """Verifica intentos de intrusión"""
        self.event_queue.put(('log', 'Verificando intentos de intrusión...'))
        # Aquí se implementaría la lógica de detección
    
    def clear_logs(self):
        """Limpia los logs en pantalla"""
        self.log_text.delete('1.0', tk.END)
        self.event_queue.put(('log', 'Logs limpiados'))

def start_dashboard():
    """Inicia el panel de control"""
    root = tk.Tk()
    dashboard = Dashboard(root)
    root.mainloop()

if __name__ == "__main__":
    start_dashboard()