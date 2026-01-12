import sqlite3
import time
import tkinter as tk
from tkinter import scrolledtext
import threading
import os
import pandas as pd

try:
    from scapy.all import sniff, IP, TCP, UDP
    print("Scapy imported successfully!")
except ImportError:
    print("ERROR: Scapy not installed!")
    print("Please install it by running: pip install scapy")
    print("Then run this program again.")
    exit()

if os.path.exists('packets.db'):
    try:
        os.remove('packets.db')
        print("Old database file deleted - starting fresh!")
    except:
        print("Could not delete old database file")

print("Setting up database...")
conn = sqlite3.connect('packets.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port TEXT,
    dst_port TEXT,
    protocol TEXT,
    packet_size INTEGER,
    tcp_flags TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

cursor.execute('''
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT,
    source_ip TEXT,
    description TEXT,
    severity TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

conn.commit()
print("Database created successfully!")

ip_packet_counts = {}
ip_ports_tried = {}
syn_packet_counts = {}
suspicious_ports = [22, 23, 80, 443, 3389, 445, 21, 25, 53, 135, 139, 1433]

text_display = None
packet_counter = 0

def create_security_alert(alert_name, suspicious_ip, what_happened, how_serious="MEDIUM"):
    try:
        cursor.execute('''
            INSERT INTO alerts (alert_type, source_ip, description, severity)
            VALUES (?, ?, ?, ?)
        ''', (alert_name, suspicious_ip, what_happened, how_serious))
        conn.commit()
        
        alert_message = f"\n*** SECURITY ALERT! ***"
        alert_message += f"\nSeverity: {how_serious}"
        alert_message += f"\nType: {alert_name}"
        alert_message += f"\nSuspicious IP: {suspicious_ip}"
        alert_message += f"\nWhat happened: {what_happened}"
        alert_message += f"\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        alert_message += f"\n" + "="*50
        
        print(alert_message)
        
        if text_display:
            try:
                text_display.insert(tk.END, alert_message + "\n")
                text_display.see(tk.END)
            except:
                pass
                
    except Exception as e:
        print(f"Error creating alert: {e}")

def check_for_port_scanning(ip_address, port_number):
    if ip_address not in ip_ports_tried:
        ip_ports_tried[ip_address] = set()
    
    ip_ports_tried[ip_address].add(port_number)
    
    ports_tried = len(ip_ports_tried[ip_address])
    if ports_tried > 15:
        create_security_alert("Port Scanning Attack", ip_address, 
                            f"Tried {ports_tried} different ports", "CRITICAL")
        ip_ports_tried[ip_address] = set()
    elif ports_tried > 8:
        create_security_alert("Possible Port Scan", ip_address, 
                            f"Tried {ports_tried} ports", "HIGH")

def check_for_packet_flooding(ip_address):
    if ip_address not in ip_packet_counts:
        ip_packet_counts[ip_address] = 0
    
    ip_packet_counts[ip_address] = ip_packet_counts[ip_address] + 1
    
    packet_count = ip_packet_counts[ip_address]
    if packet_count > 100:
        create_security_alert("Packet Flooding Attack", ip_address, 
                            f"Sent {packet_count} packets very quickly", "CRITICAL")
        ip_packet_counts[ip_address] = 0
    elif packet_count > 50:
        create_security_alert("High Traffic Warning", ip_address, 
                            f"Sent {packet_count} packets", "HIGH")

def check_for_syn_flooding(ip_address, tcp_flags):
    if "SYN" in tcp_flags and "ACK" not in tcp_flags:
        if ip_address not in syn_packet_counts:
            syn_packet_counts[ip_address] = 0
        
        syn_packet_counts[ip_address] = syn_packet_counts[ip_address] + 1
        
        syn_count = syn_packet_counts[ip_address]
        if syn_count > 30:
            create_security_alert("SYN Flood Attack", ip_address, 
                                f"Sent {syn_count} SYN packets", "CRITICAL")
            syn_packet_counts[ip_address] = 0

def check_for_suspicious_ports(ip_address, port_number):
    port_descriptions = {
        21: "FTP File Transfer", 22: "SSH Remote Access", 23: "Telnet Remote Access", 
        25: "Email Server", 53: "DNS Server", 80: "Web Server", 135: "Windows RPC", 
        139: "Windows File Sharing", 443: "Secure Web Server", 445: "Windows Network Shares", 
        1433: "SQL Database Server", 3389: "Windows Remote Desktop"
    }
    
    if port_number in suspicious_ports:
        service_name = port_descriptions.get(port_number, f"Port {port_number}")
        if port_number in [22, 23, 3389, 445]:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        create_security_alert("Suspicious Port Access", ip_address, 
                            f"Trying to access {service_name} (port {port_number})", severity)

def get_protocol_name(protocol_number):
    if protocol_number == 1:
        return "ICMP"
    elif protocol_number == 6:
        return "TCP"
    elif protocol_number == 17:
        return "UDP"
    else:
        return f"Protocol-{protocol_number}"

def get_tcp_flags_from_packet(packet):
    if not packet.haslayer(TCP):
        return ""
    
    tcp_flags = packet[TCP].flags
    flag_names = []
    
    if tcp_flags & 0x01: flag_names.append("FIN")
    if tcp_flags & 0x02: flag_names.append("SYN")
    if tcp_flags & 0x04: flag_names.append("RST")
    if tcp_flags & 0x08: flag_names.append("PSH")
    if tcp_flags & 0x10: flag_names.append("ACK")
    if tcp_flags & 0x20: flag_names.append("URG")
    
    return ",".join(flag_names)

def process_captured_packet(packet):
    global packet_counter
    
    if packet.haslayer(IP):
        try:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            protocol_number = packet[IP].proto
            protocol_name = get_protocol_name(protocol_number)
            packet_size = len(packet)
            
            source_port = "N/A"
            destination_port = "N/A" 
            tcp_flags = ""
            
            if packet.haslayer(TCP):
                source_port = str(packet[TCP].sport)
                destination_port = str(packet[TCP].dport)
                tcp_flags = get_tcp_flags_from_packet(packet)
            elif packet.haslayer(UDP):
                source_port = str(packet[UDP].sport)
                destination_port = str(packet[UDP].dport)
            
            try:
                cursor.execute('''
                    INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, packet_size, tcp_flags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (source_ip, destination_ip, source_port, destination_port, protocol_name, packet_size, tcp_flags))
                conn.commit()
            except Exception as db_error:
                print(f"Database save error: {db_error}")
            
            packet_info = f"{source_ip}:{source_port} -> {destination_ip}:{destination_port} [{protocol_name}] {packet_size} bytes"
            if tcp_flags:
                packet_info = packet_info + f" Flags: {tcp_flags}"
            
            print(packet_info)
            
            if text_display:
                try:
                    text_display.insert(tk.END, packet_info + "\n")
                    text_display.see(tk.END)
                except:
                    pass
            
            if destination_port != "N/A":
                try:
                    dest_port_num = int(destination_port)
                    check_for_port_scanning(source_ip, dest_port_num)
                    check_for_suspicious_ports(source_ip, dest_port_num)
                except:
                    pass
            
            check_for_packet_flooding(source_ip)
            
            if tcp_flags:
                check_for_syn_flooding(source_ip, tcp_flags)
                
        except Exception as e:
            print(f"Error processing packet: {e}")

def show_network_statistics():
    try:
        print("\n" + "="*60)
        print("NETWORK TRAFFIC STATISTICS")
        print("="*60)
        
        cursor.execute('''
            SELECT src_ip, COUNT(*) as packet_count 
            FROM packets 
            GROUP BY src_ip 
            ORDER BY packet_count DESC 
            LIMIT 5
        ''')
        
        active_ips = cursor.fetchall()
        if active_ips:
            print("\nMost Active IP Addresses:")
            for ip, count in active_ips:
                print(f"  {ip} - {count} packets")
        
        cursor.execute('''
            SELECT protocol, COUNT(*) as count 
            FROM packets 
            GROUP BY protocol
        ''')
        
        protocols = cursor.fetchall()
        if protocols:
            print("\nProtocol Usage:")
            for protocol, count in protocols:
                print(f"  {protocol}: {count} packets")
        
        cursor.execute('''
            SELECT alert_type, source_ip, description, severity, timestamp
            FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT 5
        ''')
        
        recent_alerts = cursor.fetchall()
        if recent_alerts:
            print("\nRecent Security Alerts:")
            for alert_type, ip, description, severity, timestamp in recent_alerts:
                print(f"  [{severity}] {alert_type}: {ip} - {description}")
        
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"Error showing statistics: {e}")

def show_tabular_data():
    try:
        print("\n" + "="*80)
        print("RECENT ALERTS TABLE")
        print("="*80)
        
        df_alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10", conn)
        if not df_alerts.empty:
            print(df_alerts.to_string(index=False))
        else:
            print("No alerts found.")
        
        print("\n" + "="*80)
        print("RECENT PACKETS TABLE")
        print("="*80)
        
        df_packets = pd.read_sql_query("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 10", conn)
        if not df_packets.empty:
            print(df_packets.to_string(index=False))
        else:
            print("No packets found.")
            
        print("="*80 + "\n")
        
    except Exception as e:
        print(f"Error showing tabular data: {e}")

def create_monitoring_gui():
    global text_display
    
    main_window = tk.Tk()
    main_window.title("Network Security Monitor")
    main_window.geometry("900x700")
    
    title_label = tk.Label(main_window, text="Live Network Security Monitor", 
                          font=("Arial", 18, "bold"))
    title_label.pack(pady=15)
    
    text_display = scrolledtext.ScrolledText(main_window, width=110, height=40, 
                                           font=("Courier New", 10))
    text_display.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)
    
    button_frame = tk.Frame(main_window)
    button_frame.pack(pady=10)
    
    def show_stats_button_clicked():
        show_network_statistics()
    
    def clear_display_button_clicked():
        if text_display:
            text_display.delete(1.0, tk.END)
    
    def show_tables_button_clicked():
        show_tabular_data()
    
    stats_button = tk.Button(button_frame, text="Show Statistics", 
                           command=show_stats_button_clicked, font=("Arial", 12))
    stats_button.pack(side=tk.LEFT, padx=10)
    
    clear_button = tk.Button(button_frame, text="Clear Display", 
                           command=clear_display_button_clicked, font=("Arial", 12))
    clear_button.pack(side=tk.LEFT, padx=10)
    
    tables_button = tk.Button(button_frame, text="Show Tables", 
                           command=show_tables_button_clicked, font=("Arial", 12))
    tables_button.pack(side=tk.LEFT, padx=10)
    
    return main_window

def start_monitoring_with_gui():
    global packet_counter
    print("Starting Network Security Monitor with GUI...")
    
    def start_gui_thread():
        try:
            gui_window = create_monitoring_gui()
            gui_window.mainloop()
        except Exception as e:
            print(f"GUI Error: {e}")
    
    gui_thread = threading.Thread(target=start_gui_thread)
    gui_thread.daemon = True
    gui_thread.start()
    
    packet_counter = 0
    
    def packet_handler(packet):
        global packet_counter
        packet_counter = packet_counter + 1
        process_captured_packet(packet)
        
        if packet_counter % 25 == 0:
            show_network_statistics()
    
    try:
        print("GUI window should be open now!")
        print("Starting packet capture...")
        print("Press Ctrl+C to stop monitoring")
        print("-" * 50)
        
        time.sleep(3)
        
        sniff(prn=packet_handler, store=0)
        
    except KeyboardInterrupt:
        print("\n\nStopping network monitor...")
        show_network_statistics()
        show_tabular_data()
    except Exception as e:
        print(f"Error during monitoring: {e}")

def start_monitoring_console_only():
    global packet_counter
    print("Starting Network Security Monitor (Console Mode)...")
    print("Press Ctrl+C to stop monitoring")
    print("-" * 50)
    
    packet_counter = 0
    
    def packet_handler(packet):
        global packet_counter
        packet_counter = packet_counter + 1
        process_captured_packet(packet)
        
        if packet_counter % 20 == 0:
            show_network_statistics()
    
    try:
        sniff(prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n\nStopping network monitor...")
        show_network_statistics()
        show_tabular_data()
    except Exception as e:
        print(f"Error during monitoring: {e}")

if __name__ == "__main__":
    print("Network Security Monitor")
    print("========================")
    print("This program monitors network traffic and detects suspicious activity.")
    print()
    
    print("How would you like to run this program?")
    print("1 - Console only (text mode)")
    print("2 - With GUI window (graphical mode)")
    print()
    user_choice = input("Please enter 1 or 2: ")
    
    try:
        if user_choice == "2":
            start_monitoring_with_gui()
        else:
            start_monitoring_console_only()
            
    except Exception as main_error:
        print(f"Program error: {main_error}")
        
    finally:
        try:
            conn.close()
            print("Database connection closed.")
        except:
            pass
        print("Program finished. Goodbye!")