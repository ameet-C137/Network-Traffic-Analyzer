import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
import time
import requests

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("1200x600")
        self.root.configure(bg="#3A5F8E")

        self.create_widgets()
        self.capture_running = False
        self.interface = "Wi-Fi"

        self.packet_details = []
        self.protocols = {80: "HTTP", 443: "HTTPS", 53: "DNS"}

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        title_label = tk.Label(self.root, text="Network Traffic Analyzer", bg="#2F4B7C", fg="#FFFFFF",
                               font=("Helvetica", 24, "bold italic"))
        title_label.pack(fill=tk.X, pady=20)

        interface_frame = tk.Frame(self.root, bg="#3A5F8E")
        interface_frame.pack(pady=10)

        tk.Label(interface_frame, text="Select Interface:", bg="#3A5F8E", fg="#FFFFFF", font=("Arial", 12)).pack(
            side=tk.LEFT, padx=5)

        self.interface_var = tk.StringVar(value="Wi-Fi")
        self.interface_menu = ttk.Combobox(interface_frame, textvariable=self.interface_var, state="readonly",
                                           font=("Arial", 10))
        self.interface_menu['values'] = ["Wi-Fi", "Ethernet", "lo"]  # Add more interfaces as needed
        self.interface_menu.pack(side=tk.LEFT, padx=5)

        button_frame = tk.Frame(self.root, bg="#3A5F8E")
        button_frame.pack(pady=10)

        self.start_button = tk.Button(
            button_frame, text="Start Capture", command=self.start_capture, bg="#61afef", fg="#282c34",
            font=("Arial", 12, "bold"))
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(
            button_frame, text="Stop Capture", command=self.stop_capture, bg="#e06c75", fg="#282c34",
            font=("Arial", 12, "bold"))
        self.stop_button.pack(side=tk.LEFT, padx=10)

        self.save_log_button = tk.Button(
            button_frame, text="Save Log", command=self.save_log, bg="#98c379", fg="#282c34",
            font=("Arial", 12, "bold"))
        self.save_log_button.pack(side=tk.LEFT, padx=10)

        table_frame = tk.Frame(self.root)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ("Number", "Time", "Source", "Destination", "Protocol", "Geolocation", "Info")
        self.packet_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)

        self.packet_table.heading("Number", text="Number", anchor=tk.W)
        self.packet_table.heading("Time", text="Time", anchor=tk.W)
        self.packet_table.heading("Source", text="Source", anchor=tk.W)
        self.packet_table.heading("Destination", text="Destination", anchor=tk.W)
        self.packet_table.heading("Protocol", text="Protocol", anchor=tk.W)
        self.packet_table.heading("Geolocation", text="Geolocation", anchor=tk.W)
        self.packet_table.heading("Info", text="Info", anchor=tk.W)

        self.packet_table.column("Number", width=50, anchor=tk.W)
        self.packet_table.column("Time", width=80, anchor=tk.W)
        self.packet_table.column("Source", width=150, anchor=tk.W)
        self.packet_table.column("Destination", width=150, anchor=tk.W)
        self.packet_table.column("Protocol", width=100, anchor=tk.W)
        self.packet_table.column("Geolocation", width=200, anchor=tk.W)
        self.packet_table.column("Info", width=400, anchor=tk.W)

        self.packet_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = tk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.packet_table.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_table.configure(yscrollcommand=self.scrollbar.set)

        self.packet_table.bind("<ButtonRelease-1>", self.on_packet_click)

        log_frame = tk.Frame(self.root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_text = scrolledtext.ScrolledText(log_frame, bg="#3A5F8E", fg="#FFFFFF", font=("Arial", 10))
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        suspicious_frame = tk.Frame(log_frame, bg="#3A5F8E", width=300)
        suspicious_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

        self.suspicious_text = scrolledtext.ScrolledText(suspicious_frame, bg="#3A5F8E", fg="#FF6347", font=("Arial", 10))
        self.suspicious_text.pack(fill=tk.BOTH, expand=True)
        self.suspicious_text.insert(tk.END, "Suspicious Traffic Log:\n")

    def start_capture(self):
        if not self.capture_running:
            self.interface = self.interface_var.get()
            self.capture_running = True
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.start()
            self.log("Capture started on interface: {}.".format(self.interface))
        else:
            self.log("Capture is already running.")

    def stop_capture(self):
        if self.capture_running:
            self.capture_running = False
            self.log("Stopping capture...")
            time.sleep(1)
            if self.capture_thread.is_alive():
                self.capture_thread.join()
            self.log("Capture stopped.")
        else:
            self.log("Capture is not running.")

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.yview(tk.END)
        print(message)

    def capture_packets(self):
        try:
            sniff(prn=self.packet_callback, stop_filter=self.stop_capture_condition, iface=self.interface)
        except Exception as e:
            self.log(f"Error: {str(e)}")
            self.capture_running = False

    def stop_capture_condition(self, packet):
        return not self.capture_running

    def packet_callback(self, packet):
        if IP in packet:
            timestamp = time.time()
            packet_info = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": None,
                "geolocation": self.get_geolocation(packet[IP].dst),
                "info": self.format_packet_details(packet),
                "timestamp": timestamp
            }
            time_str = self.get_time()

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                packet_info["protocol"] = self.protocols.get(dst_port, "TCP")
                packet_info["info"] = f"TCP Packet: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}"

            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                packet_info["protocol"] = "UDP"
                packet_info["info"] = f"UDP Packet: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}"

                if dst_port == 53 or src_port == 53:
                    packet_info["protocol"] = "DNS"
                    packet_info["info"] = f"DNS Traffic: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}"

            self.packet_details.append(packet_info)
            self.packet_table.insert("", tk.END, values=(
                len(self.packet_details), time_str, packet_info["src_ip"], packet_info["dst_ip"], packet_info["protocol"],
                packet_info["geolocation"], packet_info["info"]))

            if self.detect_suspicious_activity(packet):
                self.suspicious_text.insert(tk.END, packet_info["info"] + "\n")
                self.suspicious_text.yview(tk.END)

    def detect_suspicious_activity(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = None

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = self.protocols.get(dst_port, "TCP")
                if protocol == "TCP" and (dst_port in [22, 80]):
                    return True

            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                if dst_port == 53:
                    return True

        return False

    def get_geolocation(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            if data.get("status") == "fail":
                return "Geolocation error"
            return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
        except Exception as e:
            return "Geolocation error"

    def get_time(self):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def format_packet_details(self, packet):
        details = ""
        if IP in packet:
            details += f"Source: {packet[IP].src}\n"
            details += f"Destination: {packet[IP].dst}\n"
            if TCP in packet:
                details += f"Source Port: {packet[TCP].sport}\n"
                details += f"Destination Port: {packet[TCP].dport}\n"
            elif UDP in packet:
                details += f"Source Port: {packet[UDP].sport}\n"
                details += f"Destination Port: {packet[UDP].dport}\n"
            if Raw in packet:
                details += f"Data: {packet[Raw].load}\n"
        return details

    def on_packet_click(self, event):
        selected_item = self.packet_table.selection()
        if selected_item:
            packet_index = int(self.packet_table.item(selected_item)["values"][0]) - 1
            if 0 <= packet_index < len(self.packet_details):
                packet_info = self.packet_details[packet_index]
                details = f"Packet Number: {packet_index + 1}\n" \
                          f"Time: {self.get_time()}\n" \
                          f"Source IP: {packet_info['src_ip']}\n" \
                          f"Destination IP: {packet_info['dst_ip']}\n" \
                          f"Protocol: {packet_info['protocol']}\n" \
                          f"Geolocation: {packet_info['geolocation']}\n" \
                          f"Info:\n{packet_info['info']}"
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, details)

    def save_log(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                for packet_info in self.packet_details:
                    file.write(f"Number: {len(self.packet_details)}\n")
                    file.write(f"Time: {self.get_time()}\n")
                    file.write(f"Source IP: {packet_info['src_ip']}\n")
                    file.write(f"Destination IP: {packet_info['dst_ip']}\n")
                    file.write(f"Protocol: {packet_info['protocol']}\n")
                    file.write(f"Geolocation: {packet_info['geolocation']}\n")
                    file.write(f"Info: {packet_info['info']}\n")
                    file.write("="*40 + "\n")

    def on_closing(self):
        if self.capture_running:
            self.stop_capture()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    root.mainloop()
