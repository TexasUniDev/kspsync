import socket
import threading
import os
import time
import json
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import configparser
import appdirs
import struct
import subprocess
import zipfile

# Configuration
APP_NAME = "KSP_Sync"
CONFIG_DIR = appdirs.user_data_dir(APP_NAME)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.ini")
UDP_PORT = 5005
TCP_PORT = 5006
BROADCAST_INTERVAL = 10  # seconds
CHUNK_SIZE = 4096  # bytes for file transfer

# Ensure config directory exists
os.makedirs(CONFIG_DIR, exist_ok=True)

class KSPSync:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("KSP Sync")
        self.ksp_dir = self.load_config()
        self.local_ip = self.get_local_ip()
        self.peers = set()
        self.running = True
        self.sync_dirs = []  # List to store directories selected for syncing

        # GUI Setup
        self.setup_gui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Configure firewall rules
        self.configure_firewall()

        # Network Setup
        self.start_networking()

    def load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE)
            return config.get("Settings", "ksp_dir", fallback=None)
        return self.prompt_ksp_directory()

    def save_config(self, ksp_dir):
        config = configparser.ConfigParser()
        config["Settings"] = {"ksp_dir": ksp_dir}
        with open(CONFIG_FILE, "w") as f:
            config.write(f)

    def prompt_ksp_directory(self):
        ksp_dir = filedialog.askdirectory(title="Select KSP Directory")
        if ksp_dir:
            self.save_config(ksp_dir)
            return ksp_dir
        else:
            self.log("No KSP directory selected. Exiting.")
            self.root.quit()
            return None

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def setup_gui(self):
        tk.Label(self.root, text="KSP Directory:").pack()
        self.dir_label = tk.Label(self.root, text=self.ksp_dir or "Not set")
        self.dir_label.pack()
        tk.Button(self.root, text="Change Directory", command=self.change_dir).pack()
        tk.Button(self.root, text="Select Directories to Sync", command=self.select_directories).pack()
        self.log_text = scrolledtext.ScrolledText(self.root, width=60, height=20)
        self.log_text.pack()
        self.status_label = tk.Label(self.root, text="Status: Idle")
        self.status_label.pack()
        self.progress = ttk.Progressbar(self.root, length=300, mode='determinate')
        self.progress.pack()
        self.progress_label = tk.Label(self.root, text="")
        self.progress_label.pack()
        self.progress.pack_forget()  # Hide initially
        self.progress_label.pack_forget()

    def select_directories(self):
        """Prompt the user to select directories to sync."""
        dirs = [d for d in os.listdir(self.ksp_dir) if os.path.isdir(os.path.join(self.ksp_dir, d))]
        if not dirs:
            self.log("No directories found in KSP directory.")
            return

        select_window = tk.Toplevel(self.root)
        select_window.title("Select Directories to Sync")

        listbox = tk.Listbox(select_window, selectmode=tk.MULTIPLE)
        for dir in dirs:
            listbox.insert(tk.END, dir)
        listbox.pack()

        def confirm_selection():
            selected_indices = listbox.curselection()
            self.sync_dirs = [dirs[i] for i in selected_indices]
            self.log(f"Selected directories to sync: {', '.join(self.sync_dirs)}")
            select_window.destroy()

        tk.Button(select_window, text="Confirm", command=confirm_selection).pack()

    def change_dir(self):
        new_dir = filedialog.askdirectory(title="Select KSP Directory")
        if new_dir:
            self.ksp_dir = new_dir
            self.dir_label.config(text=new_dir)
            self.save_config(new_dir)
            self.log(f"KSP directory changed to: {new_dir}")

    def log(self, message):
        self.log_text.insert(tk.END, f"{time.ctime()}: {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def configure_firewall(self):
        try:
            if not self.firewall_rule_exists("KSP_Sync_UDP_5005"):
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", "name=KSP_Sync_UDP_5005",
                     "dir=in", "action=allow", "protocol=UDP", "localport=5005"],
                    check=True, capture_output=True, text=True
                )
                self.log("Added firewall rule for UDP port 5005")
            else:
                self.log("Firewall rule for UDP port 5005 already exists")

            if not self.firewall_rule_exists("KSP_Sync_TCP_5006"):
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", "name=KSP_Sync_TCP_5006",
                     "dir=in", "action=allow", "protocol=TCP", "localport=5006"],
                    check=True, capture_output=True, text=True
                )
                self.log("Added firewall rule for TCP port 5006")
            else:
                self.log("Firewall rule for TCP port 5006 already exists")
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to configure firewall: {e.stderr}")
            self.log("Run the program as administrator to configure firewall rules.")
        except Exception as e:
            self.log(f"Unexpected error configuring firewall: {e}")

    def firewall_rule_exists(self, rule_name):
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                capture_output=True, text=True
            )
            return "No rules match" not in result.stdout
        except subprocess.CalledProcessError:
            return False

    def start_networking(self):
        if not self.ksp_dir:
            return
        threading.Thread(target=self.udp_broadcast, daemon=True).start()
        threading.Thread(target=self.udp_listen, daemon=True).start()
        threading.Thread(target=self.tcp_server, daemon=True).start()

    def udp_broadcast(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        message = f"KSP_SYNC_DISCOVERY|{self.local_ip}".encode()
        while self.running:
            s.sendto(message, ("255.255.255.255", UDP_PORT))
            time.sleep(BROADCAST_INTERVAL)
        s.close()

    def udp_listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("", UDP_PORT))
        while self.running:
            data, addr = s.recvfrom(1024)
            message = data.decode()
            if message.startswith("KSP_SYNC_DISCOVERY|"):
                peer_ip = message.split("|")[1]
                if peer_ip != self.local_ip and peer_ip not in self.peers:
                    self_ip_tuple = tuple(map(int, self.local_ip.split('.')))
                    peer_ip_tuple = tuple(map(int, peer_ip.split('.')))
                    if self_ip_tuple > peer_ip_tuple:
                        threading.Thread(target=self.connect_to_peer, args=(peer_ip,), daemon=True).start()
        s.close()

    def tcp_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", TCP_PORT))
        s.listen(5)
        while self.running:
            conn, addr = s.accept()
            threading.Thread(target=self.handle_connection, args=(conn, addr, True), daemon=True).start()
        s.close()

    def connect_to_peer(self, peer_ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((peer_ip, TCP_PORT))
            self.peers.add(peer_ip)
            self.handle_connection(s, (peer_ip, TCP_PORT), False)
        except Exception as e:
            self.log(f"Failed to connect to {peer_ip}: {e}")

    def handle_connection(self, conn, addr, is_server):
        self.log(f"Connected to {addr[0]}")
        self.status_label.config(text=f"Status: Syncing with {addr[0]}")
        try:
            if is_server:
                self.sync_as_server(conn)
            else:
                self.sync_as_client(conn)
            self.log(f"Sync completed with {addr[0]}")
        except Exception as e:
            self.log(f"Sync error with {addr[0]}: {e}")
        finally:
            conn.close()
            self.peers.discard(addr[0])
            self.status_label.config(text="Status: Idle")
            self.log(f"Disconnected from {addr[0]}")
            self.hide_progress()

    def get_dir_list(self):
        """Get a list of selected directories with their latest modification times."""
        dir_list = {}
        for dir in self.sync_dirs:
            dir_path = os.path.join(self.ksp_dir, dir)
            if os.path.exists(dir_path):
                latest_mtime = 0
                for root, _, files in os.walk(dir_path):
                    for file in files:
                        path = os.path.join(root, file)
                        mtime = os.stat(path).st_mtime
                        if mtime > latest_mtime:
                            latest_mtime = mtime
                dir_list[dir] = latest_mtime
        return dir_list

    def send_message(self, conn, message):
        if isinstance(message, str):
            message = message.encode()
        length = len(message)
        conn.send(struct.pack(">I", length))
        conn.send(message)

    def recv_message(self, conn):
        try:
            length_data = conn.recv(4)
            if len(length_data) < 4:
                return None
            length = struct.unpack(">I", length_data)[0]
            data = b""
            while len(data) < length:
                chunk = conn.recv(min(4096, length - len(data)))
                if not chunk:
                    break
                data += chunk
            if len(data) < length:
                raise ValueError("Incomplete message received")
            return data.decode()
        except Exception as e:
            self.log(f"Error receiving message: {e}")
            return None

    def show_progress(self, action, filename):
        self.progress.pack()
        self.progress_label.pack()
        self.progress_label.config(text=f"{action} {filename}")
        self.progress['value'] = 0
        self.root.update_idletasks()

    def update_progress(self, current, total):
        percentage = (current / total) * 100
        self.progress['value'] = percentage
        self.root.update_idletasks()

    def hide_progress(self):
        self.progress.pack_forget()
        self.progress_label.pack_forget()
        self.root.update_idletasks()

    def sync_as_client(self, conn):
        """Client sends its directory list and handles transfers."""
        if not self.sync_dirs:
            self.log("No directories selected for sync. Please select directories.")
            return
        dir_list = self.get_dir_list()
        self.send_message(conn, f"DIR_LIST|{json.dumps(dir_list)}")
        self.handle_file_transfers(conn)

    def sync_as_server(self, conn):
        """Server receives client directory list, compares, and syncs."""
        data = self.recv_message(conn)
        if data and data.startswith("DIR_LIST|"):
            client_dirs = json.loads(data.split("|", 1)[1])
            server_dirs = self.get_dir_list()
            self.log("Comparing directory lists with client")
            for dir, client_mtime in client_dirs.items():
                if dir not in server_dirs:
                    self.log(f"Requesting {dir} from client (missing locally)")
                    self.send_message(conn, f"REQUEST_DIR_ZIP|{dir}")
                elif server_dirs[dir] < client_mtime:
                    self.log(f"Requesting {dir} from client (client has newer version)")
                    self.send_message(conn, f"REQUEST_DIR_ZIP|{dir}")
                elif server_dirs[dir] > client_mtime:
                    self.log(f"Sending {dir} to client (server has newer version)")
                    self.send_dir_zip(conn, dir)
            for dir in server_dirs:
                if dir not in client_dirs:
                    self.log(f"Sending {dir} to client (missing on client)")
                    self.send_dir_zip(conn, dir)
        self.handle_file_transfers(conn)

    def create_dir_zip(self, dir, zip_path):
        """Create a zip file of the specified directory."""
        dir_path = os.path.join(self.ksp_dir, dir)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.ksp_dir)
                    zipf.write(file_path, arcname)

    def send_dir_zip(self, conn, dir):
        """Send a zipped directory to the peer."""
        zip_path = os.path.join(self.ksp_dir, f"{dir}.zip")
        self.create_dir_zip(dir, zip_path)
        size = os.path.getsize(zip_path)
        self.send_message(conn, f"SEND_DIR_ZIP|{dir}|{size}")
        self.show_progress("Sending", f"{dir}.zip")
        start_time = time.time()
        bytes_sent = 0
        with open(zip_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                conn.send(chunk)
                bytes_sent += len(chunk)
                self.root.after(0, self.update_progress, bytes_sent, size)
        elapsed_time = time.time() - start_time
        speed_mbps = (bytes_sent * 8 / 1024 / 1024) / elapsed_time if elapsed_time > 0 else 0
        self.log(f"Sent {dir}.zip ({size} bytes) at {speed_mbps:.2f} Mbps")
        os.remove(zip_path)
        self.hide_progress()

    def receive_dir_zip(self, conn, dir, size):
        """Receive and extract a zipped directory from the peer."""
        zip_path = os.path.join(self.ksp_dir, f"{dir}.zip")
        self.show_progress("Receiving", f"{dir}.zip")
        start_time = time.time()
        bytes_received = 0
        with open(zip_path, "wb") as f:
            received = 0
            while received < size:
                chunk = conn.recv(min(CHUNK_SIZE, size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
                bytes_received += len(chunk)
                self.root.after(0, self.update_progress, bytes_received, size)
        elapsed_time = time.time() - start_time
        speed_mbps = (bytes_received * 8 / 1024 / 1024) / elapsed_time if elapsed_time > 0 else 0
        self.log(f"Received {dir}.zip ({size} bytes) at {speed_mbps:.2f} Mbps")
        self.extract_dir_zip(dir, zip_path)
        os.remove(zip_path)
        self.hide_progress()

    def extract_dir_zip(self, dir, zip_path):
        """Extract the received zip file into the KSP directory."""
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(self.ksp_dir)

    def handle_file_transfers(self, conn):
        """Handle sending and receiving of directory zip files."""
        while self.running:
            data = self.recv_message(conn)
            if not data:
                break
            parts = data.split("|", 2)
            command = parts[0]
            if command == "SEND_DIR_ZIP":
                dir, size = parts[1], int(parts[2])
                self.receive_dir_zip(conn, dir, size)
            elif command == "REQUEST_DIR_ZIP":
                dir = parts[1]
                self.log(f"Client requested {dir}.zip")
                self.send_dir_zip(conn, dir)

    def on_closing(self):
        self.running = False
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = KSPSync()
    app.run()
