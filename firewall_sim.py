import psutil
import json
import time
from datetime import datetime
import threading
import socket
import tkinter as tk
from tkinter import ttk, messagebox
from plyer import notification

# ------------------------------
# Global variables and files
# ------------------------------
RULES_FILE = "firewall_rules.json"
LOG_FILE = "firewall_logs.txt"

try:
    with open(RULES_FILE, "r") as f:
        firewall_rules = json.load(f)
except FileNotFoundError:
    firewall_rules = []

# ------------------------------
# Helper functions
# ------------------------------
def save_rules():
    with open(RULES_FILE, "w") as f:
        json.dump(firewall_rules, f, indent=4)

def log_action(action, conn_info):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | {action} | {conn_info}\n")

def notify_block(conn_info):
    notification.notify(
        title="Firewall Simulator Alert",
        message=f"Blocked connection from {conn_info['raddr']} (PID {conn_info['pid']})",
        timeout=5
    )

def check_connection(conn):
    """Check connection against firewall rules"""
    action = "ALLOW"
    for rule in firewall_rules:
        ip_match = rule["ip"] == "ANY" or (conn.raddr and conn.raddr.ip == rule["ip"])
        port_match = rule["port"] == "ANY" or (conn.raddr and conn.raddr.port == int(rule["port"]))
        proto_match = rule["protocol"].upper() == "ANY" or rule["protocol"].upper() == ("TCP" if conn.type == psutil.SOCK_STREAM else "UDP")
        if ip_match and port_match and proto_match:
            action = rule["action"].upper()
            break
    return action

def scan_connections():
    conns = psutil.net_connections(kind='inet')
    results = []
    for c in conns:
        action = check_connection(c)
        conn_info = {
            "pid": c.pid,
            "laddr": f"{c.laddr.ip}:{c.laddr.port}",
            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A",
            "status": action,
            "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        }
        results.append(conn_info)
        log_action(action, conn_info)
    return results

# ------------------------------
# GUI Class
# ------------------------------
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Simulator")
        self.root.geometry("1000x600")

        # --------------------------
        # Rules Frame
        # --------------------------
        rules_frame = tk.Frame(root)
        rules_frame.pack(side="top", fill="x", padx=10, pady=5)
        tk.Button(rules_frame, text="Add Rule", command=self.add_rule).pack(side="left", padx=5)
        tk.Button(rules_frame, text="Remove Rule", command=self.remove_rule).pack(side="left", padx=5)
        tk.Button(rules_frame, text="Save Rules", command=save_rules).pack(side="left", padx=5)
        tk.Button(rules_frame, text="Export Rules", command=self.export_rules).pack(side="left", padx=5)
        tk.Button(rules_frame, text="Import Rules", command=self.import_rules).pack(side="left", padx=5)

        # --------------------------
        # Search Frame
        # --------------------------
        search_frame = tk.Frame(root)
        search_frame.pack(side="top", fill="x", padx=10, pady=5)
        tk.Label(search_frame, text="Search:").pack(side="left")
        self.search_entry = tk.Entry(search_frame)
        self.search_entry.pack(side="left", padx=5)
        tk.Button(search_frame, text="Filter", command=self.filter_table).pack(side="left", padx=5)
        tk.Button(search_frame, text="Reset", command=self.reset_table).pack(side="left", padx=5)

        # --------------------------
        # Connections Table
        # --------------------------
        table_frame = tk.Frame(root)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.tree = ttk.Treeview(table_frame, columns=("PID","Local","Remote","Protocol","Status"), show="headings")
        for col in ("PID","Local","Remote","Protocol","Status"):
            self.tree.heading(col,text=col)
            self.tree.column(col, width=150)
        self.tree.pack(fill="both", expand=True)
        scrollbar = tk.Scrollbar(table_frame, command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # --------------------------
        # Start monitoring
        # --------------------------
        self.running = True
        self.seen_blocked = set()
        threading.Thread(target=self.monitor_connections, daemon=True).start()

    # --------------------------
    # Rule management
    # --------------------------
    def add_rule(self):
        popup = tk.Toplevel(self.root)
        popup.title("Add Rule")
        tk.Label(popup, text="IP (or ANY)").grid(row=0,column=0)
        ip_entry = tk.Entry(popup)
        ip_entry.grid(row=0,column=1)
        tk.Label(popup, text="Port (or ANY)").grid(row=1,column=0)
        port_entry = tk.Entry(popup)
        port_entry.grid(row=1,column=1)
        tk.Label(popup, text="Protocol (TCP/UDP/ANY)").grid(row=2,column=0)
        proto_entry = tk.Entry(popup)
        proto_entry.grid(row=2,column=1)
        tk.Label(popup, text="Action (ALLOW/BLOCK)").grid(row=3,column=0)
        action_entry = tk.Entry(popup)
        action_entry.grid(row=3,column=1)
        def save_rule():
            rule = {
                "ip": ip_entry.get().upper(),
                "port": port_entry.get().upper(),
                "protocol": proto_entry.get().upper(),
                "action": action_entry.get().upper()
            }
            firewall_rules.append(rule)
            popup.destroy()
        tk.Button(popup, text="Add", command=save_rule).grid(row=4,column=0,columnspan=2)

    def remove_rule(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Info","No row selected.")
            return

        # Get values of the selected row
        item = self.tree.item(selected[0])
        values = item["values"]  # This returns [PID, Local, Remote, Protocol, Status]

        # Find matching rule in firewall_rules and remove it
        removed = False
        for rule in firewall_rules:
            ip_match = rule["ip"] in values[2] or rule["ip"] == "ANY"
            proto_match = rule["protocol"].upper() == values[3].upper() or rule["protocol"].upper() == "ANY"
            if ip_match and proto_match:
                firewall_rules.remove(rule)
                removed = True
                break

        if removed:
            messagebox.showinfo("Removed", "Rule removed successfully.")
        else:
            messagebox.showwarning("Not found", "Selected rule not found in firewall rules.")


    def export_rules(self):
        try:
            with open("firewall_rules.json", "w") as f:
                json.dump(firewall_rules, f, indent=4)
            messagebox.showinfo("Export", "Rules exported successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export rules: {e}")

    def import_rules(self):
        try:
            global firewall_rules
            with open("firewall_rules.json", "r") as f:
                firewall_rules = json.load(f)
            messagebox.showinfo("Import", "Rules imported successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {e}")

    # --------------------------
    # Filter / Reset Table
    # --------------------------
    def filter_table(self):
        keyword = self.search_entry.get().lower()
        self.tree.delete(*self.tree.get_children())
        conns = scan_connections()
        for c in conns:
            if keyword in str(c.values()).lower():
                self.insert_connection(c)

    def reset_table(self):
        self.search_entry.delete(0, tk.END)

    # --------------------------
    # Insert row with color
    # --------------------------
    def insert_connection(self, c):
        self.tree.insert("",tk.END,values=(c["pid"],c["laddr"],c["raddr"],c["protocol"],c["status"]))
        tags = []
        if c["status"]=="BLOCK":
            tags.append("blocked")
        if c["protocol"]=="TCP":
            tags.append("TCP")
        if c["protocol"]=="UDP":
            tags.append("UDP")
        self.tree.item(self.tree.get_children()[-1], tags=tags)
        self.tree.tag_configure("blocked", foreground="red")
        self.tree.tag_configure("TCP", foreground="blue")
        self.tree.tag_configure("UDP", foreground="orange")

    # --------------------------
    # Monitor connections
    # --------------------------
    def monitor_connections(self):
        while self.running:
            self.tree.delete(*self.tree.get_children())
            conns = scan_connections()
            for c in conns:
                self.insert_connection(c)
                if c["status"]=="BLOCK" and c["raddr"] not in self.seen_blocked:
                    notify_block(c)
                    self.seen_blocked.add(c["raddr"])
            time.sleep(2)

# ------------------------------
# Main
# ------------------------------
if __name__=="__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()

