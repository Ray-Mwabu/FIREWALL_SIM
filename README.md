# Firewall Simulator – Cross-Platform GUI

---

## **Project Overview**

The **Firewall Simulator** is a **cross-platform Python application** that simulates firewall behavior:

- Monitors active network connections in real-time.
- Applies **user-defined rules** to allow or block connections.
- Provides an **interactive GUI dashboard** for monitoring, filtering, and managing rules.
- Sends **system notifications** for blocked connections.

---

## **🎯 Key Features**

| Feature | Description |
|---------|-------------|
| **Rule-Based Filtering** | Block or allow connections by IP, port, protocol. |
| **Real-Time Monitoring** | Shows all active connections with PID, IP, port, protocol, status. |
| **System Notifications** | Alerts when a connection is blocked. |
| **GUI Dashboard** | Add/remove rules, filter/search connections, color-coded protocols. |
| **Logging** | Save all connection attempts to `firewall_logs.txt`. |
| **Export/Import Rules** | Save/load firewall rules in JSON format. |

---


The application comes with a **full-featured GUI**:

1. **Dashboard** – Displays all current network connections in real-time, color-coded by protocol and blocked status.  
2. **Add/Remove Rules** – Manage rules for blocking or allowing connections with IP, port, and protocol.  
3. **Notifications** – Receives system notifications for blocked connections.  
4. **Filter/Search** – Quickly filter connections by IP, PID, or protocol.  

## **⚙️ Tech Stack**

- **Language:** Python 3  
- **Libraries:**  
  - `psutil` → Network connections and process info  
  - `tkinter` → GUI dashboard  
  - `plyer` → Cross-platform notifications  
  - `json` → Save/load firewall rules  

---

## **🚀 How to Run**

### **1. Install Dependencies**
```bash
pip install psutil plyer

For Linux notifications, also install dbus:

sudo apt install python3-dbus

2. Run the Simulator

python firewall_sim.py

3. Compile to Executable (Optional)

pip install pyinstaller
pyinstaller --onefile --windowed firewall_sim.py

    The executable will appear in the dist/ folder.

    Launch it to run without a terminal window.

📂 File Structure

Firewall-Simulator/
├── firewall_sim.py         # Main application script
├── firewall_rules.json     # Optional: saved firewall rules
├── firewall_logs.txt       # Connection logs
└── README.md              # This README

💡 Notes

    Detection is simulation-only; does not modify the system firewall.

    Supports cross-platform notifications (Windows, Linux, macOS).

    GUI highlights blocked connections in red, TCP in blue, UDP in orange.

    Filter/search allows quick access to specific connections.

    Rules can be exported/imported for backup or sharing.

🔗 References

    psutil Documentation

tkinter Documentation

plyer Documentation
