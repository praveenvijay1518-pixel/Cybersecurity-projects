#!/usr/bin/env python3
"""
monitor_gui_dark.py
Advanced Dark-mode Suspicious Process Detector Dashboard
- Requires: psutil, matplotlib, pillow
- Logo image included (update path if needed)
"""

import psutil
import time
import threading
import csv
import os
from datetime import datetime
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from PIL import Image, ImageTk

# -------------------------
# CONFIG
# -------------------------
CPU_THRESHOLD = 70.0          # % CPU considered high
MEM_THRESHOLD_MB = 300.0      # MB considered high
GRAPH_LENGTH = 30             # number of samples to keep in graph
REFRESH_INTERVAL_MS = 1000    # UI graph update interval
PROCESS_POLL_INTERVAL = 1.0   # seconds (in monitor thread)

# Path to uploaded logo image (from your environment)
LOGO_PATH = "/mnt/data/c94e200f-53fe-4cc2-97be-eb5aff5f4a5f.png"

# -------------------------
# UTILITIES
# -------------------------
def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_get_name(p):
    try:
        return p.info.get("name") or str(p.pid)
    except Exception:
        return str(p.pid)

# -------------------------
# MAIN GUI CLASS
# -------------------------
class DarkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Suspicious Process Detector")
        self.root.geometry("1200x780")
        self.root.configure(bg="#0b0f12")  # deep charcoal background

        # state
        self.monitoring = False
        self.cpu_history = []
        self.ram_history = []
        self.process_data = {}  # pid -> last (cpu, mem)
        self.alert_log = []     # list of alert dicts

        # styles
        self.setup_styles()

        # layout
        self.build_header()
        self.build_graphs()
        self.build_controls()
        self.build_table()
        self.build_alerts_panel()

        # initial graph updater
        self.root.after(REFRESH_INTERVAL_MS, self.update_graphs)

    # -------------------------
    # UI STYLING
    # -------------------------
    def setup_styles(self):
        style = ttk.Style()
        # Use default theme then tweak
        style.theme_use('clam')

        # Treeview style - dark
        style.configure("Dark.Treeview",
                        background="#0b0f12",
                        fieldbackground="#0b0f12",
                        foreground="#d6e6f0",
                        rowheight=26,
                        font=('Segoe UI', 10))
        style.map("Dark.Treeview", background=[('selected', '#1b8bff')], foreground=[('selected', 'white')])

        # Heading style
        style.configure("Dark.Treeview.Heading",
                        background="#111417",
                        foreground="#bfe9ff",
                        font=('Segoe UI Semibold', 10))

        # Buttons
        style.configure("Dark.TButton",
                        background="#121416",
                        foreground="white",
                        padding=6,
                        relief="flat",
                        font=('Segoe UI', 10, 'bold'))

    # -------------------------
    # HEADER (LOGO + TITLE)
    # -------------------------
    def build_header(self):
        header = Frame(self.root, bg="#0b0f12", pady=8)
        header.pack(fill=X)

        # logo (if available)
        logo_frame = Frame(header, bg="#0b0f12")
        logo_frame.pack(side=LEFT, padx=(12,6))
        try:
            img = Image.open(LOGO_PATH)
            img.thumbnail((72,72), Image.LANCZOS)
            self.logo_img = ImageTk.PhotoImage(img)
            Label(logo_frame, image=self.logo_img, bg="#0b0f12").pack()
        except Exception:
            # fallback icon
            Label(logo_frame, text="🛡️", bg="#0b0f12", font=("Segoe UI", 28)).pack()

        # title
        title_frame = Frame(header, bg="#0b0f12")
        title_frame.pack(side=LEFT, padx=8)
        Label(title_frame, text="Advanced Suspicious Process Detector",
              bg="#0b0f12", fg="#e6f7ff", font=("Segoe UI", 20, "bold")).pack(anchor=W)
        Label(title_frame, text="Dark mode • Neon CPU & RAM • Task-manager style",
              bg="#0b0f12", fg="#9fbfdc", font=("Segoe UI", 10)).pack(anchor=W)

    # -------------------------
    # GRAPHS (Matplotlib)
    # -------------------------
    def build_graphs(self):
        graph_holder = Frame(self.root, bg="#0b0f12")
        graph_holder.pack(fill=X, padx=12, pady=(6,4))

        fig = Figure(figsize=(9.8,2.6), dpi=100)
        self.ax_cpu = fig.add_subplot(121)
        self.ax_ram = fig.add_subplot(122)

        # initial styling
        for ax in (self.ax_cpu, self.ax_ram):
            ax.set_facecolor("#0b0f12")
            ax.tick_params(colors="#9fbfdc")
            for spine in ax.spines.values():
                spine.set_color("#233445")

        self.ax_cpu.set_title("CPU Usage (%)", color="#bfffbf")
        self.ax_ram.set_title("RAM Usage (%)", color="#bdf0ff")

        self.cpu_line, = self.ax_cpu.plot([], linewidth=2.8)
        self.ram_line, = self.ax_ram.plot([], linewidth=2.8)

        # neon color config
        self.cpu_color = "#39ff14"  # neon green
        self.ram_color = "#40c4ff"  # neon blue

        self.cpu_line.set_color(self.cpu_color)
        self.ram_line.set_color(self.ram_color)

        self.ax_cpu.set_ylim(0, 100)
        self.ax_ram.set_ylim(0, 100)

        self.canvas = FigureCanvasTkAgg(fig, master=graph_holder)
        self.canvas.get_tk_widget().pack(fill=X)

    def update_graphs(self):
        # gather aggregated system metrics
        try:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
        except Exception:
            cpu, ram = 0.0, 0.0

        self.cpu_history.append(cpu)
        self.ram_history.append(ram)
        self.cpu_history = self.cpu_history[-GRAPH_LENGTH:]
        self.ram_history = self.ram_history[-GRAPH_LENGTH:]

        # update plots
        self.ax_cpu.clear()
        self.ax_ram.clear()

        # redraw axes styling
        for ax in (self.ax_cpu, self.ax_ram):
            ax.set_facecolor("#0b0f12")
            ax.tick_params(colors="#9fbfdc")
            for spine in ax.spines.values():
                spine.set_color("#233445")

        self.ax_cpu.plot(self.cpu_history, color=self.cpu_color, linewidth=2.6)
        self.ax_ram.plot(self.ram_history, color=self.ram_color, linewidth=2.6)

        self.ax_cpu.set_title("CPU Usage (%)", color="#bfffbf")
        self.ax_ram.set_title("RAM Usage (%)", color="#bdf0ff")

        self.ax_cpu.set_ylim(0, 100)
        self.ax_ram.set_ylim(0, 100)

        self.canvas.draw_idle()

        # schedule next
        self.root.after(REFRESH_INTERVAL_MS, self.update_graphs)

    # -------------------------
    # CONTROLS (Start / Stop / Kill / Export)
    # -------------------------
    def build_controls(self):
        ctrl_frame = Frame(self.root, bg="#0b0f12")
        ctrl_frame.pack(fill=X, padx=12, pady=(6,0))

        # Start button
        self.start_btn = Button(ctrl_frame, text="START MONITOR", command=self.start_monitor,
                                bg="#1e7a1e", fg="white", font=("Segoe UI", 10, "bold"))
        self.start_btn.pack(side=LEFT, padx=6)

        # Stop button
        self.stop_btn = Button(ctrl_frame, text="STOP", command=self.stop_monitor,
                               bg="#8b1e1e", fg="white", font=("Segoe UI", 10, "bold"))
        self.stop_btn.pack(side=LEFT, padx=6)

        # Kill button
        self.kill_btn = Button(ctrl_frame, text="KILL SELECTED", command=self.kill_selected,
                               bg="#ff3b30", fg="white", font=("Segoe UI", 10, "bold"))
        self.kill_btn.pack(side=LEFT, padx=6)

        # Export button
        self.export_btn = Button(ctrl_frame, text="EXPORT LOGS (CSV)", command=self.export_logs,
                                 bg="#243b8a", fg="white", font=("Segoe UI", 10, "bold"))
        self.export_btn.pack(side=LEFT, padx=6)

        # Spacer and thresholds display
        spacer = Frame(ctrl_frame, bg="#0b0f12")
        spacer.pack(side=LEFT, expand=True)

        thr_label = Label(ctrl_frame, text=f"CPU Thr: {CPU_THRESHOLD}%  •  MEM Thr: {MEM_THRESHOLD_MB}MB",
                          bg="#0b0f12", fg="#9fbfdc", font=("Segoe UI", 10))
        thr_label.pack(side=RIGHT, padx=12)

    # -------------------------
    # PROCESS TABLE
    # -------------------------
    def build_table(self):
        table_holder = Frame(self.root, bg="#0b0f12")
        table_holder.pack(fill=BOTH, expand=True, padx=12, pady=(8,6))

        cols = ("PID", "Name", "CPU", "Memory_MB")
        self.tree = ttk.Treeview(table_holder, columns=cols, show="headings", style="Dark.Treeview")
        self.tree.heading("PID", text="PID", command=lambda: self.sort_tree("PID", False))
        self.tree.heading("Name", text="Process Name", command=lambda: self.sort_tree("Name", False))
        self.tree.heading("CPU", text="CPU %", command=lambda: self.sort_tree("CPU", False))
        self.tree.heading("Memory_MB", text="Memory (MB)", command=lambda: self.sort_tree("Memory_MB", False))

        self.tree.column("PID", width=80, anchor=CENTER)
        self.tree.column("Name", width=520, anchor=W)
        self.tree.column("CPU", width=100, anchor=E)
        self.tree.column("Memory_MB", width=140, anchor=E)

        # Alternating row tags
        self.tree.tag_configure('odd', background="#0d1113")
        self.tree.tag_configure('even', background="#0b0f12")
        self.tree.tag_configure('suspicious', background="#4a0b0b", foreground="#ffdede")

        vsb = Scrollbar(table_holder, orient=VERTICAL, command=self.tree.yview)
        vsb.pack(side=RIGHT, fill=Y)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(fill=BOTH, expand=True)

    def sort_tree(self, col, reverse):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            data = [(float(item[0]), item[1]) for item in data]
        except:
            data = [(item[0].lower(), item[1]) for item in data]
        data.sort(reverse=reverse)
        for index, (_, k) in enumerate(data):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.sort_tree(col, not reverse))

    # -------------------------
    # ALERTS PANEL
    # -------------------------
    def build_alerts_panel(self):
        alert_holder = Frame(self.root, bg="#0b0f12")
        alert_holder.pack(fill=X, padx=12, pady=(0,12))
        Label(alert_holder, text="Alerts:", bg="#0b0f12", fg="#bfe9ff", font=("Segoe UI", 12, "bold")).pack(anchor=W)

        self.alert_box = Text(alert_holder, height=6, bg="#070809", fg="#7CFFB2", font=("Consolas", 10))
        self.alert_box.pack(fill=X, pady=(6,0))

    # -------------------------
    # MONITOR THREAD
    # -------------------------
    def monitor_loop(self):
        while self.monitoring:
            rows = []
            try:
                for p in psutil.process_iter(['pid', 'name']):
                    pid = p.info['pid']
                    name = safe_get_name(p)
                    try:
                        cpu = p.cpu_percent(interval=None)
                        mem = p.memory_info().rss / 1024.0 / 1024.0
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    rows.append((pid, name, cpu, mem))
                    self.process_data[pid] = (cpu, mem)
            except Exception:
                pass

            # update UI table (thread-safe via .after)
            self.root.after(0, self.refresh_table, rows)
            time.sleep(PROCESS_POLL_INTERVAL)

    def refresh_table(self, rows):
        # clear
        for item in self.tree.get_children():
            self.tree.delete(item)

        # insert with alternating rows and suspicious highlighting
        for idx, (pid, name, cpu, mem) in enumerate(sorted(rows, key=lambda r: (-r[2], -r[3]))):
            tag = 'odd' if idx % 2 else 'even'
            # mark suspicious if thresholds exceeded
            if cpu >= CPU_THRESHOLD or mem >= MEM_THRESHOLD_MB:
                tag = 'suspicious'
                # log alert once per event (avoid flooding)
                a = {"time": now_ts(), "pid": pid, "name": name, "cpu": cpu, "mem": mem}
                # avoid duplicate consecutive same alert
                if (not self.alert_log) or (self.alert_log and self.alert_log[-1].get("pid") != pid):
                    self.alert_log.append(a)
                    self.alert_box.insert(END, f"[{a['time']}] ⚠ {name} (PID {pid}) CPU={cpu:.1f}% MEM={mem:.1f}MB\n")
                    self.alert_box.see(END)
            self.tree.insert("", END, values=(pid, name, f"{cpu:.1f}", f"{mem:.1f}"), tags=(tag,))

    # -------------------------
    # BUTTON ACTIONS
    # -------------------------
    def start_monitor(self):
        if self.monitoring:
            return
        self.monitoring = True
        # prime cpu_percent calls
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except Exception:
                pass
        threading.Thread(target=self.monitor_loop, daemon=True).start()
        self.alert_box.insert(END, f"[{now_ts()}] Monitoring started\n")
        self.alert_box.see(END)

    def stop_monitor(self):
        self.monitoring = False
        self.alert_box.insert(END, f"[{now_ts()}] Monitoring stopped\n")
        self.alert_box.see(END)

    def kill_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Kill process", "Select a process row to kill.")
            return
        item = selected[0]
        vals = self.tree.item(item, "values")
        pid = int(vals[0])
        name = vals[1]
        confirm = messagebox.askyesno("Confirm Kill",
                                      f"Kill process '{name}' (PID {pid})?\nThis may close applications or system processes.")
        if not confirm:
            return
        try:
            p = psutil.Process(pid)
            p.kill()
            self.alert_box.insert(END, f"[{now_ts()}] KILLED: {name} (PID {pid})\n")
            self.alert_box.see(END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to kill PID {pid}: {e}")

    def export_logs(self):
        if not self.alert_log:
            messagebox.showinfo("Export Logs", "No alerts to export.")
            return
        fpath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not fpath:
            return
        try:
            with open(fpath, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["time","pid","name","cpu","mem"])
                for a in self.alert_log:
                    writer.writerow([a.get("time"), a.get("pid"), a.get("name"), a.get("cpu"), a.get("mem")])
            messagebox.showinfo("Export Logs", f"Exported {len(self.alert_log)} alerts to:\n{fpath}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    root = Tk()
    app = DarkMonitorGUI(root)
    root.mainloop()
