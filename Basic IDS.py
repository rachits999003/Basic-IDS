from scapy.all import sniff
import datetime
import tkinter as tk
import threading
from tkinter import scrolledtext

global sniffing
sniffing = False

def packet_callback(packet):
    log_entry = f"{datetime.datetime.now()} - {packet.summary()}\n"
    text_area.insert(tk.END, log_entry)
    text_area.see(tk.END)
    with open('ids_log.txt', 'a') as log_file:
        log_file.write(log_entry)

def start_sniffing():
    global sniffing
    sniffing = True
    text_area.insert(tk.END, "Starting packet sniffing...\n")
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

def sniff_packets():
    global sniffing
    sniff(prn = packet_callback, store = False)

def stop_sniffing():
    global sniffing
    sniff(prn = packet_callback, store = False)
    text_area.insert(tk.END, "Stopping packet sniffing...\n")

#GUI setup
root = tk.Tk()
root.title("Simple IDS")
root.geometry("800x600")

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
text_area.pack(pady = 10)

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack()

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack()

root.mainloop()