import pyshark
import shutil
import os
import tkinter as tk
from tkinter import filedialog
from PIL import ImageTk, Image

def find_large_stream_index(file):
    cap = pyshark.FileCapture(file)
    largest_stream = 0
    # Iterate through all packets in the capture file
    for packet in cap:
        try:
            stream_id = int(packet.stream)
            if stream_id > largest_stream:
                largest_stream = stream_id
        except AttributeError:
            # Skip packets that are not IP packets
            pass
    cap.close()
    return largest_stream

def check_png_for_links(png_file_path):
    link_hex_values = [
        '68 74 74 70 73 3A',  # 'https:'
        '68 74 74 70 3A',     # 'http:'
        '77 77 77 2E'         # 'www.'
    ]
    
    # Read in the PNG file as binary data
    with open(png_file_path, 'rb') as f:
        png_data = f.read()
    
    # Convert the PNG data to a hex string
    png_hex_string = png_data.hex()
    
    # Search for the hex values of links
    for link_hex in link_hex_values:
        if bytes.fromhex(link_hex) in png_hex_string:
            return True
    
    # No links were found
    return False

# Open the pcap file in Wireshark and find the desired TCP stream number
pcap_file = "pcap.pcap"
def find_png(pcap_file):
    count = -1
    max_stream = find_large_stream_index(pcap_file)
    for i in range(0,max_stream+1):
        # Use PyShark to extract the TCP stream data
        cap = pyshark.FileCapture(pcap_file, display_filter=f"tcp.stream eq {i}")

        # Print the payload of each TCP packet in the stream
        for packet in cap:
            try:
                f = open('Saved Files\{}.txt'.format(i),'wb')
                #f.write(packet.tcp.payload.replace(':',''))
                count += 1
                payload_bytes = bytes.fromhex(packet.tcp.payload.replace(':',''))
                f.write(payload_bytes)
            except AttributeError:
                # Ignore packets that don't have a payload
                pass
            
            # Close the capture file when finished
        cap.close()
    for i in range(0,count-1):
        try:
        # specify the file path and the starting and ending character sets
            file_path = 'Saved Files/{}.txt'.format(i)
            with open(file_path, 'rb') as f:
                file_data = f.read()
            png_start = file_data.find(b'\x89\x50\x4e\x47')
            png_end = file_data.rfind(b'\x49\x45\x4e\x44') + 8
            png_data = file_data[png_start:png_end]
            with open('Saved Files/{}.png'.format(i), 'wb') as f:
                f.write(png_data)
                f.close()
            os.remove(file_path)    
        except AttributeError:
            pass

    for i in range(0,count-1):
        try:
            file_path = 'Saved Files/{}.png'.format(i)
            mal_dest_path = 'Saved Files/Malicious/{}.png'.format(i)
            safe_dest_path = 'Saved Files/Safe/{}.png'.format(i)
            if(check_png_for_links(file_path)):
                shutil.copy(file_path, mal_dest_path)
            else:
                shutil.copy(file_path, safe_dest_path)
            os.remove(file_path)
        except AttributeError:
            pass

def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_path_label.config(text="File Path: " + file_path)
        run_button.config(command=lambda: find_png(file_path))

root = tk.Tk()

# Load and display an image as the app header
header_image = ImageTk.PhotoImage(Image.open("image.jpg"))
header_label = tk.Label(root, image=header_image)
header_label.pack()

# Create a label to display the file path
file_path_label = tk.Label(root, text="File Path: ")
file_path_label.pack()

# Create a button to upload a file
file_button = tk.Button(root, text='Upload File', command=open_file)
file_button.pack()

# Create a button to run a function
run_button = tk.Button(root, text='Run Function', command=lambda: None)
run_button.pack()

root.mainloop()
