import hashlib
from scapy.all import IP, TCP, Raw
import time
from datetime import datetime, timedelta

class Threshold:
    def __init__(self, count, windows, group_key, unique_key):
        self.count = count # Amount of packets that would trigger an alert
        self.windows = windows # Window size in seconds

        self.group_key = group_key # Function that receives a packet and returns a group_identifier, used to associate each packet to a group
        # For ARP scan, this would be source MAC
        # If multiple machines are sending ARP requests, we need 1 tracking window for each

        self.unique_key = unique_key # Function that receives a packet and returns a "unique value"
        # Unique value determines if the packet enters tracking window. To enter it, this value must not match any other "unique keys" of packets in the windows
        # E.g. for ARP scan, multiple ARP requests resolving same IP should count as 1 packet only
        # Only want packets that are unique in the tracking window to count towards the threshold

        self.packet_window = {} # Dictionary of group_identifiers (key) and a list of packets (value) 

    # Each packet {'time':datetime.now(), 'key': self.unique_key(packet)}

    def remove_outdated(self):
        now = datetime.now()
        expiration_time = timedelta(seconds=self.windows)

        # Iterate over each identifier and its packet list
        for group_id in list(self.packet_window.keys()):
            original_packets = self.packet_window[group_id]
            # Keep only packets that are still within the time window
            filtered_packets = [pkt for pkt in original_packets if now - pkt['time'] <= expiration_time]

            if filtered_packets:
                self.packet_window[group_id] = filtered_packets
            else:
                del self.packet_window[group_id] # Remove if no packet in tracking list
    
    def is_exceeded(self, packet):
        self.remove_outdated()
        group_id = self.group_key(packet)
        unique_id = self.unique_key(packet)

        if group_id not in self.packet_window:
            self.packet_window[group_id] = []

        # If the unique value already exists, don't add again
        if unique_id in [entry['key'] for entry in self.packet_window[group_id]]:
            return False

        self.packet_window[group_id].append({
            'time': datetime.now(),
            'key': unique_id
        })

        if len(self.packet_window[group_id]) >= self.count:
            return True

        return False

        