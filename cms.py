import time
# import binascii
from collections import defaultdict
#from crccheck.crc import Crc16, Crc32
import hashlib

# Define the parameters for the Count-Min Sketch
width = 100
depth = 3

# Initialize the Count-Min Sketch data structure
count_min_sketch = [[0] * width for _ in range(depth)]

# Initialize a dictionary to store the counts of each IP address
ip_counts = defaultdict(int)

def crc16_hash(data):
    crc = hashlib.sha1()
    crc.update(data.encode('utf-8'))
    return crc.hexdigest()

def crc32_hash(data):
    crc = hashlib.sha512()
    crc.update(data.encode('utf-8'))
    return crc.hexdigest()

def sha1_hash(data):
    sha1 = hashlib.sha256()
    sha1.update(data.encode('utf-8'))
    return sha1.hexdigest()

def update_count_min_sketch(ip_address):
    for i in range(depth):
        hash_values = [crc16_hash(ip_address), crc32_hash(ip_address), sha1_hash(ip_address)]
        min_hash_value = min(int(h, 16) % width for h in hash_values)
        count_min_sketch[i][min_hash_value] += 1

def check_attack(ip_address):
    min_count = float('inf')
    for i in range(depth):
        hash_values = [crc16_hash(ip_address), crc32_hash(ip_address), sha1_hash(ip_address)]
        min_hash_value = min(int(h, 16) % width for h in hash_values)
        min_count = min(min_count, count_min_sketch[i][min_hash_value])

    return min_count >= 3

def reset_count_min_sketch():
    global count_min_sketch
    count_min_sketch = [[0] * width for _ in range(depth)]

def process_input_files(file_paths):
    while True:
        for file_path in file_paths:
            with open(file_path, 'r') as file:
                for line in file:
                    ip_address = line.strip()
                    update_count_min_sketch(ip_address)
                    ip_counts[ip_address] += 1

                    if check_attack(ip_address):
                        print("Attack detected for IP address:"+ ip_address)
                        # Reset count for the IP address
                        ip_counts[ip_address] = 0

        # Reset the count-min sketch after processing a set of three files
        reset_count_min_sketch()
        time.sleep(3)

# Example usage
input_file_paths = ["ip1.txt", "ip2.txt", "ip3.txt"]
process_input_files(input_file_paths)