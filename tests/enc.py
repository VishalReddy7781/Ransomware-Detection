import os
import random
import time

TARGET_DIR = r"D:\3RD year\attack_test"
os.makedirs(TARGET_DIR, exist_ok=True)

def fake_encrypt(file_path):
    with open(file_path, "wb") as f:
        f.write(os.urandom(50000))  # high entropy data

for i in range(10):
    path = os.path.join(TARGET_DIR, f"doc_{i}.txt")
    fake_encrypt(path)
    time.sleep(0.1)

print("Fake encryption attack completed")
