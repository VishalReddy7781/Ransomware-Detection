import os
import time

TARGET_DIR = r"D:\3RD year\attack_test"
os.makedirs(TARGET_DIR, exist_ok=True)

# Create sample files
for i in range(10):
    with open(os.path.join(TARGET_DIR, f"file_{i}.txt"), "w") as f:
        f.write("important data")

time.sleep(1)

# Rename files like ransomware
for file in os.listdir(TARGET_DIR):
    old = os.path.join(TARGET_DIR, file)
    new = old + ".locked"
    os.rename(old, new)
    time.sleep(0.05)

print("Mass rename attack completed")
