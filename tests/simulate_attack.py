import time
import os

TARGET = r"D:\3RD year\attack_test"

os.makedirs(TARGET, exist_ok=True)

for i in range(100):
    file_path = os.path.join(TARGET, f"file_{i}.txt")
    with open(file_path, "w") as f:
        f.write("X" * 10000)
    time.sleep(0.02)

print("Simulation completed")
