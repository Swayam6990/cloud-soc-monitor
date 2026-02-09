import time
import detector

print("Monitoring started...\n")

while True:
    detector.process_logs()
    time.sleep(5)  # check every 5 seconds
