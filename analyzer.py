failed_attempts = 0
ip_count = {}
threat_detected = False

with open("auth.log", "r") as log_file:
    for line in log_file:

        if "Failed password" in line:
            failed_attempts += 1

            parts = line.split()
            ip_address = parts[10]

            if ip_address in ip_count:
                ip_count[ip_address] += 1
            else:
                ip_count[ip_address] = 1


print("\n========== SOC INVESTIGATION ==========")
print("Total failed login attempts:", failed_attempts)
print()

for ip, attempts in ip_count.items():

    if attempts > 5:
        threat_detected = True

        print("Suspicious Activity:")
        print("Source IP:", ip)
        print("Failed attempts:", attempts)
        print("Severity: HIGH")
        print()


if threat_detected:
    print("Assessment: Potential brute-force activity detected.")
    print("Recommended Action: Investigate the source IP and review related authentication events.")
else:
    print("Assessment: No significant suspicious activity detected.")
    print("Recommended Action: Continue monitoring authentication logs for any unusual patterns.")