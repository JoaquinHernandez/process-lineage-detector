import os
import sys
import json
import subprocess
import platform

class ProcessLineageDetector:
    def __init__(self, rules_path="suspicious_rules.json"):
        if not os.path.exists(rules_path):
            print(f"[-] Missing rules file: {rules_path}")
            sys.exit(1)
        with open(rules_path, "r") as f:
            self.rules = json.load(f)
        self.suspicious_parents = self.rules.get("suspicious_parents", {})
        self.suspicious_paths = self.rules.get("suspicious_paths", [])

    def fetch_processes(self):
        """Retrieve process list cross-platform."""
        processes = {}
        if platform.system() == "Linux":
            try:
                # Fetch PID, PPID, Command, Executable Path
                output = subprocess.check_output(
                    ["ps", "-eo", "pid,ppid,comm,args"],
                    text=True
                )
                for line in output.strip().split("\n")[1:]:
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 3:
                        pid = int(parts[0])
                        ppid = int(parts[1])
                        comm = parts[2]
                        args = parts[3] if len(parts) > 3 else comm
                        processes[pid] = {
                            "ppid": ppid,
                            "comm": comm,
                            "args": args
                        }
            except Exception as e:
                print(f"[-] Could not read Linux process table: {e}")
        else:
            # Fallback mock telemetry for demonstration on non-Linux hosts
            processes = {
                1: {"ppid": 0, "comm": "systemd", "args": "/sbin/init"},
                501: {"ppid": 1, "comm": "nginx", "args": "nginx: worker process"},
                502: {"ppid": 501, "comm": "sh", "args": "/bin/sh -i"},
                800: {"ppid": 1, "comm": "malware_test", "args": "/tmp/malware_test --daemon"}
            }
        return processes

    def analyze(self):
        print("=" * 65)
        print("🔍 Process Lineage Visualizer & Anomaly Detector")
        print("=" * 65)

        processes = self.fetch_processes()
        print(f"[+] Auditing {len(processes)} active system processes...\n")

        anomalies = []

        for pid, data in processes.items():
            ppid = data["ppid"]
            comm = data["comm"]
            args = data["args"]
            parent = processes.get(ppid)
            parent_comm = parent["comm"] if parent else "Unknown"

            # Check 1: Suspicious Parent-Child Process Chain (e.g. Webserver -> Shell)
            if parent_comm in self.suspicious_parents:
                flagged_children = self.suspicious_parents[parent_comm]
                if comm in flagged_children:
                    anomalies.append({
                        "type": "SUSPICIOUS_CHILD_PROCESS",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "ppid": ppid,
                        "details": f"Web/Service daemon '{parent_comm}' (PID: {ppid}) spawned shell/interpreter '{comm}' (PID: {pid})",
                        "cmd": args
                    })

            # Check 2: Binary running from volatile/writable temp paths
            for bad_path in self.suspicious_paths:
                if bad_path in args:
                    anomalies.append({
                        "type": "SUSPICIOUS_EXECUTION_PATH",
                        "severity": "HIGH",
                        "pid": pid,
                        "ppid": ppid,
                        "details": f"Process executing from temporary directory: '{bad_path}'",
                        "cmd": args
                    })

        # Display findings
        if not anomalies:
            print("[✓] Process analysis complete: No anomalous lineage behaviors detected.")
        else:
            print(f"[🚨] Detected {len(anomalies)} suspicious process anomaly(ies):\n")
            for alert in anomalies:
                print(f"[{alert['severity']}] {alert['type']}")
                print(f"    • PID: {alert['pid']} (Parent PID: {alert['ppid']})")
                print(f"    • Finding: {alert['details']}")
                print(f"    • Command: {alert['cmd']}\n")

if __name__ == "__main__":
    detector = ProcessLineageDetector()
    detector.analyze()
