# process-lineage-detector

Markdown
# Process Lineage Visualizer & Anomaly Detector

A defensive Blue Team utility designed to audit process trees and detect common post-exploitation behaviors, including reverse shells spawned from web servers and binary execution from temporary directories.

## Features
- **Parent-Child Chain Auditing**: Identifies suspicious process relationships (e.g., `nginx` $\rightarrow$ `sh`).
- **Path Verification**: Flags binaries executing from writable system locations like `/tmp` or `/dev/shm`.
- **Zero Third-Party Dependencies**: Built exclusively with Python standard libraries.

## Quick Start
```bash
python3 process_tree_detector.py
Custom Rules
Detection signatures can be tuned directly in suspicious_rules.json:

JSON
{
  "suspicious_parents": {
    "nginx": ["bash", "sh", "nc", "python"]
  },
  "suspicious_paths": [
    "/tmp",
    "/var/tmp"
  ]
}

---

## 🌐 How to Add to Your GitHub Repository via Web UI

1. On your `Blue-Team-Defensive-Security` repository page, click **Add file** $\rightarrow$ **Create new file**.
2. Type `process-lineage-detector/suspicious_rules.json` into the filename box.
3. Paste the contents of `suspicious_rules.json` and click **Commit changes**.
4. Repeat for:
   * `process-lineage-detector/process_tree_detector.py`
   * `process-lineage-detector/README.md`

