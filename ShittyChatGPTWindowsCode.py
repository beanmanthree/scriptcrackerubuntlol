import os
import subprocess
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_powershell(cmd):
    result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("Error:", result.stderr)

def enable_firewall():
    run_powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")

def block_ports():
    ports_to_block = [20, 21, 23, 139, 445]
    for port in ports_to_block:
        run_powershell(f"New-NetFirewallRule -DisplayName 'Block Port {port}' -Direction Inbound -LocalPort {port} -Protocol TCP -Action Block")

def update_windows():
    run_powershell("Install-Module PSWindowsUpdate -Force")
    run_powershell("Get-WindowsUpdate -AcceptAll -Install -AutoReboot")

def audit_users():
    run_powershell("net user")

def antivirus_scan():
    run_powershell("Start-MpScan -ScanType FullScan")

def find_suspicious_files():
    extensions = ['*.mp3', '*.mp4', '*.avi', '*.jpg']
    with open("SuspiciousFilesLog.txt", "w") as f:
        for ext in extensions:
            result = subprocess.run(["powershell", "-Command", f"Get-ChildItem -Path C:\\ -Include {ext} -Recurse -ErrorAction SilentlyContinue"], capture_output=True, text=True)
            f.write(result.stdout)

if __name__ == "__main__":
    if not is_admin():
        print("You must run this script as Administrator.")
        exit(1)

    enable_firewall()
    block_ports()
    update_windows()
    audit_users()
    antivirus_scan()
    find_suspicious_files()
