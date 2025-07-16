import os
import traceback

newPass = "Cyb3rP@tri0t"

def firewall():
    os.system("ufw enable") #firewall
    os.system("ufw allow 22") #ssh
    os.system("ufw deny 21") #ftp
def update():
    os.system("apt update")
    os.system("apt upgrade")
def blacklistPrograms():
    blacklistedPrograms = []
    with open("BlacklistPrograms.txt", "r") as blacklistFile:
        blacklistedPrograms = blacklistFile.readlines()
    for program in blacklistedPrograms:
        os.system("apt purge %s -y"%(program))
def moderateFiles():
    badExtensions = [".mp4", ".mp3", ".jpg", ".png", ".avi", ".ogg", ".cpp", ".mov", "txt"]
    os.system("echo '' > SuspiciousFilesLog.txt")
    for extension in badExtensions:
        os.system("find / -name \"*%s\" >> SuspiciousFilesLog.txt"%(extension))
def auditUsers():
    users = set()
    with open("/etc/passwd") as etcPasswd:
        for line in etcPasswd.readlines():
            tokenizedLine = line.split(":")
            if int(tokenizedLine[2]) >= 1000 and int(tokenizedLine[2]) != 65534:
                users.add(tokenizedLine[0])
    for user in list(users):
        os.system(f"echo \"{newPass}\n{newPass}\" | passwd %s"%(user))
    allowedUsers = set()
    with open("AllowedUsers.txt") as allowed:
        for line in allowed.readlines():
            allowedUsers.add(line.strip())
    badUsers = list(users.difference(allowedUsers))
    for badUser in badUsers:
        os.system("deluser %s"%(badUser))
    for user in list(allowedUsers):
        os.system("adduser %s"%(user))
    sudoLine = ""
    with open("/etc/group") as groups:
        for group in groups.readlines():
            if group[:4] == "sudo":
                sudoLine = group
                break
    admins = set([line.strip() for line in sudoLine.split(":")[-1].split(",")])
    allowedAdmins = set()
    with open("AllowedAdmins.txt") as allowed:
        for line in allowed.readlines():
            allowedAdmins.add(line.strip())
    badAdmins = list(admins.difference(allowedAdmins))
    for badAdmin in badAdmins:
        os.system("deluser %s sudo"%(badAdmin))
def disableRoot():
    os.system("passwd -l root")
def disablePermissions():
    os.system("chmod 640 /etc/shadow/")
def passwordFix():
    os.system("sed -i \"/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS\t30\" /etc/login.defs")
    os.system("sed -i \"/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS\t14\" /etc/login.defs")
    os.system("sed -i \"/^PASS_WARN_DAYS/ c\PASS_WARN_DAYS\t7\" /etc/login.defs")
    os.system("sed -i \"s/ENCRYPT_METHOD .*/ENCRYPT_METHOD SHA512/g\" /etc/login.defs")
    os.system("echo \"auth optional pam_tally.so deny=5 onerr=fail unlock_time=1800 audit even_deny_root_account_silent\" >> /etc/pam.d/common-auth")
    os.system("echo \"auth required pam_wheel.so\" >> /etc/pam.d/su")
    os.system("echo \"password	requisite			pam_cracklib.so retry=3 minlen=8 difok=3 remember=5 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\" >> /etc/pam.d/common-password")
    os.system("echo \"password	requisite			pam_cracklib.so retry=3 minlen=8 difok=3 remember=5 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\" >> /etc/pam.d/common-password")
    os.system("echo \"auth required pam_wheel.so\" /etc/pam.d/su")
def general():
    os.system("apt install clamav -y")
    os.system("apt instal RKhunter -y")
    os.system("apt install chrootkit -y")
    os.system("apt install clamtk -y")
    os.system("apt install libpam-cracklib -y")
    os.system("apt install expect -y")
def ssh():
    sshNeeded = input("Is SSH Needed? (Y/N): ")
    sshPort = int(input())
    if sshNeeded.upper() == "Y":
        os.system("apt install openssh-server")
        os.system("sed -i \"s/Port .*/Port %s/g\" /etc/sshd_config"%(sshPort))
        os.system("ufw allow %s"%(sshPort))
        os.system("sed -i \"s/PermitRootLogin .*/PermitRootLogin no/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/PermitEmptyPasswords .*/PermitEmptyPasswords no/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/AllowTcpForwarding .*/AllowTcpForwarding no/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/HostBasedAuthentication .*/HostBasedAuthentication no/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/LoginGraceTime .*/LoginGraceTime 30/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/Protocol .*/Protocol 2/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/IgnoreRhosts .*/IgnoreRhosts yes/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/X11Forwarding .*/X11Forwarding no/g\" /etc/ssh/sshd_config")
        os.system("echo \"ClientAliveInterval 300'\">> /etc/ssh/sshd_config")
        os.system("echo \"ClientAliveCountMax 0\" >> /etc/ssh/sshd_config")
        os.system("sed -i \"s/StrictModes .*/StrictModes yes/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/UsePrivilegeSeparation .*/UsePrivilegeSeparation yes/g\" /etc/ssh/sshd_config")
        os.system("sed -i \"s/PrintLastLog .*/PrintLastLog no/g\" /etc/ssh/sshd_config")
    else:
        os.system("ufw deny %s"%(sshPort))
        os.system("apt purge openssh-server")
def disableGuest():
    os.system("echo \"allow-guest=false\" >> /etc/lightdm/lightdm.conf")
    os.system("echo \"allow-guest=false\" >> /etc/lightdm/lightdm.conf.d/50-unity-greeter.conf")
    os.system("echo \"\" > /etc/rc.local")
    os.system("echo \"'net.ipv6.conf.all.disable_ipv6 = 1\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv6.conf.default.disable_ipv6 = 1\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv6.conf.lo.disable_ipv6 = 1\" >> /etc/sysctl.conf")
    os.system("sysctl -p")
    os.system("echo \"net.ipv4.ip_forward = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.default.accept_source_route = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.tcp_syncookies = 1\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.all.send_redirects = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.default.send_redirects = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.all.accept_redirects = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.all.secure_redirects = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.all.accept_source_route = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.all.log_martians = 1\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.default.accept_source_route = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.default.accept_redirects = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.default.secure_redirects = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.all.accept_redirects = 0\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.icmp_echo_ignore_broadcasts = 1\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.all.rp_filter = 1\" >> /etc/sysctl.conf")
    os.system("echo \"net.ipv4.conf.default.rp_filter = 1\" >> /etc/sysctl.conf")
    os.system("sysctl -p")
def fixAll():
    disableRoot()
    firewall()
    update()
    disablePermissions()
    passwordFix()
    blacklistPrograms()
    moderateFiles()
    auditUsers()
    disableGuest()
    ssh()
exit = True
begin = True
while exit:
    print("\033[1;32;40m")
    if begin:
        os.system("clear")
        begin = False
    else:
        command = input(">>> ")
        if (command == "quit"):
            exit = False
        elif "run" in command:
            if "run " in command:
                command = command.replace("run ", "")
                if len(command) > 0:
                    try:
                        eval(command)
                    except Exception:
                        os.system("echo " + 'sh: 1: "' + command + '" could not be executed')
                        print(traceback.format_exc())
                else:
                    os.system("echo " + 'sh: 1: "run" missing one or more arguments')
            else:
                if len(command) > 3:
                    os.system("echo " + 'sh: 1: Unkown command: "' + command + '"')
                else:
                    os.system("echo " + 'sh: 1: "run" missing one or more arguments')
        elif "calc" in command:
            if "calc " in command:
                command = command.replace("calc ", "")
                if len(command) > 0:
                    try:
                        os.system("echo " + str(eval(command.replace("^", "**"))))
                    except Exception:
                        os.system("echo " + 'sh: 1: "' + command + '" could not be evaluated')
                        print(traceback.format_exc())
                else:
                    os.system("echo " + 'sh: 1: "calc" missing one or more arguments')
            else:
                if len(command) > 4:
                    os.system("echo " + 'sh: 1: Unkown command: "' + command + '"')
                else:
                    os.system("echo " + 'sh: 1: "calc" missing one or more arguments')
        else:
            os.system(command)
