# h@rdL!n - Linux Hardening Script

**h@rdL!n** is a bash script designed to automate the process of hardening a Linux system with essential security measures. Whether you're a beginner or an experienced system administrator, this script will help ensure your Linux system is secured through a series of configurable tasks. 

With **h@rdL!n**, you can apply best practices like updating system packages, enforcing password policies, disabling SSH root login, setting up firewalls, and more, all in a gamified manner that tracks your progress with a security score.

## Features
- **Gamified Security Levels:** Each task is part of a level, and you can track your progress with a security score.
- **Automatic & Manual Configurations:** Run specific security measures or apply all levels at once. You can also revert any changes made.
- **Interactive Menu:** Easy-to-use menu to guide you through the hardening process.

## Levels Explained/Key Features

`h@rdL!n` applies progressive security hardening in levels. Each level targets a specific area of Linux system security:

### Level 1: System Update
**Goal:** Ensure the system is using the latest software and security patches.  
**Actions Taken:**
- Runs `apt update` and `apt upgrade -y` to refresh the package list and upgrade all installed packages.  
**Why:** Outdated packages often contain vulnerabilities that can be exploited. Keeping your system updated is the first line of defense.

---

### Level 2: Password Policy Enforcement
**Goal:** Strengthen password security to resist brute-force or dictionary attacks.  
**Actions Taken:**
- Appends a line to `/etc/pam.d/common-password` to enforce:
  - Minimum password length (`minlen=12`)
  - Minimum difference from previous passwords (`difok=4`)
- Uses the `pam_pwquality` module for complexity enforcement.  
**Why:** Strong, unique passwords are essential for user-level security. This prevents weak credentials from being exploited.

---

### Level 3: Disable SSH Root Login
**Goal:** Prevent direct remote login as the root user via SSH.  
**Actions Taken:**
- Modifies `/etc/ssh/sshd_config` to set `PermitRootLogin no`
- Restarts the SSH service to apply changes.  
**Why:** Root access over SSH is a huge security risk. Disabling it forces attackers to breach a lower-privileged account first, reducing attack surface.

---

### Level 4: UFW Firewall Setup
**Goal:** Enable a basic firewall to restrict incoming traffic.  
**Actions Taken:**
- Installs UFW if not present.
- Allows SSH connections.
- Enables the firewall using `ufw --force enable`.  
**Why:** A firewall adds an extra layer of protection by allowing only trusted traffic and dropping everything else.

---

### Level 5: Disable Unused Filesystems
**Goal:** Prevent attackers from loading vulnerable or unnecessary filesystem modules.  
**Actions Taken:**
- Writes rules to `/etc/modprobe.d/disable-filesystems.conf` to disable:
  - `cramfs`, `udf`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `squashfs`  
**Why:** If your system doesn’t use these legacy or niche filesystems, disabling them reduces kernel attack surface and speeds up boot time.

---

### Level 6: Enable Automatic Security Updates
**Goal:** Ensure the system automatically installs critical security patches.  
**Actions Taken:**
- Installs `unattended-upgrades` and `apt-listchanges`.
- Configures daily package list updates and automatic upgrades.
- Enables the `unattended-upgrades` systemd service.  
**Why:** Automating security updates reduces human error and ensures fast mitigation of vulnerabilities.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Maaroof-Khan/hardLin.git
   cd hardLin-main/src
   ```

2. **Make the script executable:**
   ```bash
   chmod +x 'h@rdL!n.sh'
   ```

3. **Run the script as root:**
   ```bash
   sudo './h@rdL!n.sh'
   ```

## Usage

### Running the Script
The script provides an interactive menu that allows you to choose which security measures you want to apply or revert. Here's how the menu works:

```bash
[*] Starting: h@rdL!n by Maaroof Khan
[*] Sit back while we harden your Linux *wink* *wink*

[1] - Update system packages
[2] - Enforce Password Policy
[3] - Disable SSH Root Login
[4] - Set up UFW Firewall
[5] - Disable unused filesystems
[6] - Enable automatic security updates
[a] - Apply all levels
[r] - Revert applied tasks
[n] - Apply none

[.] Please choose options (e.g., '1 3 5' or 'r' to revert): 
```

You can:
- **Choose individual tasks** by entering their numbers (e.g., `1 3 5`).
- **Apply all tasks** with the `a` option.
- **Revert any applied changes** with the `r` option.

### Security Score
After applying tasks, the script will show your **security score** based on the number of successful tasks completed. It will provide feedback on how well you've hardened your system:

- **Excellent:** Your system is tightly secured.
- **Good:** Some improvements are possible.
- **Needs Work:** Review failed steps and try again.

## Example

```bash
[*] Starting: h@rdL!n by Maaroof Khan
[*] Sit back while we harden your Linux *wink* *wink*

[1] - Update system packages
[2] - Enforce Password Policy
[3] - Disable SSH Root Login
[4] - Set up UFW Firewall
[5] - Disable unused filesystems
[6] - Enable automatic security updates
[a] - Apply all levels
[r] - Revert applied tasks
[n] - Apply none

[.] Please choose options (e.g., '1 3 5' or 'r' to revert): 1 3 5
```

---

## Reverting Changes
If you decide to undo any applied security measures, you can use the **Revert** option. The script will guide you through reverting specific tasks, such as:
- Removing password policy configurations
- Enabling SSH root login
- Disabling UFW firewall
- Reverting filesystem hardening

---

## Contributions
Feel free to fork the repository and submit pull requests if you have any suggestions or improvements! This script is designed to help anyone looking to enhance their Linux security.

### Reporting Issues
If you encounter any issues, please open an issue on GitHub with a detailed description of the problem.

---

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
