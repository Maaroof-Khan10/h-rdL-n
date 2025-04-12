#!/bin/bash

# h@rdL!n by Maaroof Khan
# A script to harden a Linux system with essential security measures.
# Usage: Run as root to automatically apply or revert security configurations.

# Safety Settings
set -euo pipefail  # Exit on error, unset variables, or bad command substitution
IFS=$'\n\t'  # Set Internal Field Separator (IFS) to handle input correctly

# Global Variables
SEC_SCORE=0
TOTAL_TASKS=0

# Utility Functions
function header() {
  echo -e "\n[$] $1\n"
}

function complete_task() {
  SEC_SCORE=$((SEC_SCORE + 1))
  TOTAL_TASKS=$((TOTAL_TASKS + 1))
  echo -e "[+] Task completed! Sec_Score: $SEC_SCORE\n"
}

function skip_task() {
  TOTAL_TASKS=$((TOTAL_TASKS + 1))
  echo -e "[-] Task Skipped.\n"
}

function show_score() {
  echo -e "\n[$] Final Security Score: $SEC_SCORE / $TOTAL_TASKS\n"
  if (( SEC_SCORE == TOTAL_TASKS )); then
    echo "[+] Excellent! Your system is tightly secured."
  elif (( SEC_SCORE > TOTAL_TASKS / 2 )); then
    echo "[=] Good job! Some improvements still possible."
  else
    echo "[-] Needs work. Review failed steps and try again."
  fi
}

# Check for root access
if [ "$EUID" -ne 0 ]; then
  echo -e "[!] Please run this script as root (use sudo)."
  exit 1
fi

# Level 1: Update System
function level1_update_system() {
  header "Level [1]: Updating system packages..."
  if apt update && apt upgrade -y; then
    complete_task
  else
    echo "[-] Failed to update system packages."
    skip_task
  fi
}

# Level 2: Password Policy
function level2_password_policy() {
  header "Level [2]: Enforcing Password Policy"
  header "Setting minimum pass_len to 12 characters and 4 chars should be different than the last pass"

  if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    echo "[+] PAM Password Quality is already configured."
  else
    echo "[*] Configuring password quality..."
    echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=4" >> /etc/pam.d/common-password
  fi

  if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    complete_task
  else
    echo "[-] Failed to configure password policy."
    skip_task
  fi
}

# Level 3: Disable SSH Root Login
function level3_disable_ssh_root() {
  header "Level [3]: Disable SSH Root Login"

  # Check if PermitRootLogin is already set to 'no'
  if grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
    echo "[+] SSH root login is already disabled."
    complete_task
    return
  fi

  # Modify the sshd_config file to disable root login
  echo "[*] Disabling root login over SSH..."
  sed -i 's/^#PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config

  # Ensure the change is made
  if grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
    echo "[+] Successfully disabled SSH root login."
    # Restart SSH service
    if systemctl restart ssh || systemctl restart sshd; then
      complete_task
    else
      echo "[-] Failed to restart SSH service."
      skip_task
    fi
  else
    echo "[-] Failed to disable SSH root login."
    skip_task
  fi
}


# Level 4: UFW Firewall
function level4_ufw_firewall() {
  header "Level [4]: Setting up UFW Firewall"
  
  if ! command -v ufw &> /dev/null; then
    echo "[*] Installing UFW..."
    apt install ufw -y || { echo "[-] Failed to install UFW."; skip_task; return; }
  fi
  
  ufw allow ssh
  ufw --force enable
  
  if ufw status | grep -q "active" && ufw status | grep -q "22"; then
    complete_task
  else
    echo "[-] Failed to configure UFW firewall."
    skip_task
  fi
}

# Level 5: Disable Unused Filesystems
function level5_disable_filesystems() {
  header "Level [5]: Disabling unused filesystems (cramfs, udf, freevxfs, jffs2, hfs, hfsplus, squashfs)"

  FILE="/etc/modprobe.d/disable-filesystems.conf"
  cat <<EOF > "$FILE"
install cramfs /bin/true
install udf /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
EOF

  if [[ -f "$FILE" ]] && grep -q "install cramfs /bin/true" "$FILE"; then
    complete_task
  else
    echo "[-] Failed to disable unused filesystems."
    skip_task
  fi
}

# Level 6: Enable Automatic Security Updates
function level6_auto_security_updates() {
  header "Level [6]: Enabling Unattended Security Updates"

  if apt install -y unattended-upgrades apt-listchanges; then
    dpkg-reconfigure -f noninteractive unattended-upgrades

    cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    if systemctl is-enabled unattended-upgrades &>/dev/null; then
      complete_task
    else
      echo "[-] Failed to enable automatic updates."
      skip_task
    fi
  else
    echo "[-] Failed to install unattended-upgrades."
    skip_task
  fi
}

# Revert Changes (Direct Reversion)
# Revert Changes (Direct Reversion)
function revert_changes() {
  echo -e "\n[*] Reverting Applied Tasks...\n"
  echo -e "[*] Select the task(s) to revert (e.g., '1 2 3' to revert levels 1, 2, 3):\n"
  echo -e "[1] - Update system packages"
  echo -e "[2] - Enforce Password Policy"
  echo -e "[3] - Disable SSH Root Login"
  echo -e "[4] - Set up UFW Firewall"
  echo -e "[5] - Disable unused filesystems"
  echo -e "[6] - Enable automatic security updates \n"

  echo -n "[.] Please choose options: "
  read -r input
  IFS=' ' read -r -a choices <<< "$input"

  for choice in "${choices[@]}"; do
    case "$choice" in
      1)
        echo -e "\n[*] Skipping system update revert (no action required)."
        ;;
      2)
        echo "[*] Reverting password policy..."
        sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
        ;;
      3)
        echo "[*] Reverting SSH root login disable..."
        # Revert the changes in sshd_config
        sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
        
        # Check if either service exists and restart it
        if systemctl list-units --type=service | grep -q "ssh.service"; then
          systemctl restart ssh.service
        elif systemctl list-units --type=service | grep -q "sshd.service"; then
          systemctl restart sshd.service
        else
          echo "[-] SSH service not found. You may need to restart it manually."
        fi
        ;;
      4)
        echo "[*] Disabling UFW..."
        ufw disable
        ;;
      5)
        echo "[*] Reverting filesystem disabling..."
        rm -f /etc/modprobe.d/disable-filesystems.conf
        ;;
      6)
        echo "[*] Reverting automatic updates..."
        rm -f /etc/apt/apt.conf.d/20auto-upgrades
        dpkg-reconfigure -f noninteractive unattended-upgrades
        ;;
      *)
        echo "[-] Invalid choice: $choice"
        ;;
    esac
  done

  echo -e "[+] Selected tasks reverted successfully.\n"
}

# Main Menu
function main() {
  echo -e "\n[*] Starting: h@rdL!n by Maaroof Khan\n"
  echo -e "[*] Sit back while we harden your Linux *wink* *wink*\n"

  echo -e "[1] - Update system packages"
  echo -e "[2] - Enforce Password Policy"
  echo -e "[3] - Disable SSH Root Login"
  echo -e "[4] - Set up UFW Firewall"
  echo -e "[5] - Disable unused filesystems"
  echo -e "[6] - Enable automatic security updates"
  echo -e "[a] - Apply all levels"
  echo -e "[r] - Revert applied tasks"
  echo -e "[n] - Apply none\n"

  echo -n "[.] Please choose options (e.g., '1 3 5' or 'r' to revert): "
  read -r input
  IFS=' ' read -r -a choices <<< "$input"

  if [[ "$input" == "a" ]]; then
    echo -e "[*] Applying all levels...\n"
    level1_update_system
    level2_password_policy
    level3_disable_ssh_root
    level4_ufw_firewall
    level5_disable_filesystems
    level6_auto_security_updates
    show_score  # Show score only after tasks are applied
  elif [[ "$input" == "r" ]]; then
    revert_changes  # No need to show score when reverting
  elif [[ "$input" == "n" ]]; then
    echo -e "[-] No levels will be applied. Exiting.\n"
  else
    for choice in "${choices[@]}"; do
      case "$choice" in
        1) level1_update_system ;;
        2) level2_password_policy ;;
        3) level3_disable_ssh_root ;;
        4) level4_ufw_firewall ;;
        5) level5_disable_filesystems ;;
        6) level6_auto_security_updates ;;
        *) echo "[-] Invalid choice: $choice" ;;
      esac
    done
    show_score  # Show score only after tasks are applied
  fi
}

main