#!/bin/bash

# Title: System Information
# Description: Gather general system information
# Author: Jonas Resch

check_os_version() {
  print_subtitle "Operating System Information"
  
  # OS Details
  if [ -f /etc/os-release ]; then
    os_name=$(grep "^NAME=" /etc/os-release | cut -d= -f2 | tr -d '"')
    os_version=$(grep "^VERSION=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    os_id=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    print_success "OS: ${os_name} ${os_version} (${os_id})"
  else
    os_info=$(uname -a)
    print_success "OS: ${os_info}"
  fi
  
  # Kernel version
  kernel_version=$(uname -r)
  print_success "Kernel version: ${kernel_version}"
  
  # Check for architecture
  arch=$(uname -m)
  print_success "Architecture: ${arch}"
  
  # Check if it's a virtual machine
  if [ -f /sys/class/dmi/id/product_name ] || [ -d /proc/xen ] || grep -q "^flags.*hypervisor" /proc/cpuinfo 2>/dev/null; then
    vm_type="Unknown"
    
    if grep -q "VMware" /sys/class/dmi/id/product_name 2>/dev/null; then
      vm_type="VMware"
    elif grep -q "VirtualBox" /sys/class/dmi/id/product_name 2>/dev/null; then
      vm_type="VirtualBox"
    elif [ -d /proc/xen ]; then
      vm_type="Xen"
    elif grep -q "QEMU" /sys/class/dmi/id/product_name 2>/dev/null; then
      vm_type="QEMU/KVM"
    elif grep -q "Microsoft" /sys/class/dmi/id/product_name 2>/dev/null; then
      vm_type="Hyper-V"
    elif dmesg | grep -q "Parallels" 2>/dev/null; then
      vm_type="Parallels"
    fi
    
    print_warning "Running in a virtual environment: ${vm_type}"
  else
    print_success "Running on physical hardware"
  fi
  
  # WSL detection
  if grep -q Microsoft /proc/version 2>/dev/null; then
    print_warning "Running in Windows Subsystem for Linux (WSL)"
  fi
  
  # Check for container
  if [ -f /.dockerenv ] || grep -q "docker\|lxc" /proc/1/cgroup 2>/dev/null; then
    print_warning "Running inside a container"
  fi
}

check_hardware_info() {
  print_subtitle "Hardware Information"
  
  # CPU info
  cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -n1 | cut -d: -f2 | xargs)
  cpu_cores=$(grep -c "processor" /proc/cpuinfo 2>/dev/null)
  if [ -n "$cpu_model" ]; then
    print_success "CPU: ${cpu_model} (${cpu_cores} cores)"
  else
    print_success "CPU Cores: ${cpu_cores}"
  fi
  
  # Memory info
  if [ -f /proc/meminfo ]; then
    total_mem=$(grep "MemTotal" /proc/meminfo | awk '{print $2}')
    total_mem_mb=$(($total_mem / 1024))
    free_mem=$(grep "MemFree" /proc/meminfo | awk '{print $2}')
    free_mem_mb=$(($free_mem / 1024))
    used_mem_mb=$(($total_mem_mb - $free_mem_mb))
    used_percent=$((($used_mem_mb * 100) / $total_mem_mb))
    
    print_success "Memory: ${used_mem_mb}MB / ${total_mem_mb}MB (${used_percent}% used)"
  fi
  
  # Swap info
  if [ -f /proc/meminfo ]; then
    total_swap=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    if [ "$total_swap" -gt 0 ]; then
      total_swap_mb=$(($total_swap / 1024))
      free_swap=$(grep "SwapFree" /proc/meminfo | awk '{print $2}')
      free_swap_mb=$(($free_swap / 1024))
      used_swap_mb=$(($total_swap_mb - $free_swap_mb))
      used_swap_percent=$((($used_swap_mb * 100) / $total_swap_mb))
      
      print_success "Swap: ${used_swap_mb}MB / ${total_swap_mb}MB (${used_swap_percent}% used)"
    else
      print_warning "No swap configured"
    fi
  fi
}

check_filesystem_info() {
  print_subtitle "File System Information"
  
  # Mount points
  print_info "Mount Points:"
  mount_output=$(mount -t ext2,ext3,ext4,xfs,btrfs,vfat,ntfs,fuseblk 2>/dev/null | grep -v "snap" | sort)
  if [ -n "$mount_output" ]; then
    echo "$mount_output" | while read -r line; do
      device=$(echo "$line" | awk '{print $1}')
      mountpoint=$(echo "$line" | awk '{print $3}')
      fs_type=$(echo "$line" | awk '{print $5}')
      options=$(echo "$line" | grep -oP 'type \K\S+' | tr ',' ' ')
      
      # Check if the filesystem is mounted with noexec, nosuid, or nodev
      if echo "$options" | grep -q "noexec"; then
        print_success " ${CYAN}${mountpoint}${NC} [${fs_type}] on ${device} (${YELLOW}noexec${NC})"
      elif echo "$options" | grep -q "nosuid"; then
        print_success " ${CYAN}${mountpoint}${NC} [${fs_type}] on ${device} (${YELLOW}nosuid${NC})"
      else
        print_success " ${CYAN}${mountpoint}${NC} [${fs_type}] on ${device}"
      fi
    done
  else
    print_not_found "No common filesystems mounted"
  fi
  
  # Disk usage
  print_info "Disk Usage:"
  disk_info=$(df -h -t ext2 -t ext3 -t ext4 -t xfs -t vfat -t ntfs -t btrfs 2>/dev/null | grep -v "snap" | grep -v "Filesystem" | sort)
  
  if [ -n "$disk_info" ]; then
    echo "$disk_info" | while read -r line; do
      filesystem=$(echo "$line" | awk '{print $1}')
      size=$(echo "$line" | awk '{print $2}')
      used=$(echo "$line" | awk '{print $3}')
      avail=$(echo "$line" | awk '{print $4}')
      use_percent=$(echo "$line" | awk '{print $5}')
      mountpoint=$(echo "$line" | awk '{print $6}')
      
      # Highlight high disk usage
      if [[ "${use_percent}" =~ [8-9][0-9]% ]] || [[ "${use_percent}" =~ 100% ]]; then
        print_warning " ${CYAN}${mountpoint}${NC}: ${RED}${use_percent}${NC} used (${used}/${size}, ${avail} free)"
      else
        print_success " ${CYAN}${mountpoint}${NC}: ${use_percent} used (${used}/${size}, ${avail} free)"
      fi
    done
  else
    print_not_found "No disk usage information available"
  fi
}

check_kernel_modules() {
  print_subtitle "Kernel Modules"
  
  # List kernel modules that could potentially be exploitable
  interesting_modules=("bluetooth" "usb_storage" "thunderbolt" "firewire" "bcm" "rtl" "nvidia")
  
  for module in "${interesting_modules[@]}"; do
    module_info=$(lsmod 2>/dev/null | grep "$module")
    if [ -n "$module_info" ]; then
      print_warning "Potentially interesting module loaded: $module_info"
    fi
  done
  
  # Check for unsigned kernel modules if secure boot is enabled
  if [ -d /sys/firmware/efi ]; then
    secure_boot=$(mokutil --sb-state 2>/dev/null | grep "SecureBoot" | awk '{print $2}')
    if [ "$secure_boot" = "enabled" ]; then
      unsigned_modules=$(dmesg 2>/dev/null | grep "signature" | grep -i "required" | grep -i "module" | grep -v "OK")
      if [ -n "$unsigned_modules" ]; then
        print_warning "Unsigned kernel modules with Secure Boot enabled:"
        echo "$unsigned_modules"
      fi
    fi
  fi
  
  # List loaded third-party modules
  third_party_modules=$(lsmod 2>/dev/null | grep -v "kernel" | grep -v "live" | head -n 10)
  if [ -n "$third_party_modules" ]; then
    print_info "Top 10 third-party kernel modules:"
    echo "$third_party_modules" | while read -r line; do
      print_success " $line"
    done
  fi
}

check_system_startup() {
  print_subtitle "System Startup Information"
  
  # Uptime
  uptime_output=$(uptime)
  print_success "Uptime: $uptime_output"
  
  # Init system type
  if [ -f /proc/1/comm ]; then
    init_system=$(cat /proc/1/comm)
    print_success "Init system: $init_system"
  else
    # Fallback method
    if command_exists systemctl; then
      print_success "Init system: systemd"
    elif command_exists initctl; then
      print_success "Init system: Upstart"
    elif [ -f /etc/init.d/rc ]; then
      print_success "Init system: SysVinit"
    else
      print_warning "Init system: Unknown"
    fi
  fi
  
  # Last boot time
  last_boot=$(who -b 2>/dev/null | awk '{print $3, $4}')
  if [ -n "$last_boot" ]; then
    print_success "Last boot: $last_boot"
  fi
  
  # Boot parameters that might be exploitable
  if [ -f /proc/cmdline ]; then
    cmdline=$(cat /proc/cmdline)
    print_info "Boot parameters:"
    print_success " $cmdline"
    
    # Check for potentially insecure boot parameters
    if echo "$cmdline" | grep -q "init="; then
      print_warning "Custom init process specified in boot parameters"
    fi
    if echo "$cmdline" | grep -q "nokaslr"; then
      print_warning "KASLR is disabled (nokaslr)"
    fi
    if echo "$cmdline" | grep -q "nosuid"; then
      print_warning "SUID binaries disabled globally (nosuid)"
    fi
    if echo "$cmdline" | grep -q "nosmep"; then
      print_warning "SMEP is disabled (nosmep)"
    fi
    if echo "$cmdline" | grep -q "nopti"; then
      print_warning "Kernel Page Table Isolation is disabled (nopti)"
    fi
    if echo "$cmdline" | grep -q "quiet"; then
      print_warning "Kernel is booted in quiet mode (quiet)"
    fi
  fi
}

check_system_security() {
  print_subtitle "System Security Features"
  
  # SELinux status
  if command_exists sestatus; then
    selinux_status=$(sestatus 2>/dev/null | grep "SELinux status" | awk '{print $3}')
    if [ "$selinux_status" = "enabled" ]; then
      selinux_mode=$(sestatus 2>/dev/null | grep "Current mode" | awk '{print $3}')
      print_success "SELinux: ${selinux_status} (${selinux_mode})"
    else
      print_warning "SELinux: ${selinux_status}"
    fi
  elif [ -f /etc/selinux/config ]; then
    selinux_config=$(grep "^SELINUX=" /etc/selinux/config | cut -d= -f2)
    print_warning "SELinux: ${selinux_config} (from config file)"
  else
    print_warning "SELinux: Not installed"
  fi
  
  # AppArmor status
  if command_exists aa-status; then
    apparmor_status=$(aa-status 2>&1 | grep -i "apparmor")
    if echo "$apparmor_status" | grep -q -i "enabled"; then
      print_success "AppArmor: Enabled"
    else
      print_warning "AppArmor: Disabled or not properly configured"
    fi
  elif [ -d /etc/apparmor.d ]; then
    print_warning "AppArmor: Config files exist but status cannot be determined"
  else
    print_warning "AppArmor: Not installed"
  fi
  
  # ASLR (Address Space Layout Randomization)
  if [ -f /proc/sys/kernel/randomize_va_space ]; then
    aslr_status=$(cat /proc/sys/kernel/randomize_va_space)
    case "$aslr_status" in
      0) print_critical "ASLR: Disabled (0)" ;;
      1) print_warning "ASLR: Partial - shared libraries randomization only (1)" ;;
      2) print_success "ASLR: Full randomization (2)" ;;
      *) print_warning "ASLR: Unknown status (${aslr_status})" ;;
    esac
  else
    print_warning "ASLR: Status cannot be determined"
  fi
  
  # Check if ptrace protection is enabled
  if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
    case "$ptrace_scope" in
      0) print_critical "Ptrace protection: Disabled (0)" ;;
      1) print_success "Ptrace protection: Restricted (1)" ;;
      2) print_success "Ptrace protection: Admin-only (2)" ;;
      3) print_success "Ptrace protection: No ptrace (3)" ;;
      *) print_warning "Ptrace protection: Unknown status (${ptrace_scope})" ;;
    esac
  else
    print_warning "Ptrace protection: Not available"
  fi
  
  # Check if Exec Shield is enabled
  if [ -f /proc/sys/kernel/exec-shield ]; then
    exec_shield=$(cat /proc/sys/kernel/exec-shield)
    if [ "$exec_shield" -eq 1 ]; then
      print_success "Exec Shield: Enabled"
    else
      print_warning "Exec Shield: Disabled"
    fi
  fi
  
  # Check if the system has NX/DEP protection
  nx_dep=$(grep -i "nx\|pae" /proc/cpuinfo 2>/dev/null | sort -u)
  if [ -n "$nx_dep" ]; then
    print_success "NX/DEP: CPU supports NX/DEP protection"
  else
    print_warning "NX/DEP: CPU may not support NX/DEP protection"
  fi
}

# Main function to run all system info checks
system_info_checks() {
  print_title "System Information"
  
  # Run all system information checks
  check_os_version
  check_hardware_info
  check_filesystem_info
  check_kernel_modules
  check_system_startup
  check_system_security
  
  # Wait for user if wait mode is enabled
  wait_for_user
} 