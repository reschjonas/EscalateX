#!/bin/bash

# Title: Network Information and Vulnerability Checker
# Description: Check for network misconfigurations and potential lateral movement vectors
# Author: Jonas Resch

check_network_interfaces() {
  print_subtitle "Network Interfaces"
  
  print_info "Checking network interfaces and configurations..."
  
  # Get all network interfaces
  if command_exists ip; then
    interfaces=$(ip -o link show | awk -F': ' '{print $2}')
    
    if [ -n "$interfaces" ]; then
      print_success "Found $(echo "$interfaces" | wc -l) network interfaces:"
      
      echo "$interfaces" | while read -r interface; do
        # Get IP address
        ip_addr=$(ip -o -4 addr show "$interface" 2>/dev/null | awk '{print $4}')
        ip_addr6=$(ip -o -6 addr show "$interface" 2>/dev/null | awk '{print $4}' | grep -v "fe80")
        
        # Get interface state
        state=$(ip -o link show "$interface" | awk '{print $9}')
        
        # Get MAC address
        mac=$(ip -o link show "$interface" | awk '{print $15}' | grep -E "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
        if [ -z "$mac" ]; then
          mac=$(ip -o link show "$interface" | awk '{print $17}' | grep -E "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
        fi
        
        # Print interface info
        if [ -n "$ip_addr" ]; then
          print_success " ${CYAN}$interface${NC}: $ip_addr [$state] [$mac]"
          
          # Check for internal IPs on external interfaces
          if [[ "$interface" =~ ^(eth|en|wl) ]] && [[ "$ip_addr" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
            print_warning "   ${YELLOW}→ Private IP detected on potentially external interface${NC}"
          fi
        elif [ -n "$ip_addr6" ]; then
          print_success " ${CYAN}$interface${NC}: $ip_addr6 [$state] [$mac]"
        else
          print_success " ${CYAN}$interface${NC}: No IPv4/IPv6 address [$state] [$mac]"
        fi
        
        # Check for promiscuous mode
        if ip -o link show "$interface" | grep -q "PROMISC"; then
          print_critical "   ${RED}→ Interface is in PROMISCUOUS mode! Possible network sniffing.${NC}"
        fi
      done
    else
      print_warning "No network interfaces found"
    fi
  elif command_exists ifconfig; then
    # Fallback to ifconfig
    interfaces=$(ifconfig | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}' | tr -d ':')
    
    if [ -n "$interfaces" ]; then
      print_success "Found $(echo "$interfaces" | wc -l) network interfaces:"
      
      echo "$interfaces" | while read -r interface; do
        # Get IP address
        ip_addr=$(ifconfig "$interface" | grep -oP 'inet addr:\K\S+' 2>/dev/null || ifconfig "$interface" | grep -oP 'inet\s+\K\S+' 2>/dev/null)
        ip_addr6=$(ifconfig "$interface" | grep -oP 'inet6 addr:\K\S+' 2>/dev/null || ifconfig "$interface" | grep -oP 'inet6\s+\K\S+' 2>/dev/null | grep -v "fe80")
        
        # Get MAC address
        mac=$(ifconfig "$interface" | grep -oP 'HWaddr\s+\K\S+' 2>/dev/null || ifconfig "$interface" | grep -oP 'ether\s+\K\S+' 2>/dev/null)
        
        # Print interface info
        if [ -n "$ip_addr" ]; then
          print_success " ${CYAN}$interface${NC}: $ip_addr [$mac]"
        elif [ -n "$ip_addr6" ]; then
          print_success " ${CYAN}$interface${NC}: $ip_addr6 [$mac]"
        else
          print_success " ${CYAN}$interface${NC}: No IPv4/IPv6 address [$mac]"
        fi
        
        # Check for promiscuous mode
        if ifconfig "$interface" | grep -q "PROMISC"; then
          print_critical "   ${RED}→ Interface is in PROMISCUOUS mode! Possible network sniffing.${NC}"
        fi
      done
    else
      print_warning "No network interfaces found"
    fi
  else
    print_warning "Neither ip nor ifconfig commands are available"
  fi
}

check_listening_ports() {
  print_subtitle "Listening Ports"
  
  print_info "Checking for open ports and listening services..."
  
  # Check using ss command (preferred)
  if command_exists ss; then
    # Get listening TCP ports
    tcp_ports=$(ss -tlnp 2>/dev/null | grep -v "*:*" | grep "LISTEN")
    
    if [ -n "$tcp_ports" ]; then
      print_success "TCP ports listening for connections:"
      
      echo "$tcp_ports" | grep -v "127.0.0.1" | while read -r line; do
        local_address=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' | cut -d"," -f1)
        
        # Identify public-facing services
        if echo "$local_address" | grep -qv "127.0.0.1\|::1"; then
          port=$(echo "$local_address" | awk -F: '{print $NF}')
          
          # Check for dangerous ports
          case "$port" in
            22) 
              print_critical " ${RED}SSH${NC} - ${RED}$local_address${NC} - $process"
              ;;
            445|139)
              print_critical " ${RED}SMB/Samba${NC} - ${RED}$local_address${NC} - $process"
              ;;
            3389)
              print_critical " ${RED}RDP${NC} - ${RED}$local_address${NC} - $process"
              ;;
            23)
              print_critical " ${RED}Telnet${NC} - ${RED}$local_address${NC} - $process"
              ;;
            *)
              print_warning " ${YELLOW}$local_address${NC} - $process"
              ;;
          esac
        else
          print_success " $local_address - $process"
        fi
      done
    else
      print_success "No TCP ports found listening for connections"
    fi
    
    # Get listening UDP ports
    udp_ports=$(ss -ulnp 2>/dev/null | grep -v "*:*")
    
    if [ -n "$udp_ports" ]; then
      print_success "UDP ports listening for connections:"
      
      echo "$udp_ports" | grep -v "127.0.0.1" | while read -r line; do
        local_address=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' | cut -d"," -f1)
        
        # Identify public-facing services
        if echo "$local_address" | grep -qv "127.0.0.1\|::1"; then
          port=$(echo "$local_address" | awk -F: '{print $NF}')
          
          # Check for dangerous ports
          case "$port" in
            53) 
              print_warning " ${YELLOW}DNS${NC} - ${YELLOW}$local_address${NC} - $process"
              ;;
            161)
              print_warning " ${YELLOW}SNMP${NC} - ${YELLOW}$local_address${NC} - $process"
              ;;
            69)
              print_warning " ${YELLOW}TFTP${NC} - ${YELLOW}$local_address${NC} - $process"
              ;;
            *)
              print_success " $local_address - $process"
              ;;
          esac
        else
          print_success " $local_address - $process"
        fi
      done
    else
      print_success "No UDP ports found listening for connections"
    fi
  # Fallback to netstat
  elif command_exists netstat; then
    # Get listening TCP ports
    tcp_ports=$(netstat -tlnp 2>/dev/null | grep "LISTEN")
    
    if [ -n "$tcp_ports" ]; then
      print_success "TCP ports listening for connections:"
      
      echo "$tcp_ports" | grep -v "127.0.0.1" | while read -r line; do
        local_address=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i}')
        
        # Identify public-facing services
        if echo "$local_address" | grep -qv "127.0.0.1\|::1"; then
          port=$(echo "$local_address" | awk -F: '{print $NF}')
          
          # Check for dangerous ports
          case "$port" in
            22) 
              print_critical " ${RED}SSH${NC} - ${RED}$local_address${NC} - $process"
              ;;
            445|139)
              print_critical " ${RED}SMB/Samba${NC} - ${RED}$local_address${NC} - $process"
              ;;
            3389)
              print_critical " ${RED}RDP${NC} - ${RED}$local_address${NC} - $process"
              ;;
            23)
              print_critical " ${RED}Telnet${NC} - ${RED}$local_address${NC} - $process"
              ;;
            *)
              print_warning " ${YELLOW}$local_address${NC} - $process"
              ;;
          esac
        else
          print_success " $local_address - $process"
        fi
      done
    else
      print_success "No TCP ports found listening for connections"
    fi
  else
    print_warning "Neither ss nor netstat commands are available"
  fi
}

check_iptables_rules() {
  print_subtitle "Firewall Rules"
  
  print_info "Checking firewall configuration..."
  
  # Check iptables firewall
  if command_exists iptables && [ "$IAMROOT" ]; then
    iptables_rules=$(iptables -L -n 2>/dev/null)
    
    if [ -n "$iptables_rules" ]; then
      print_success "iptables firewall rules:"
      
      # Check for default policies
      input_policy=$(iptables -L INPUT -n 2>/dev/null | head -n 1 | awk '{print $4}')
      forward_policy=$(iptables -L FORWARD -n 2>/dev/null | head -n 1 | awk '{print $4}')
      output_policy=$(iptables -L OUTPUT -n 2>/dev/null | head -n 1 | awk '{print $4}')
      
      # Print policies with appropriate colors
      if [ "$input_policy" = "ACCEPT" ]; then
        print_warning " ${YELLOW}INPUT chain policy: $input_policy${NC}"
      else
        print_success " INPUT chain policy: $input_policy"
      fi
      
      if [ "$forward_policy" = "ACCEPT" ]; then
        print_warning " ${YELLOW}FORWARD chain policy: $forward_policy${NC}"
      else
        print_success " FORWARD chain policy: $forward_policy"
      fi
      
      if [ "$output_policy" = "ACCEPT" ]; then
        print_success " OUTPUT chain policy: $output_policy"
      else
        print_warning " ${YELLOW}OUTPUT chain policy: $output_policy${NC}"
      fi
      
      # Check for any REJECT/DROP rules for incoming SSH (port 22)
      ssh_blocked=$(iptables -L INPUT -n 2>/dev/null | grep -E "REJECT|DROP" | grep -E "dpt:22|ssh")
      if [ -n "$ssh_blocked" ]; then
        print_success " SSH (port 22) appears to be blocked by firewall rules"
      elif [ "$input_policy" != "DROP" ] && [ "$input_policy" != "REJECT" ]; then
        print_warning " ${YELLOW}No specific rules to block SSH (port 22) were found${NC}"
      fi
      
      # Check for empty ruleset
      rule_count=$(iptables -L -n 2>/dev/null | grep -E "ACCEPT|REJECT|DROP" | wc -l)
      if [ "$rule_count" -lt 3 ]; then
        print_warning " ${YELLOW}Very few firewall rules detected ($rule_count). This might be insecure.${NC}"
      else
        print_success " Total rules: $rule_count"
      fi
    else
      print_warning "iptables is available but no rules were retrieved (might need root privileges)"
    fi
  elif command_exists ufw; then
    # Check UFW status
    ufw_status=$(ufw status 2>/dev/null)
    
    if [ -n "$ufw_status" ]; then
      print_success "UFW firewall status:"
      
      # Check if UFW is active
      if echo "$ufw_status" | grep -q "Status: active"; then
        print_success " UFW is active"
        
        # Print any open ports
        open_ports=$(echo "$ufw_status" | grep "ALLOW" | grep -v "(v6)")
        if [ -n "$open_ports" ]; then
          print_warning " ${YELLOW}Open ports:${NC}"
          echo "$open_ports" | while read -r line; do
            print_warning " ${YELLOW}→ $line${NC}"
            
            # Check for dangerous open ports
            if echo "$line" | grep -qE "22/tcp|23/tcp|3389/tcp|445/tcp"; then
              print_critical "   ${RED}→ Security critical port is open to incoming connections!${NC}"
            fi
          done
        else
          print_success " No open ports detected in UFW rules"
        fi
      else
        print_warning " ${YELLOW}UFW is installed but not active${NC}"
      fi
    else
      print_warning "UFW is available but no status was retrieved (might need root privileges)"
    fi
  elif command_exists firewall-cmd; then
    # Check firewalld status
    firewalld_status=$(firewall-cmd --state 2>/dev/null)
    
    if [ "$firewalld_status" = "running" ]; then
      print_success "firewalld is active"
      
      # Get default zone
      default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
      print_success " Default zone: $default_zone"
      
      # List open ports in default zone
      open_ports=$(firewall-cmd --zone="$default_zone" --list-ports 2>/dev/null)
      if [ -n "$open_ports" ]; then
        print_warning " ${YELLOW}Open ports in $default_zone zone:${NC}"
        
        # Check for dangerous open ports
        for port in $open_ports; do
          print_warning " ${YELLOW}→ $port${NC}"
          
          if [[ "$port" =~ ^(22|23|3389|445)/ ]]; then
            print_critical "   ${RED}→ Security critical port is open to incoming connections!${NC}"
          fi
        done
      else
        print_success " No open ports detected in $default_zone zone"
      fi
    else
      print_warning " ${YELLOW}firewalld is installed but not active${NC}"
    fi
  else
    print_warning "No supported firewall (iptables, ufw, firewalld) detected"
  fi
}

check_network_shares() {
  print_subtitle "Network Shares"
  
  print_info "Checking for shared network resources..."
  
  # Check for NFS exports
  if [ -f /etc/exports ]; then
    nfs_shares=$(grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$")
    
    if [ -n "$nfs_shares" ]; then
      print_warning "NFS shares exported to the network:"
      
      echo "$nfs_shares" | while read -r line; do
        print_warning " ${YELLOW}→ $line${NC}"
        
        # Check for dangerous NFS options
        if echo "$line" | grep -qE "no_root_squash|no_all_squash"; then
          print_critical "   ${RED}→ This NFS share has dangerous options (no_root_squash)!${NC}"
          print_critical "   ${RED}→ Remote root users can create files as root on this system.${NC}"
        fi
      done
    else
      print_success "No NFS shares found"
    fi
  fi
  
  # Check for Samba shares
  if [ -f /etc/samba/smb.conf ]; then
    samba_shares=$(grep -E "^\s*\[.*\]" /etc/samba/smb.conf 2>/dev/null | grep -v "\[global\]")
    
    if [ -n "$samba_shares" ]; then
      print_warning "Samba shares available on the network:"
      
      echo "$samba_shares" | while read -r line; do
        share_name=$(echo "$line" | tr -d '[]')
        print_warning " ${YELLOW}→ $share_name${NC}"
        
        # Get share path and permissions
        path=$(grep -A 20 "^\s*\[$share_name\]" /etc/samba/smb.conf | grep "path" | head -n 1 | awk -F= '{print $2}' | tr -d ' ')
        writable=$(grep -A 20 "^\s*\[$share_name\]" /etc/samba/smb.conf | grep -E "writable|writeable" | head -n 1)
        guest_ok=$(grep -A 20 "^\s*\[$share_name\]" /etc/samba/smb.conf | grep "guest ok" | head -n 1)
        
        if [ -n "$path" ]; then
          print_warning "   ${YELLOW}→ Path: $path${NC}"
          
          # Check for dangerous Samba configurations
          if echo "$writable" | grep -q "yes"; then
            print_warning "   ${YELLOW}→ Share is writable${NC}"
          fi
          
          if echo "$guest_ok" | grep -q "yes"; then
            print_critical "   ${RED}→ Guest access is allowed!${NC}"
          fi
        fi
      done
    else
      print_success "No Samba shares found"
    fi
  fi
  
  # Check for mounted network shares
  mounted_shares=$(mount | grep -E "nfs|cifs|smb")
  
  if [ -n "$mounted_shares" ]; then
    print_warning "Mounted network shares:"
    
    echo "$mounted_shares" | while read -r line; do
      print_warning " ${YELLOW}→ $line${NC}"
    done
  else
    print_success "No mounted network shares found"
  fi
}

check_network_credentials() {
  print_subtitle "Network Credentials"
  
  print_info "Checking for stored network credentials..."
  
  # Check for SSH keys
  if [ -d "$HOME/.ssh" ]; then
    ssh_files=$(find "$HOME/.ssh" -type f -name "id_*" 2>/dev/null)
    
    if [ -n "$ssh_files" ]; then
      print_warning "SSH keys found:"
      
      echo "$ssh_files" | while read -r key; do
        # Check key permissions
        key_perms=$(ls -la "$key" | awk '{print $1}')
        
        if [[ "$key_perms" =~ [g|o][r|w|x] ]]; then
          print_critical " ${RED}→ $key${NC} [$key_perms] (Bad permissions!)"
        else
          print_warning " ${YELLOW}→ $key${NC} [$key_perms]"
        fi
        
        # Check if key is encrypted
        if [[ "$key" != *.pub ]] && grep -q "ENCRYPTED" "$key" 2>/dev/null; then
          print_success "   → Key is encrypted with a passphrase"
        elif [[ "$key" != *.pub ]]; then
          print_critical "   ${RED}→ Key is NOT encrypted with a passphrase!${NC}"
        fi
      done
    else
      print_success "No SSH keys found"
    fi
  fi
  
  # Check SSH authorized_keys
  if [ -f "$HOME/.ssh/authorized_keys" ]; then
    authorized_keys=$(cat "$HOME/.ssh/authorized_keys" 2>/dev/null | grep -v "^#" | grep -v "^$")
    
    if [ -n "$authorized_keys" ]; then
      print_warning "SSH authorized_keys entries:"
      
      echo "$authorized_keys" | wc -l | xargs -I{} print_warning " ${YELLOW}→ {} keys found${NC}"
      
      # Check permissions
      auth_perms=$(ls -la "$HOME/.ssh/authorized_keys" | awk '{print $1}')
      if [[ "$auth_perms" =~ [g|o][r|w|x] ]]; then
        print_critical " ${RED}→ Bad permissions on authorized_keys file: $auth_perms${NC}"
      fi
    else
      print_success "No SSH authorized_keys entries found"
    fi
  fi
  
  # Check for .netrc file
  if [ -f "$HOME/.netrc" ]; then
    netrc_perms=$(ls -la "$HOME/.netrc" | awk '{print $1}')
    
    print_critical "${RED}→ .netrc file found: $HOME/.netrc${NC}"
    print_critical " ${RED}→ This file may contain cleartext credentials for FTP/remote services${NC}"
    
    if [[ "$netrc_perms" =~ [g|o][r|w|x] ]]; then
      print_critical " ${RED}→ Bad permissions: $netrc_perms${NC}"
    fi
  fi
  
  # Check for WPA/WiFi credentials
  if [ -d "/etc/NetworkManager/system-connections" ] && [ "$IAMROOT" ]; then
    wifi_conns=$(find /etc/NetworkManager/system-connections -type f 2>/dev/null)
    
    if [ -n "$wifi_conns" ]; then
      print_warning "WiFi connection profiles found:"
      
      echo "$wifi_conns" | while read -r conn; do
        ssid=$(grep -i "ssid=" "$conn" 2>/dev/null | cut -d= -f2)
        if [ -n "$ssid" ]; then
          print_warning " ${YELLOW}→ $conn${NC} (SSID: $ssid)"
          
          # Look for PSK
          if grep -i "psk=" "$conn" 2>/dev/null; then
            print_critical "   ${RED}→ Contains WiFi password!${NC}"
          fi
        fi
      done
    else
      print_success "No NetworkManager WiFi connections found"
    fi
  fi
}

check_potential_pivoting() {
  print_subtitle "Lateral Movement Potential"
  
  print_info "Checking for potential pivoting/lateral movement vectors..."
  
  # Check for hosts.equiv file
  if [ -f "/etc/hosts.equiv" ]; then
    hosts_equiv=$(cat "/etc/hosts.equiv" 2>/dev/null)
    
    if [ -n "$hosts_equiv" ]; then
      print_critical "${RED}hosts.equiv file found! This can allow remote logins without passwords:${NC}"
      
      echo "$hosts_equiv" | while read -r line; do
        print_critical " ${RED}→ $line${NC}"
      done
    fi
  fi
  
  # Check for .rhosts file
  rhosts_files=$(find / -name ".rhosts" 2>/dev/null)
  
  if [ -n "$rhosts_files" ]; then
    print_critical "${RED}.rhosts files found! These can allow remote logins without passwords:${NC}"
    
    echo "$rhosts_files" | while read -r file; do
      print_critical " ${RED}→ $file${NC}"
      
      if [ -r "$file" ]; then
        content=$(cat "$file" 2>/dev/null)
        if [ -n "$content" ]; then
          echo "$content" | while read -r line; do
            print_critical "   ${RED}→ $line${NC}"
          done
        fi
      fi
    done
  fi
  
  # Check for obviously shared SSH keys (same key on multiple systems)
  if [ -d "$HOME/.ssh" ]; then
    # Look for comments indicating shared keys
    shared_comments=$(find "$HOME/.ssh" -name "id_*" -exec grep -l "shared\|deploy\|ansible\|puppet\|automation" {} \; 2>/dev/null)
    
    if [ -n "$shared_comments" ]; then
      print_critical "${RED}Potentially shared SSH keys found:${NC}"
      
      echo "$shared_comments" | while read -r key; do
        print_critical " ${RED}→ $key${NC}"
        grep -i "shared\|deploy\|ansible\|puppet\|automation" "$key" | while read -r line; do
          print_critical "   ${RED}→ $line${NC}"
        done
      done
    fi
  fi
  
  # Check for pre-configured SSH hosts
  if [ -f "$HOME/.ssh/config" ]; then
    ssh_config=$(cat "$HOME/.ssh/config" 2>/dev/null)
    
    if [ -n "$ssh_config" ]; then
      print_warning "SSH client configuration found with potential pivot targets:"
      
      grep -i "^host " "$HOME/.ssh/config" | while read -r line; do
        print_warning " ${YELLOW}→ $line${NC}"
      done
    fi
  fi
  
  # Check for stored credentials in .ssh/known_hosts
  if [ -f "$HOME/.ssh/known_hosts" ]; then
    known_hosts_count=$(wc -l < "$HOME/.ssh/known_hosts")
    
    if [ "$known_hosts_count" -gt 0 ]; then
      print_warning "SSH known_hosts file contains $known_hosts_count entries"
      print_warning " ${YELLOW}→ These are potential lateral movement targets${NC}"
      
      # Check for non-hashed entries
      if grep -v "^|" "$HOME/.ssh/known_hosts" > /dev/null 2>&1; then
        print_critical " ${RED}→ known_hosts contains non-hashed entries that reveal hostnames/IPs${NC}"
        
        if [ "$THOROUGH" ]; then
          print_warning " ${YELLOW}→ Sample of reachable hosts:${NC}"
          grep -v "^|" "$HOME/.ssh/known_hosts" | cut -d" " -f1 | cut -d, -f1 | head -5 | while read -r host; do
            print_warning "   ${YELLOW}→ $host${NC}"
          done
        fi
      fi
    else
      print_success "No SSH known_hosts entries found"
    fi
  fi
}

# Main function to run all network checks
network_checks() {
  print_title "Network Information and Vulnerabilities"
  
  # Run all network security checks
  check_network_interfaces
  check_listening_ports
  check_iptables_rules
  check_network_shares
  check_network_credentials
  check_potential_pivoting
  
  # Wait for user if wait mode is enabled
  wait_for_user
} 