#!/bin/bash

# Title: User Information
# Description: Check users, their permissions, and related security
# Author: Jonas Resch

check_current_user() {
  print_subtitle "Current User Information"
  
  # Basic info about current user
  current_user=$(whoami 2>/dev/null)
  current_uid=$(id -u 2>/dev/null)
  current_gid=$(id -g 2>/dev/null)
  
  print_success "Current user: ${current_user} (UID: ${current_uid}, GID: ${current_gid})"
  
  # Check if we're root
  if [ "$IAMROOT" ]; then
    print_warning "You are running as root! No privilege escalation needed."
  fi
  
  # Groups for current user
  user_groups=$(id -G 2>/dev/null)
  user_groups_names=$(id -Gn 2>/dev/null)
  
  if [ -n "$user_groups_names" ]; then
    print_success "Groups: ${user_groups_names} (IDs: ${user_groups})"
    
    # Check if user is in interesting groups
    interesting_groups=("sudo" "admin" "wheel" "video" "docker" "lxd" "adm" "shadow" "disk" "root")
    
    for group in "${interesting_groups[@]}"; do
      if id -Gn 2>/dev/null | grep -qw "$group"; then
        print_critical "User is a member of the high-privilege '${group}' group!"
      fi
    done
  fi
  
  # Environment variables
  print_info "Environment Variables:"
  env_vars=$(env 2>/dev/null | grep -v "LS_COLORS" | sort)
  
  if [ -n "$env_vars" ]; then
    # Look for potentially interesting vars (password, token, key, etc.)
    sensitive_env=$(echo "$env_vars" | grep -i "key\|token\|pass\|secret\|cred\|auth" 2>/dev/null)
    
    if [ -n "$sensitive_env" ]; then
      print_warning "Potentially sensitive environment variables:"
      echo "$sensitive_env" | while read -r line; do
        print_warning " $line"
      done
    fi
    
    # Path variable (could be used for hijacking)
    path_var=$(echo "$env_vars" | grep "^PATH=" 2>/dev/null)
    if [ -n "$path_var" ]; then
      print_success "Path: $path_var"
      
      # Look for writable directories in PATH
      path_dirs=$(echo "$path_var" | sed 's/PATH=//g' | tr ':' '\n')
      
      echo "$path_dirs" | while read -r directory; do
        if [ -n "$directory" ] && [ -w "$directory" ]; then
          print_critical "Writable directory in PATH: $directory"
        elif [ -n "$directory" ] && [ ! -d "$directory" ]; then
          print_warning "Non-existent directory in PATH: $directory"
        fi
      done
    fi
  else
    print_not_found "No environment variables found"
  fi
  
  # Check sudo permissions
  print_info "Sudo access:"
  
  # Check if we have a password
  if [ -n "$PASSWORD" ]; then
    sudo_output=$(echo "$PASSWORD" | timeout 1 sudo -S -l 2>/dev/null)
    sudo_exit_code=$?
    
    if [ $sudo_exit_code -eq 0 ]; then
      # Remove password prompt from output
      sudo_output=$(echo "$sudo_output" | grep -v "password for")
      print_critical "User has sudo privileges! Sudo permissions:"
      echo "$sudo_output" | sed 's/^/    /'
    elif [ $sudo_exit_code -eq 1 ]; then
      print_warning "Incorrect sudo password provided"
    else
      print_success "User does not have sudo access (or requires a different password)"
    fi
  else
    # Try sudo without password
    sudo_nopass=$(sudo -l -n 2>/dev/null)
    sudo_nopass_exit=$?
    
    if [ $sudo_nopass_exit -eq 0 ]; then
      print_critical "User has sudo privileges without password! Sudo permissions:"
      echo "$sudo_nopass" | sed 's/^/    /'
    else
      print_success "User does not have passwordless sudo access"
    fi
  fi
}

check_all_users() {
  print_subtitle "All Users Information"
  
  # Get all users
  print_info "Users with console:"
  users_consoles=$(cat /etc/passwd 2>/dev/null | grep -v "^#" | grep -v "nologin\|false" | sort)
  
  if [ -n "$users_consoles" ]; then
    echo "$users_consoles" | while read -r user_line; do
      user_name=$(echo "$user_line" | cut -d: -f1)
      user_uid=$(echo "$user_line" | cut -d: -f3)
      user_gid=$(echo "$user_line" | cut -d: -f4)
      user_info=$(echo "$user_line" | cut -d: -f5)
      user_home=$(echo "$user_line" | cut -d: -f6)
      user_shell=$(echo "$user_line" | cut -d: -f7)
      
      # Highlight root accounts and service accounts
      if [ "$user_uid" -eq 0 ]; then
        print_critical " ${RED}${user_name}${NC} [UID: ${user_uid}] [GID: ${user_gid}] [Home: ${user_home}] [Shell: ${user_shell}]"
      elif [ "$user_uid" -lt 1000 ] && [ "$user_uid" -gt 0 ]; then
        print_success " ${YELLOW}${user_name}${NC} [UID: ${user_uid}] [GID: ${user_gid}] [Home: ${user_home}] [Shell: ${user_shell}]"
      else
        print_success " ${GREEN}${user_name}${NC} [UID: ${user_uid}] [GID: ${user_gid}] [Home: ${user_home}] [Shell: ${user_shell}]"
      fi
    done
  else
    print_not_found "No users with console found"
  fi
  
  # Users currently logged in
  print_info "Currently logged-in users:"
  current_logins=$(who 2>/dev/null)
  
  if [ -n "$current_logins" ]; then
    echo "$current_logins" | while read -r line; do
      print_success " $line"
    done
  else
    print_not_found "No currently logged-in users found"
  fi
  
  # Last logins
  print_info "Last logins:"
  last_logins=$(last -a 2>/dev/null | head -n 10)
  
  if [ -n "$last_logins" ]; then
    echo "$last_logins" | while read -r line; do
      print_success " $line"
    done
  else
    print_not_found "No login history found"
  fi
}

check_user_directories() {
  print_subtitle "User Directories and Permissions"
  
  # Check home directories
  print_info "Readable home directories:"
  
  for home_dir in /home/*; do
    if [ -d "$home_dir" ]; then
      user=$(basename "$home_dir")
      
      if [ -r "$home_dir" ]; then
        if [ -w "$home_dir" ]; then
          print_critical " ${RED}${user}${NC} [${home_dir}] - Directory is readable and writable!"
        else
          print_warning " ${YELLOW}${user}${NC} [${home_dir}] - Directory is readable"
        fi
        
        # Check for interesting files
        if [ "$THOROUGH" ]; then
          print_info "   Interesting files in ${user}'s home directory:"
          
          # SSH keys
          ssh_dir="$home_dir/.ssh"
          if [ -r "$ssh_dir" ]; then
            if [ -f "$ssh_dir/id_rsa" ]; then
              print_critical "    ${RED}Found SSH private key:${NC} $ssh_dir/id_rsa"
            fi
            if [ -f "$ssh_dir/id_dsa" ]; then
              print_critical "    ${RED}Found SSH private key:${NC} $ssh_dir/id_dsa"
            fi
            if [ -f "$ssh_dir/id_ecdsa" ]; then
              print_critical "    ${RED}Found SSH private key:${NC} $ssh_dir/id_ecdsa"
            fi
            if [ -f "$ssh_dir/id_ed25519" ]; then
              print_critical "    ${RED}Found SSH private key:${NC} $ssh_dir/id_ed25519"
            fi
            if [ -f "$ssh_dir/authorized_keys" ]; then
              print_warning "    ${YELLOW}Found SSH authorized_keys:${NC} $ssh_dir/authorized_keys"
            fi
          fi
          
          # History files
          for history_file in ".bash_history" ".zsh_history" ".mysql_history" ".python_history" ".psql_history" ".viminfo"; do
            if [ -r "$home_dir/$history_file" ]; then
              print_warning "    ${YELLOW}Found history file:${NC} $home_dir/$history_file"
            fi
          done
          
          # Config files
          for config_file in ".bashrc" ".bash_profile" ".profile" ".zshrc" ".zhsenv" ".vimrc" ".gitconfig"; do
            if [ -r "$home_dir/$config_file" ]; then
              print_warning "    ${BLUE}Found config file:${NC} $home_dir/$config_file"
            fi
          done
        fi
      fi
    fi
  done
  
  # Check mail directories
  if [ -d "/var/mail" ]; then
    print_info "Readable mail directories:"
    
    if [ -r "/var/mail" ]; then
      if [ -w "/var/mail" ]; then
        print_critical " /var/mail directory is readable and writable!"
      else
        print_warning " /var/mail directory is readable"
      fi
      
      for mail_file in /var/mail/*; do
        if [ -f "$mail_file" ]; then
          user=$(basename "$mail_file")
          
          if [ -r "$mail_file" ]; then
            if [ -w "$mail_file" ]; then
              print_critical "  ${RED}${user}${NC} mail file is readable and writable!"
            else
              print_warning "  ${YELLOW}${user}${NC} mail file is readable"
            fi
          fi
        fi
      done
    fi
  fi
}

check_password_policy() {
  print_subtitle "Password Policy"
  
  # Check for password aging
  print_info "Password aging policy:"
  
  if [ -f /etc/login.defs ]; then
    pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
    pass_warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
    
    if [ -n "$pass_max_days" ]; then
      if [ "$pass_max_days" -gt 90 ]; then
        print_warning " Maximum password age: ${YELLOW}${pass_max_days}${NC} days (should be 90 or less)"
      else
        print_success " Maximum password age: ${pass_max_days} days"
      fi
    fi
    
    if [ -n "$pass_min_days" ]; then
      if [ "$pass_min_days" -eq 0 ]; then
        print_warning " Minimum password age: ${YELLOW}${pass_min_days}${NC} days (should be greater than 0)"
      else
        print_success " Minimum password age: ${pass_min_days} days"
      fi
    fi
    
    if [ -n "$pass_warn_age" ]; then
      if [ "$pass_warn_age" -lt 7 ]; then
        print_warning " Password warning age: ${YELLOW}${pass_warn_age}${NC} days (should be 7 or more)"
      else
        print_success " Password warning age: ${pass_warn_age} days"
      fi
    fi
  else
    print_not_found "Password policy file not found"
  fi
  
  # Check for PAM password complexity
  print_info "Password complexity requirements:"
  
  if [ -f /etc/pam.d/common-password ]; then
    password_pam=$(grep -v '^#' /etc/pam.d/common-password)
    
    if echo "$password_pam" | grep -q "pam_pwquality.so\|pam_cracklib.so"; then
      print_success " Password complexity is enforced via PAM"
      
      # Check minimum length
      min_length=$(echo "$password_pam" | grep -o "minlen=[0-9]*" | cut -d= -f2)
      if [ -n "$min_length" ]; then
        if [ "$min_length" -lt 8 ]; then
          print_warning "  Minimum password length: ${YELLOW}${min_length}${NC} (should be 8 or more)"
        else
          print_success "  Minimum password length: ${min_length}"
        fi
      fi
      
      # Check if dictionary words are rejected
      if echo "$password_pam" | grep -q "reject_username\|dictcheck"; then
        print_success "  Dictionary words and usernames are rejected"
      else
        print_warning "  No explicit check for dictionary words"
      fi
    else
      print_warning " No password complexity requirements found"
    fi
  else
    print_not_found "PAM password configuration not found"
  fi
  
  # Check for accounts with empty passwords
  print_info "Accounts with empty passwords:"
  
  if [ -f /etc/shadow ]; then
    empty_passwords=$(grep -v ':\*:\|:!:' /etc/shadow | grep '::' 2>/dev/null)
    
    if [ -n "$empty_passwords" ]; then
      print_critical " Accounts with empty passwords found:"
      echo "$empty_passwords" | while read -r line; do
        user=$(echo "$line" | cut -d: -f1)
        print_critical "  ${RED}${user}${NC} has no password set!"
      done
    else
      print_success " No accounts with empty passwords"
    fi
  else
    print_warning " Cannot read shadow file to check for empty passwords"
  fi
}

check_sudo_permissions() {
  print_subtitle "Sudo Configuration"
  
  # Check if we have a custom sudoers file
  print_info "Custom sudoers files:"
  
  if [ -d /etc/sudoers.d ]; then
    custom_sudoers=$(ls -la /etc/sudoers.d/ 2>/dev/null)
    
    if [ -n "$custom_sudoers" ]; then
      echo "$custom_sudoers" | while read -r line; do
        print_success " $line"
      done
      
      # Check for NOPASSWD and interesting rules
      nopasswd_rules=$(grep -r "NOPASSWD" /etc/sudoers.d/ 2>/dev/null)
      
      if [ -n "$nopasswd_rules" ]; then
        print_warning " NOPASSWD rules found:"
        echo "$nopasswd_rules" | while read -r line; do
          print_warning "  $line"
        done
      fi
    else
      print_success " No custom sudoers files found"
    fi
  fi
  
  # Check main sudoers file
  print_info "Main sudoers file:"
  
  if [ -r /etc/sudoers ]; then
    sudoers=$(grep -v "^#\|^Defaults\|^$" /etc/sudoers 2>/dev/null)
    
    if [ -n "$sudoers" ]; then
      echo "$sudoers" | while read -r line; do
        # Highlight NOPASSWD entries
        if echo "$line" | grep -q "NOPASSWD"; then
          print_warning " ${YELLOW}${line}${NC}"
        else
          print_success " $line"
        fi
      done
    else
      print_not_found " No non-default entries in sudoers file"
    fi
  else
    print_warning " Cannot read sudoers file"
  fi
  
  # Check for sudo version (for vulnerabilities)
  print_info "Sudo version:"
  
  sudo_version=$(sudo -V 2>/dev/null | grep "Sudo version" | awk '{print $3}')
  
  if [ -n "$sudo_version" ]; then
    print_success " Sudo version: ${sudo_version}"
    
    # Check for sudo vulnerability CVE-2021-3156 (Baron Samedit)
    if version_greater_equal "1.8.30" "$sudo_version" && ! version_greater_equal "1.8.26" "$sudo_version"; then
      print_critical " ${RED}Potentially vulnerable to CVE-2021-3156 (Baron Samedit)${NC}"
    fi
    
    # Check for sudo vulnerability CVE-2019-14287 (runas user ID -1)
    if version_greater_equal "1.8.28" "$sudo_version" && ! version_greater_equal "1.8.1" "$sudo_version"; then
      print_critical " ${RED}Potentially vulnerable to CVE-2019-14287 (Negative user ID)${NC}"
    fi
  else
    print_warning " Sudo version could not be determined"
  fi
}

# Main function to run all user info checks
user_info_checks() {
  print_title "User Information"
  
  # Run all user information checks
  check_current_user
  check_all_users
  check_user_directories
  check_password_policy
  check_sudo_permissions
  
  # Wait for user if wait mode is enabled
  wait_for_user
} 