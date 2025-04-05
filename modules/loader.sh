#!/bin/bash

# Title: Module Loader
# Description: Load and initialize all modules for EscalateX
# Author: Jonas Resch

# Load core utilities
if [ ! -f "modules/utils/core.sh" ]; then
  echo "Error: Core utilities module not found!" >&2
  exit 1
fi

source modules/utils/core.sh

# Initialize the scan environment
initialize_scan() {
  print_debug "Initializing scan environment"
  
  # Initialize global variables first (needed for start time)
  init_globals

  # Check privileges
  check_privileges
  
  # Create a temp directory for scan data if needed
  if [ "$EXTREME_SCAN" ] || [ "$THOROUGH" ]; then
    TEMP_DIR=$(create_temp_dir)
    if [ -n "$TEMP_DIR" ]; then
      print_debug "Created temporary directory: $TEMP_DIR"
    else
      print_error "Failed to create temporary directory. Some checks might fail."
    fi
  fi
}

# Function to load a module with error handling
load_module() {
  local module_path="$1"
  local module_name="$2"
  
  if [ ! -f "$module_path" ]; then
    print_warning "Module not found: $module_path ($module_name)"
    # Define stub function to prevent errors if module is critical
    # Adjust as needed for other essential modules
    case "$module_name" in
        "System Information") system_info_checks() { print_error "System Info module missing!"; } ;; 
        "User Information") user_info_checks() { print_error "User Info module missing!"; } ;;
        "SUID/SGID Checker") suid_sgid_checks() { print_error "SUID/SGID module missing!"; } ;; 
        # Add stubs for other potentially critical modules if desired
    esac
    return 1
  fi
  
  print_debug "Loading module: $module_name ($module_path)"
  source "$module_path"
  
  if [ $? -ne 0 ]; then
    print_warning "Failed to load module: $module_name ($module_path)"
    return 1
  fi
  
  return 0
}

# Function to load all modules
load_modules() {
  # System information modules
  load_module "modules/system_info/general.sh" "System Information"
  
  # User information modules
  load_module "modules/user_info/users.sh" "User Information"
  
  # Exploit checking modules
  load_module "modules/exploit_checks/suid_sgid.sh" "SUID/SGID Checker"
  load_module "modules/exploit_checks/writable_files.sh" "Writable Files"
  load_module "modules/exploit_checks/cron_jobs.sh" "Cron Jobs"
  load_module "modules/exploit_checks/docker_checks.sh" "Docker Checks"
  load_module "modules/exploit_checks/kernel_exploits.sh" "Kernel Exploits"
  
  # Credentials module
  load_module "modules/credentials/credentials_hunter.sh" "Credentials Hunter"
  
  # Network module (optional?)
  if [ -f "modules/network_info/network_checks.sh" ]; then
    load_module "modules/network_info/network_checks.sh" "Network Checks"
  else
      print_debug "Optional module not found: modules/network_info/network_checks.sh"
      network_checks() { print_warning "Network checks module not available"; }
  fi

  # Conditionally load modules based on scan intensity
  local conditional_modules=()
  if [ "$THOROUGH" ] || [ "$EXTREME_SCAN" ]; then
    print_debug "Loading thorough scan modules"
    conditional_modules+=(
      "modules/container_checks/container_escape.sh:Container Escape Checks"
      "modules/exploit_checks/sudo_helper.sh:Sudo Helper Checks"
      # Add other thorough modules here if they exist
      # "modules/cloud_checks/aws_azure_gcp.sh:Cloud Environment"
      # "modules/kubernetes/kube_checks.sh:Kubernetes"
      # "modules/exploit_checks/dbus_checks.sh:D-Bus Checks"
      # "modules/exploit_checks/library_checks.sh:Library Checks"
    )
  fi

  if [ "$EXTREME_SCAN" ]; then
      print_debug "Loading extreme scan modules"
      conditional_modules+=(
          # Add extreme modules here if they exist
          # "modules/memory_checks/memory_analysis.sh:Memory Analysis"
          # "modules/exploit_checks/deep_search.sh:Deep Search Checks"
          # "modules/exploit_checks/binary_analysis.sh:Binary Analysis Checks"
      )
  fi

  for module_info in "${conditional_modules[@]}"; do
      IFS=':' read -r module_path module_name <<< "$module_info"
      if [ -f "$module_path" ]; then
          load_module "$module_path" "$module_name"
      else
          print_debug "Conditional module not found: $module_path"
          # Define stub functions based on module name pattern
          func_name=$(basename "$module_path" .sh | sed 's/_checks$//')_checks
          eval "${func_name}() { print_warning \"${module_name} module not available\"; }"
      fi
  done

  print_debug "Finished loading modules"
}

# Run the appropriate checks based on the options
run_checks() {
  # Welcome and initialization
  print_debug "Starting EscalateX scan"
  
  # Initialize (includes HTML header if enabled)
  initialize_scan

  # Load modules
  load_modules

  print_debug "Running selected checks..."

  # Run checks sequentially, allowing parallel execution within checks if enabled
  if [ "$CHECKS" = "all" ]; then
    # Basic/Core Checks
    system_info_checks
    user_info_checks
    suid_sgid_checks
    writable_files_checks
    cron_job_checks
    docker_environment_checks # Basic docker checks
    kernel_exploit_checks
    credentials_hunter_main
    
    # Network checks if available
    if command -v network_checks &>/dev/null; then network_checks; fi
    
    # Thorough Checks (run if function exists)
    if [ "$THOROUGH" ] || [ "$EXTREME_SCAN" ]; then
        if command -v container_escape_checks &>/dev/null; then container_escape_checks; fi
        if command -v sudo_helper_checks &>/dev/null; then sudo_helper_checks; fi
        # Add other thorough checks here
        # if command -v cloud_environment_checks &>/dev/null; then cloud_environment_checks; fi
        # if command -v kubernetes_checks &>/dev/null; then kubernetes_checks; fi
        # if command -v dbus_checks &>/dev/null; then dbus_checks; fi
        # if command -v library_checks &>/dev/null; then library_checks; fi
    fi
    
    # Extreme Checks (run if function exists)
    if [ "$EXTREME_SCAN" ]; then
        # Add extreme checks here
        # if command -v memory_analysis &>/dev/null; then memory_analysis; fi
        # if command -v deep_search_checks &>/dev/null; then deep_search_checks; fi
        # if command -v binary_analysis_checks &>/dev/null; then binary_analysis_checks; fi
        print_warning "Extreme scan checks are placeholders/not fully implemented."
    fi
    
  else
    # Run only selected checks
    IFS=',' read -ra selected_checks <<< "$CHECKS"
    print_info "Running only selected checks: ${selected_checks[*]}"
    
    for check in "${selected_checks[@]}"; do
      check=$(echo "$check" | tr -d '[:space:]')
      local func_name=""

      # Map check names to function names (adjust as needed)
      case "$check" in
          system_info) func_name="system_info_checks" ;; 
          user_info) func_name="user_info_checks" ;; 
          suid_sgid) func_name="suid_sgid_checks" ;; 
          writable_files) func_name="writable_files_checks" ;; 
          cron_jobs) func_name="cron_job_checks" ;; 
          docker) func_name="docker_environment_checks" ;; # Basic docker checks 
          kernel) func_name="kernel_exploit_checks" ;; 
          credentials) func_name="credentials_hunter_main" ;; 
          network) func_name="network_checks" ;; 
          container_escape) func_name="container_escape_checks" ;; # Specific escape checks
          sudo) func_name="sudo_helper_checks" ;; 
          # Add mappings for other check types 
          *) print_warning "Unknown or unavailable check requested: $check" ;; 
      esac
      
      # Check if the function exists and run it
      if [ -n "$func_name" ] && command -v "$func_name" &>/dev/null; then
        print_debug "Running specific check function: $func_name"
        eval "$func_name"
      elif [ -n "$func_name" ]; then
         print_warning "Check function '$func_name' for '$check' not found or module not loaded."
      fi
    done
  fi

  # Wait for any remaining background jobs if multithreaded
  wait_for_processes
  print_debug "All checks completed."
  
  # Cleanup temporary resources
  cleanup_resources
  
  # Print summary at the end
  print_summary
}

# Cleanup temporary resources
cleanup_resources() {
  if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
    print_debug "Cleaning up temporary directory: $TEMP_DIR"
    rm -rf "$TEMP_DIR"
  fi
}

# Generate a summary of findings
print_summary() {
  # Skip summary if quiet mode
  [ "$QUIET" ] && return

  print_title "Scan Summary"
  
  echo -e "${BLUE}[*] EscalateX scan completed at $(date)${NC}"
  
  # Calculate and show execution time
  END_TIME=$(date +%s)
  TOTAL_TIME=$((END_TIME - SCAN_START_TIME))
  local duration_str
  if [ "$TOTAL_TIME" -lt 60 ]; then
      duration_str="${TOTAL_TIME} seconds"
  elif [ "$TOTAL_TIME" -lt 3600 ]; then
      duration_str="$((TOTAL_TIME / 60)) minutes, $((TOTAL_TIME % 60)) seconds"
  else
       duration_str="$((TOTAL_TIME / 3600)) hours, $(((TOTAL_TIME % 3600) / 60)) minutes, $((TOTAL_TIME % 60)) seconds"
  fi
  echo -e "${BLUE}[*] Total execution time: ${WHITE}${duration_str}${NC}"
  
  # Show critical findings count
  if [ ${#CRITICAL_FINDINGS[@]} -gt 0 ]; then
    echo -e "${RED}[!] Critical findings detected: ${#CRITICAL_FINDINGS[@]}${NC}"
    echo -e "${RED}[!] Review the highlighted items in the scan results${NC}"
  else
    echo -e "${GREEN}[+] No critical findings detected${NC}"
  fi
  
  echo -e "${BLUE}[*] Remember to check the most promising privilege escalation vectors highlighted in ${RED}red${NC}"
  
  # Display a nice message
  echo -e "\n${GREEN}Thank you for using EscalateX!${NC}"
}

# Main initialization function
init_modules() {
  # Run the selected checks (this now includes initialization)
  run_checks
} 