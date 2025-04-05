#!/bin/bash

# Title: Core Utilities
# Description: Core utility functions for EscalateX
# Author: Jonas Resch

###########################################
#-----------) Display Utils (------------#
###########################################

# Print a major section title with a box
print_title() {
  # Skip if quiet mode
  [ "$QUIET" ] && return
  
  # Debug timer functionality
  if [ "$DEBUG" ]; then
    END_TIMER=$(date +%s 2>/dev/null)
    if [ "$START_TIMER" ]; then
      TOTAL_TIME=$(($END_TIMER - $START_TIMER))
      echo -e "${GRAY}[Debug] Previous section execution took $TOTAL_TIME seconds${NC}"
      echo ""
    fi
    START_TIMER=$(date +%s 2>/dev/null)
  fi

  title="$1"
  title_len=$(echo "$title" | wc -c)
  max_title_len=80
  rest_len=$((($max_title_len - $title_len) / 2))

  # Draw top border
  echo -e "${BLUE}"
  for i in $(seq 1 $rest_len); do printf " "; done
  printf "┏"
  for i in $(seq 1 $title_len); do printf "━"; done; printf "━";
  printf "┓"
  echo ""

  # Draw title with decorations
  for i in $(seq 1 $rest_len); do printf "━"; done
  printf "┫ ${GREEN}${title}${BLUE} ┣"
  for i in $(seq 1 $rest_len); do printf "━"; done
  echo ""

  # Draw bottom border
  for i in $(seq 1 $rest_len); do printf " "; done
  printf "┗"
  for i in $(seq 1 $title_len); do printf "━"; done; printf "━";
  printf "┛"
  echo -e "${NC}"
  echo ""
}

# Print a subsection title
print_subtitle() {
  # Skip if quiet mode
  [ "$QUIET" ] && return
  
  # Debug timer functionality  
  if [ "$DEBUG" ]; then
    SUB_END_TIMER=$(date +%s 2>/dev/null)
    if [ "$SUB_START_TIMER" ]; then
      SUB_TOTAL_TIME=$(($SUB_END_TIMER - $SUB_START_TIMER))
      echo -e "${GRAY}[Debug] Previous subsection execution took $SUB_TOTAL_TIME seconds${NC}"
      echo ""
    fi
    SUB_START_TIMER=$(date +%s 2>/dev/null)
  fi

  echo -e "${YELLOW}╔════════[ ${CYAN}$1${YELLOW} ]════════╗${NC}"
}

# Print informational message
print_info() {
  [ "$QUIET" ] && return
  echo -e "${BLUE}[*]${NC} $1"
}

# Print a successful result
print_success() {
  echo -e "${GREEN}[+]${NC} $1"
}

# Print warning message
print_warning() {
  echo -e "${YELLOW}[!]${NC} $1"
  # Add finding to the report
  save_to_report "WARNING" "$1" ""
}

# Print error message (treat as warning for reporting)
print_error() {
  echo -e "${RED}[-]${NC} $1" >&2
  # Add finding to the report as a warning
  save_to_report "WARNING" "Error: $1" ""
}

# Print critical finding (high severity issue)
print_critical() {
  echo -e "${RED}${BOLD}[CRITICAL]${NC} $1"
  # Add finding to the report
  save_to_report "CRITICAL" "$1" ""
}

# Print a check that hasn't found anything
print_not_found() {
  if [ "$THOROUGH" ] || [ "$EXTREME_SCAN" ]; then # Show only in detailed modes
    echo -e "${GRAY}[·]${NC} $1"
  fi
}

# Print debug info only when debug is enabled
print_debug() {
  if [ "$DEBUG" ]; then
    echo -e "${GRAY}[Debug]${NC} $1" >&2
  fi
}

# Wait for user input if wait mode is enabled
wait_for_user() {
  if [ "$WAIT" ]; then
    echo ""
    read -p "Press Enter to continue..."
    echo ""
  fi
}

###########################################
#-----------) Process Utils (------------#
###########################################

# Execute binary safely with error handling
exec_binary() {
  binary="$1"
  params="$2"
  
  if ! command -v "$binary" >/dev/null 2>&1; then
    print_debug "Binary not found: $binary"
    return 1
  fi
  
  output=$($binary $params 2>/dev/null)
  retval=$?
  
  if [ $retval -ne 0 ]; then
    print_debug "Error executing $binary (exit code: $retval)"
    return $retval
  fi
  
  echo "$output"
  return 0
}

# Run command with timeout
run_with_timeout() {
  timeout="$1"
  shift
  command="$@"
  
  # Use timeout command if available
  if command_exists timeout; then
      timeout $timeout $command 2>/dev/null
      return $?
  else
      print_debug "Timeout command not found, running without timeout: $command"
      $command
      return $?
  fi
}

# Execute a command in parallel if multithreading is enabled
exec_parallel() {
  cmd="$1"
  
  if [ "$MULTITHREADED" ]; then
    $cmd &
  else
    $cmd
  fi
}

# Wait for all background processes to finish
wait_for_processes() {
  if [ "$MULTITHREADED" ]; then
    wait
  fi
}

###########################################
#----------) File System Utils (---------#
###########################################

# Check if a path is readable
is_readable() {
  [ -r "$1" ] && return 0 || return 1
}

# Check if a path is writable
is_writable() {
  [ -w "$1" ] && return 0 || return 1
}

# Check if a path is executable
is_executable() {
  [ -x "$1" ] && return 0 || return 1
}

# Check if a path exists
path_exists() {
  [ -e "$1" ] && return 0 || return 1
}

# Check if a command exists in PATH
command_exists() {
  command -v "$1" >/dev/null 2>&1 && return 0 || return 1
}

# Create a temporary file securely
create_temp_file() {
  mktemp /tmp/escalatex.XXXXXX 2>/dev/null || mktemp -t escalatex.XXXXXX 2>/dev/null
}

# Create a temporary directory securely
create_temp_dir() {
  local temp_dir
  temp_dir=$(mktemp -d /tmp/escalatex.XXXXXX 2>/dev/null || mktemp -d -t escalatex.XXXXXX 2>/dev/null)
  echo "$temp_dir"
}

###########################################
#----------) Output Formatting (---------#
###########################################

# Format the output as JSON if JSON mode is enabled
format_json() {
  key="$1"
  value="$2"
  
  # Since JSON output is not implemented, just return the value
  # TODO: Implement proper JSON formatting if needed in future
  echo "$value"
}

# Format the current date and time
get_datetime() {
  date "+%Y-%m-%d %H:%M:%S"
}

# Format a file size to human-readable
format_size() {
  size="$1"
  local unit="B"

  if ! [[ "$size" =~ ^[0-9]+$ ]]; then
    echo "Invalid size"
    return 1
  fi

  if [ $size -gt 1073741824 ]; then # 1 GB
    size=$(awk -v s="$size" 'BEGIN {printf "%.1f", s/1073741824}')
    unit="GB"
  elif [ $size -gt 1048576 ]; then # 1 MB
    size=$(awk -v s="$size" 'BEGIN {printf "%.1f", s/1048576}')
    unit="MB"
  elif [ $size -gt 1024 ]; then # 1 KB
    size=$(awk -v s="$size" 'BEGIN {printf "%.1f", s/1024}')
    unit="KB"
  fi
  echo "$size $unit"
}

###########################################
#-----------) String Utils (-------------#
###########################################

# Remove ANSI color codes from string
strip_colors() {
  echo "$1" | sed 's/\x1b\[[0-9;]*m//g'
}

# Truncate a string to a maximum length
truncate_string() {
  str="$1"
  max_len="$2"
  
  if [ ${#str} -gt $max_len ]; then
    echo "${str:0:$max_len}..."
  else
    echo "$str"
  fi
}

# Hash a string using SHA256
hash_string() {
  if command_exists sha256sum; then
      echo -n "$1" | sha256sum | cut -d' ' -f1
  elif command_exists shasum; then
      echo -n "$1" | shasum -a 256 | cut -d' ' -f1
  else
      echo "Hashing_Tool_Not_Found"
  fi
}

# Encode a string to base64
encode_base64() {
  if command_exists base64; then
    echo -n "$1" | base64
  else
    echo "Base64_Tool_Not_Found"
  fi
}

###########################################
#------------) Network Utils (------------#
###########################################

# Check if host is reachable
is_host_up() {
  host="$1"
  if command_exists ping; then
    ping -c 1 -W 1 "$host" >/dev/null 2>&1
    return $?
  else
    print_debug "Ping command not found, cannot check host reachability."
    return 1 # Assume not reachable if ping doesn't exist
  fi
}

# Check if port is open
is_port_open() {
  host="$1"
  port="$2"
  # Use bash internal TCP check if possible
  timeout 1 bash -c "</dev/null >/dev/tcp/$host/$port" 2>/dev/null
  return $?
  # Fallback could use nc or nmap if available and necessary
}

# Get current external IP
get_external_ip() {
  # Try multiple services for redundancy
  if command_exists curl; then
    curl -s https://api.ipify.org 2>/dev/null || curl -s https://ifconfig.me 2>/dev/null || curl -s https://icanhazip.com 2>/dev/null || echo "Unknown"
  elif command_exists wget; then
    wget -qO- https://api.ipify.org 2>/dev/null || wget -qO- https://ifconfig.me 2>/dev/null || wget -qO- https://icanhazip.com 2>/dev/null || echo "Unknown"
  else
    echo "Unknown (curl/wget not found)"
  fi
}

###########################################
#------------) Version Utils (------------#
###########################################

# Compare version numbers (returns 0 if v1 >= v2)
version_greater_equal() {
  v1="$1"
  v2="$2"
  
  # Remove non-numeric characters and handle common suffixes like 'p'
  v1=$(echo "$v1" | sed -E 's/[^0-9.]//g')
  v2=$(echo "$v2" | sed -E 's/[^0-9.]//g')
  
  # Handle empty versions
  [ -z "$v1" ] && v1="0"
  [ -z "$v2" ] && v2="0"
  
  # Use sort -V if available for robust version comparison
  if command_exists sort && sort -V <<<$"1\n1" >/dev/null 2>&1; then
    lowest_version=$(printf "%s\n%s\n" "$v1" "$v2" | sort -V | head -n1)
    if [ "$lowest_version" = "$v2" ]; then
      return 0 # v1 is greater or equal to v2
    else
      return 1 # v1 is less than v2
    fi
  else
    # Fallback simple comparison (less accurate for complex versions)
    IFS=. read -r -a ver1 <<< "$v1"
    IFS=. read -r -a ver2 <<< "$v2"
    
    len1=${#ver1[@]}
    len2=${#ver2[@]}
    max_len=$(( len1 > len2 ? len1 : len2 ))

    for ((i=0; i<max_len; i++)); do
        # Pad with zero if version component doesn't exist
        c1=${ver1[i]:-0}
        c2=${ver2[i]:-0}

        # Ensure numeric comparison
        c1=$((10#$c1))
        c2=$((10#$c2))

        if (( c1 > c2 )); then return 0; fi
        if (( c1 < c2 )); then return 1; fi
    done
    return 0 # Versions are equal
  fi
}

# Function to sanitize user input for security
sanitize_input() {
  local input="$1"
  # Remove potentially malicious characters, allow common safe ones
  # Prevent path traversal (..) and limit characters
  echo "$input" | sed -e 's/[^[:alnum:][:space:].,_\/-]//g' -e 's/\.\.\///g' -e 's/\/\.\.//g'
}

# Advanced error handling 
handle_error() {
  local exit_code=$1
  local error_message=$2
  
  if [ $exit_code -ne 0 ]; then
    print_warning "Operation failed: $error_message (Code: $exit_code)"
    return 1
  fi
  return 0
}

# Execute command safely with timeout
safe_exec() {
  local cmd="$1"
  local timeout_seconds="${2:-10}"  # Default 10 seconds
  
  run_with_timeout "$timeout_seconds" "$cmd"
  local exit_code=$?
  if [ $exit_code -eq 124 ]; then
      print_debug "Command timed out ($timeout_seconds s): $cmd"
      return 124
  elif [ $exit_code -ne 0 ]; then
      print_debug "Command failed (exit code $exit_code): $cmd"
      return $exit_code
  fi
  return 0
}

# Check if running with sufficient privileges for the requested scan
check_privileges() {
  # If not root and thorough scan requested, warn user
  if [ -z "$IAMROOT" ] && ( [ "$THOROUGH" ] || [ "$EXTREME_SCAN" ] ); then
    print_warning "Running thorough/extreme scan without root privileges. Some checks may be limited."
    if [ -z "$PASSWORD" ] && [ -z "$USE_SUDO_PASS" ]; then
        print_warning "Consider running with sudo or using --password/--sudo-pass for more comprehensive results."
    fi
  fi
  
  # If extreme scan requested without root, warn strongly
  if [ -z "$IAMROOT" ] && [ "$EXTREME_SCAN" ] && [ -z "$QUIET" ] ; then
    print_critical "Extreme scan mode works best with root privileges!"
    print_critical "Many checks will be limited or may fail."
    read -p "Do you want to continue anyway? (y/n): " response
    if [[ ! $response =~ ^[Yy]$ ]]; then
      print_info "Scan aborted. Re-run with sudo or required privileges for best results."
      exit 0
    fi
  fi
}

# Run commands in parallel if multithreaded mode is enabled
parallel_exec() {
  local cmd="$1"
  
  if [ "$MULTITHREADED" ] && [ "$THREADS" -gt 1 ]; then
    # Run in background
    eval "$cmd" &
    
    # If we have too many processes, wait for one to finish
    while [ "$(jobs -p | wc -l)" -ge "$THREADS" ]; do
      wait -n 2>/dev/null || sleep 0.1 # Wait for any job or sleep briefly
    done
  else
    # Run sequentially
    eval "$cmd"
  fi
}

# Save findings to a report file/array
save_to_report() {
  local severity="$1"
  local message="$2"
  local details="${3:-}" # Optional details
  local timestamp
  
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  
  # Strip any ANSI color codes from message
  message=$(strip_colors "$message")
  details=$(strip_colors "$details")
  
  # Escape pipe characters in message and details to avoid breaking the format
  message=$(echo "$message" | sed 's/|/\PIPE/g')
  details=$(echo "$details" | sed 's/|/\PIPE/g')

  # Add to the findings array for later reporting
  FINDINGS+=("$timestamp|$severity|$message|$details")
  
  # If critical finding, add to critical findings list (only the message)
  if [ "$severity" = "CRITICAL" ]; then
    CRITICAL_FINDINGS+=("$message")
  fi
}

# Initialize key global variables
init_globals() {
  # Initialize findings arrays
  FINDINGS=()
  CRITICAL_FINDINGS=()
  
  # Track scan start time for performance metrics
  SCAN_START_TIME=$(date +%s)
}

# Run a command with sudo using the stored password if available
run_with_sudo() {
  local cmd="$1"
  
  if [ -n "$PASSWORD" ]; then
    # Use the password with sudo
    echo "$PASSWORD" | sudo -S $cmd 2>/dev/null
    return $?
  elif [ "$USE_SUDO_PASS" ]; then
    # If --sudo-pass was used but no password given/worked, prompt?
    # For now, just try without password if USE_SUDO_PASS is set but PASSWORD is empty
     sudo -n $cmd 2>/dev/null
     return $?
  else
    # Try without password (non-interactive, only works if sudoers allows)
    sudo -n $cmd 2>/dev/null
    return $?
  fi
} 