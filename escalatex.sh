#!/bin/bash

#############################################################
#                                                           #
#  ███████╗███████╗ ██████╗ █████╗ ██╗      █████╗ ████████╗███████╗██╗  ██╗
#  ██╔════╝██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
#  █████╗  ███████╗██║     ███████║██║     ███████║   ██║   █████╗   ╚███╔╝ 
#  ██╔══╝  ╚════██║██║     ██╔══██║██║     ██╔══██║   ██║   ██╔══╝   ██╔██╗ 
#  ███████╗███████║╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗
#  ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
#                                                                           #
#  Advanced Privilege Escalation Scanner                                    #
#  https://github.com/reschjonas/EscalateX                                #
#                                                                           #
#############################################################

VERSION="1.1.0" # Updated version for HTML report feature
AUTHOR="Jonas Resch"
DISCLAIMER="This tool should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own risk on your own systems or with explicit permission."

# Cleanup function
cleanup() {
  echo -e "\n${YELLOW}[!] Interrupted! Cleaning up...${NC}" >&2
  # Kill any background processes that might be running
  jobs -p | xargs -r kill 2>/dev/null
  exit 1
}

# Set up trap for cleanup on interrupt
trap cleanup SIGINT SIGTERM

# Check if user is root
if ([ -f /usr/bin/id ] && [ "$(/usr/bin/id -u)" -eq "0" ]) || [ "`whoami 2>/dev/null`" = "root" ]; then
  IAMROOT="1"
  MAX_SEARCH_DEPTH="7"  # Increased depth for root users
else
  IAMROOT=""
  MAX_SEARCH_DEPTH="5"  # Standard depth for non-root users
fi

###########################################
#---------------) Colors (----------------#
###########################################

C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
MAGENTA="${C}[1;35m"
CYAN="${C}[1;36m"
WHITE="${C}[1;37m"
GRAY="${C}[1;90m"
BOLD="${C}[1m"
UNDERLINED="${C}[4m"
BLINK="${C}[5m"
REVERSE="${C}[7m"
NC="${C}[0m"

###########################################
#----------) Parsing Arguments (----------#
###########################################

# Default settings
THOROUGH=""           # Thorough scan (slower but more comprehensive)
EXTREME_SCAN=""       # Most aggressive scan (very slow but most comprehensive)
QUIET=""              # No banner or unnecessary output
CHECKS="all"          # All checks by default
TARGET_DIR="/"        # Default root directory to scan
WAIT=""               # Wait between major checks
PASSWORD=""           # Password for sudo/su attempts
NO_COLOR=""           # Disable colors
DEBUG=""              # Enable debug output
AUTO_NETWORK_SCAN=""  # Automatic network scanning (placeholder)
EXTENDED_CHECKS=""    # Additional extended checks (placeholder)
REGEX_SEARCH=""       # Enable regex pattern searches (placeholder)
MULTITHREADED="1"     # Enable multithreaded operations by default
USE_SUDO_PASS=""      # Whether to prompt for sudo password
THREADS=$(grep -c processor /proc/cpuinfo 2>/dev/null || echo 2)
[ -z "$THREADS" ] || ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [ "$THREADS" -lt 1 ] && THREADS=2 # Ensure threads is a number >= 1, default 2

print_banner() {
  if [ -z "$QUIET" ]; then
    echo ""
    echo -e "${GREEN}███████╗███████╗ ██████╗ █████╗ ██╗      █████╗ ████████╗███████╗██╗  ██╗${NC}"
    echo -e "${GREEN}██╔════╝██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝${NC}"
    echo -e "${GREEN}█████╗  ███████╗██║     ███████║██║     ███████║   ██║   █████╗   ╚███╔╝ ${NC}"
    echo -e "${GREEN}██╔══╝  ╚════██║██║     ██╔══██║██║     ██╔══██║   ██║   ██╔══╝   ██╔██╗ ${NC}"
    echo -e "${GREEN}███████╗███████║╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗${NC}"
    echo -e "${GREEN}╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝${NC}"
    echo ""
    echo -e "${BLUE}[*] EscalateX - Advanced Privilege Escalation Scanner${NC}"
    echo -e "${BLUE}[*] Version: ${WHITE}${VERSION}${NC}"
    echo -e "${BLUE}[*] Author: ${WHITE}${AUTHOR}${NC}"
    echo -e "${BLUE}[*] Running as: ${WHITE}$(whoami)${NC}"
    echo -e "${BLUE}[*] Started at: ${WHITE}$(date)${NC}"
    if [ "$IAMROOT" ]; then
      echo -e "${YELLOW}[!] You are already running as root. Privilege escalation might not be needed.${NC}"
    fi
    echo -e "${YELLOW}[!] ${DISCLAIMER}${NC}"
    echo ""
  fi
}

# Help message
show_help() {
  echo -e "${GREEN}EscalateX - Advanced Privilege Escalation Scanner${NC}"
  echo -e "${BLUE}Usage: ./escalatex.sh [OPTIONS]${NC}"
  echo ""
  echo -e "${GREEN}Scan Options:${NC}"
  echo -e "  ${YELLOW}-a, --all${NC}          Perform all checks (thorough mode)"
  echo -e "  ${YELLOW}-t, --thorough${NC}     Enable thorough scanning (slower but more comprehensive)"
  echo -e "  ${YELLOW}-x, --extreme${NC}      Enable extreme scanning (very slow but most comprehensive)"
  echo -e "  ${YELLOW}-o, --only CHECKS${NC}  Only execute specified checks (comma-separated list)"
  echo -e "              ${GRAY}Available: system_info, user_info, suid_sgid, writable_files, cron_jobs, docker, kernel, credentials, network, container_escape, sudo${NC}"
  echo -e "  ${YELLOW}-d, --dir PATH${NC}     Target directory to scan (default: /)"
  echo -e "  ${YELLOW}-m, --multi${NC}        Enable multithreaded scanning (default: $THREADS threads)"
  echo -e "  ${YELLOW}-s, --single${NC}       Disable multithreaded scanning"
  echo -e "  ${YELLOW}--threads N${NC}       Set number of threads for multithreaded mode (default: $THREADS)"
  # echo -e "  ${YELLOW}-r, --regex${NC}        Enable regex pattern searches (Placeholder)"
  echo -e ""
  echo -e "${GREEN}Output Options:${NC}"
  echo -e "  ${YELLOW}-q, --quiet${NC}        Quiet mode (no banner or info messages)"
  echo -e "  ${YELLOW}-n, --no-color${NC}     Disable colored output"
  echo -e "  ${YELLOW}-w, --wait${NC}         Wait between major checks (requires user input)"
  echo -e ""
  echo -e "${GREEN}Advanced Options:${NC}"
  # echo -e "  ${YELLOW}-N, --network${NC}      Automatic network scanning (Placeholder)"
  # echo -e "  ${YELLOW}-e, --extended${NC}     Perform extended checks (Placeholder)"
  echo -e "  ${YELLOW}-p, --password PWD${NC} Password for sudo/su attempts (use with caution)"
  echo -e "  ${YELLOW}-S, --sudo-pass${NC}    Prompt for sudo password for privilege escalation attempts"
  echo -e "  ${YELLOW}-D, --debug${NC}        Enable debug output (verbose)"
  echo -e "  ${YELLOW}-h, --help${NC}         Show this help message"
  echo -e "  ${YELLOW}-v, --version${NC}      Show version information"
  echo ""
  exit 0
}

# Process command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -a|--all) THOROUGH="1" ;; # No longer enables extended/regex by default
    -t|--thorough) THOROUGH="1" ;; 
    -x|--extreme) EXTREME_SCAN="1"; THOROUGH="1" ;; # Extreme implies thorough
    -o|--only) CHECKS="$2"; shift ;; 
    -d|--dir) TARGET_DIR="$2"; shift ;; 
    -q|--quiet) QUIET="1" ;; 
    -n|--no-color) NO_COLOR="1" ;; 
    -w|--wait) WAIT="1" ;; 
    -p|--password) PASSWORD="$2"; shift ;; 
    -S|--sudo-pass) USE_SUDO_PASS="1" ;; 
    -D|--debug) DEBUG="1" ;; 
    # -N|--network) AUTO_NETWORK_SCAN="1" ;; # Placeholder
    # -e|--extended) EXTENDED_CHECKS="1" ;; # Placeholder
    # -r|--regex) REGEX_SEARCH="1" ;; # Placeholder
    -m|--multi) MULTITHREADED="1" ;; 
    -s|--single) MULTITHREADED=""; THREADS=1 ;; 
    --threads) 
        if [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ]; then
            THREADS="$2"
        else
             echo -e "${RED}Error: --threads requires a positive integer.${NC}" >&2; exit 1
        fi
        shift ;; 
    -h|--help) show_help ;; 
    -v|--version) echo "EscalateX Version: $VERSION"; exit 0 ;; 
    *) echo -e "${RED}Error: Unknown option $1${NC}" >&2; show_help ;; 
  esac
  shift
done

# Apply color settings
if [ "$NO_COLOR" ]; then
  C=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; 
  WHITE=""; GRAY=""; BOLD=""; UNDERLINED=""; BLINK=""; REVERSE=""; NC=""
fi

# Validate target directory
if [ ! -d "$TARGET_DIR" ]; then
    echo -e "${RED}Error: Target directory '$TARGET_DIR' not found or is not a directory.${NC}" >&2
    exit 1
fi
print_debug "Target directory set to: $TARGET_DIR"

# Set thread count to 1 if single threaded mode is chosen
if [ -z "$MULTITHREADED" ]; then
    THREADS=1
fi
print_debug "Thread count set to: $THREADS"

# Check if the script is running from the correct directory
if [ ! -d "modules" ]; then
  echo -e "${RED}Error: The 'modules' directory was not found.${NC}" >&2
  echo -e "${YELLOW}Please run the script from the EscalateX base directory.${NC}" >&2
  exit 1
fi

# Check for required files
for required_file in "modules/loader.sh" "modules/utils/core.sh"; do
  if [ ! -f "$required_file" ]; then
    echo -e "${RED}Error: Required file '$required_file' not found.${NC}" >&2
    echo -e "${YELLOW}Please ensure all files are properly installed.${NC}" >&2
    exit 1
  fi
done

# Main function
main() {
  # Print banner unless quiet mode
  print_banner
  
  # Display disclaimer and require acceptance before proceeding (unless quiet)
  if [ -z "$QUIET" ]; then
    # Disclaimer already shown in banner
    # echo -e "${RED}DISCLAIMER:${NC}"
    # echo -e "${YELLOW}This tool should be used for authorized penetration testing and/or educational purposes only.${NC}"
    # echo -e "${YELLOW}Any misuse of this software will not be the responsibility of the author or of any other collaborator.${NC}"
    # echo -e "${YELLOW}Use it at your own risk on your own systems or with explicit permission.${NC}"
    # echo ""
    read -p "Do you understand and accept these terms? (y/n): " accept_disclaimer
    if [[ ! $accept_disclaimer =~ ^[Yy]$ ]]; then
      echo -e "${RED}Terms not accepted. Exiting.${NC}"
      exit 1
    fi
    echo ""
  fi
  
  # Ask for sudo password if enabled and not already provided via -p
  if [ "$USE_SUDO_PASS" ] && [ -z "$PASSWORD" ]; then
    echo -e "${BLUE}[*] Sudo privilege escalation attempts enabled.${NC}"
    read -s -p "Enter sudo password for $(whoami): " PASSWORD
    echo ""
    # Test if the password works (use -k to invalidate cached credentials first)
    if ! echo "$PASSWORD" | sudo -S -k true >/dev/null 2>&1; then
      echo -e "${RED}[!] Invalid sudo password or sudo access denied. Proceeding without sudo password.${NC}"
      PASSWORD="" # Clear the incorrect password
    else
      echo -e "${GREEN}[+] Sudo password verified.${NC}"
    fi
  elif [ -z "$USE_SUDO_PASS" ] && [ -z "$PASSWORD" ]; then
     if [ -z "$QUIET" ]; then # Only show if not quiet
        echo -e "${YELLOW}[!] Running without sudo password. Sudo-based checks will be limited.${NC}"
        echo -e "${YELLOW}[!] Use --sudo-pass to prompt or -p <password> to provide one.${NC}"
     fi
  fi
  
  # Load module loader
  if [ -f "modules/loader.sh" ]; then
    source modules/loader.sh
    
    # Initialize and run all modules via the loader's main function
    init_modules
  else
    echo -e "${RED}Error: Module loader (modules/loader.sh) not found. Cannot continue.${NC}" >&2
    exit 1
  fi
}

# Execute main function
main 