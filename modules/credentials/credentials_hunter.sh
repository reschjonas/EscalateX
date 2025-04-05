#!/bin/bash

# Title: Credentials Hunter
# Description: Search for passwords, API keys, and sensitive information throughout the system
# Author: Jonas Resch

# Define credential patterns with improved accuracy
# Format: "name|regex_pattern|context_lines|critical"
CREDENTIAL_PATTERNS=(
  "AWS Access Key|AKIA[0-9A-Z]{16}|2|1"
  "AWS Secret Key|[0-9a-zA-Z/+]{40}|2|1"
  "SSH Private Key|-----BEGIN( RSA| OPENSSH| DSA| EC)?\\s?PRIVATE KEY|5|1"
  "PGP Private Key|-----BEGIN PGP PRIVATE|5|1"
  "Google API Key|AIza[0-9A-Za-z_-]{35}|2|1"
  "Google OAuth|[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com|2|1"
  "Slack Token|xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}|2|1"
  "GitHub Token|gh[ps]_[0-9a-zA-Z]{36}|2|1"
  "Basic Auth|Authorization:\\s*Basic\\s+[a-zA-Z0-9+/=]{5,100}|2|1"
  "Bearer Token|Authorization:\\s*Bearer\\s+[a-zA-Z0-9_\\.-]+|2|1"
  "API Key|['\"](api[_-]?key|apikey)['\"]:?\\s*['\"]((?!placeholder|example|your-api-key)[a-zA-Z0-9_\\.-]{10,64})['\"]|2|1"
  "MongoDB Connection|mongodb(\\+srv)?://[^@]+@[a-zA-Z0-9.-]+|3|1"
  "JWT Token|eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}|2|1"
  "Firebase URL|https?://[a-zA-Z0-9-]+\\.firebaseio\\.com|2|1"
  "Azure Storage Key|DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{40,}|2|1"
  "Private Key File|\\.(key|pem|ppk|p12|pfx|jks|keystore)$|0|1"
)

# List of common credential file locations - prioritized and more specific
CREDENTIAL_FILES=(
  "/etc/shadow"
  "/etc/passwd"
  "/etc/sudoers"
  "/etc/sudoers.d/*"
  "/root/.ssh/id_*"
  "/root/.aws/credentials"
  "/root/.aws/config"
  "/home/*/.ssh/id_*"
  "/home/*/.ssh/authorized_keys"
  "/home/*/.aws/credentials"
  "/home/*/.aws/config"
  "/home/*/.git-credentials"
  "/home/*/.docker/config.json"
  "/home/*/.kube/config"
  "/home/*/.terraform.d/credentials*"
  "/var/www/*/.env"
  "/var/www/*/wp-config.php"
  "/var/www/*/config.php"
  "/var/lib/jenkins/credentials.xml"
  "/var/lib/jenkins/secrets/master.key"
  "/docker-compose*.y*ml"
  "/.env"
  "./*.env"
  "/tmp/testcreds.sh"       # Added for testing
  "/tmp/*.sh"               # Added for testing
)

# Excluded paths for credential searches
EXCLUDED_PATHS=(
  "/usr/share"
  "/usr/lib"
  "/lib"
  "/lib64"
  "/var/lib"
  "/var/cache"
  "/var/log"
  "/.cursor"
  "/.local/share/Trash"
  "/.cache"
  "/.config/google-chrome"
  "/.config/chromium"
  "/.config/BraveSoftware"
  "/.mozilla"
  "/EscalateX"
  "/proc"
  "/sys"
  "/run"
  "/dev"
  "/var/tmp"
  "/tmp"
  "node_modules"
  "venv"
  ".venv"
  "__pycache__"
  ".npm"
  ".gradle"
  ".m2"
)

# File size threshold in bytes (1MB)
MAX_FILE_SIZE=1048576

# Build excluded paths argument for find command
build_exclusion_args() {
  local excl_args=""
  for path in "${EXCLUDED_PATHS[@]}"; do
    excl_args="$excl_args -path \"*$path*\" -o "
  done
  # Remove the trailing "-o " and add "-prune -o " at the end
  excl_args=$(echo "$excl_args" | sed 's/ -o $//g')
  echo "$excl_args -prune -o"
}

# Function to mask sensitive data
mask_sensitive_data() {
  local input="$1"
  # Mask passwords, keys, tokens while preserving variable names
  echo "$input" | sed -E 's/(password|token|secret|key|credentials)[=:]["'"'"']?([^"'"'"' :]+)/\1=********/gi'
}

# Scan for files containing credentials
check_credential_files() {
  print_subtitle "Critical Credential Files"
  
  print_info "Scanning for sensitive credential files..."
  
  # Process each file pattern from CREDENTIAL_FILES
  for file_pattern in "${CREDENTIAL_FILES[@]}"; do
    # Handle wildcard patterns
    if [[ "$file_pattern" == *"*"* ]]; then
      # Use eval to properly expand the glob pattern
      eval "files=($file_pattern)"
      for file in "${files[@]}"; do
        if [ -f "$file" ] && [ -r "$file" ]; then
          check_credential_file "$file"
        fi
      done
    else
      # Regular file
      if [ -f "$file_pattern" ] && [ -r "$file_pattern" ]; then
        check_credential_file "$file_pattern"
      fi
    fi
  done
}

# Helper function to check a single credential file
check_credential_file() {
  local file="$1"
  
  # Skip if file is too large
  local file_size=$(stat -c%s "$file" 2>/dev/null || echo "0")
  if [ "$file_size" -gt "$MAX_FILE_SIZE" ]; then
    print_warning "Skipping large file: $file ($(( file_size / 1024 )) KB)"
    return
  fi
  
  # Skip binary files
  if file "$file" | grep -q "binary"; then
    return
  fi
  
  # Analyze file based on its type
  case "$file" in
    *"/shadow")
      print_critical "Found shadow password file: ${RED}$file${NC}"
      grep -v '^[^:]*:[*!]' "$file" 2>/dev/null | head -n 5 | grep ":" | while read -r line; do
        user=$(echo "$line" | cut -d: -f1)
        print_critical "  ${RED}→ User '$user' has password hash${NC}"
      done
      ;;
    
    *"/id_rsa"|*"/id_dsa"|*"/id_ecdsa"|*"/id_ed25519")
      print_critical "Found SSH private key: ${RED}$file${NC}"
      local key_header=$(head -n 1 "$file" 2>/dev/null)
      local key_owner=$(stat -c "%U" "$file" 2>/dev/null)
      print_critical "  ${RED}→ Type: $key_header${NC}"
      print_critical "  ${RED}→ Owner: $key_owner${NC}"
      print_critical "  ${RED}→ Permissions: $(stat -c "%a" "$file" 2>/dev/null)${NC}"
      ;;
    
    *"/aws/credentials"|*"/.aws/config")
      print_critical "Found AWS credentials: ${RED}$file${NC}"
      grep -A 2 -B 1 "aws_" "$file" 2>/dev/null | grep -v "^--$" | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_critical "  ${RED}→ $masked_line${NC}"
      done
      ;;
    
    *"/.kube/config")
      print_critical "Found Kubernetes config: ${RED}$file${NC}"
      grep -A 1 "token:" "$file" 2>/dev/null | grep -v "^--$" | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_critical "  ${RED}→ $masked_line${NC}"
      done
      ;;
    
    *"wp-config.php"|*"config.php")
      print_critical "Found PHP configuration with credentials: ${RED}$file${NC}"
      grep -E "(DB_PASSWORD|password|NONCE|SALT|KEY)" "$file" 2>/dev/null | grep -v "//" | head -n 5 | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_critical "  ${RED}→ $masked_line${NC}"
      done
      ;;
    
    *"/.env"|*"docker-compose"*)
      print_critical "Found environment file with credentials: ${RED}$file${NC}"
      grep -E "(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)" "$file" 2>/dev/null | grep -v "^#" | head -n 5 | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_critical "  ${RED}→ $masked_line${NC}"
      done
      ;;
    
    "/tmp/testcreds.sh"|*"/tmp/*.sh")
      # Special handling for our test file or other scripts
      if grep -q -E "AWS_|TOKEN|SECRET|PASSWORD|CREDENTIAL" "$file" 2>/dev/null; then
        print_critical "Found credentials in shell script: ${RED}$file${NC}"
        grep -E "AWS_|TOKEN|SECRET|PASSWORD|CREDENTIAL" "$file" 2>/dev/null | while read -r line; do
          masked_line=$(mask_sensitive_data "$line")
          print_critical "  ${RED}→ $masked_line${NC}"
        done
      fi
      ;;
    
    *)
      # Generic sensitive file detection
      print_warning "Found potential credential file: ${YELLOW}$file${NC}"
      grep -E "(password|secret|token|key|credential|user|login)" "$file" 2>/dev/null | grep -v "^#" | head -n 3 | while read -r line; do
        masked_line=$(mask_sensitive_data "$line")
        print_warning "  ${YELLOW}→ $masked_line${NC}"
      done
      ;;
  esac
}

# Scan for credentials in history files
check_history_files() {
  print_subtitle "Shell History Analysis"
  
  print_info "Checking shell history files for credentials..."
  
  # History files to check
  local history_files=(
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
    "$HOME/.history"
    "$HOME/.mysql_history"
    "$HOME/.psql_history"
  )
  
  # Strong patterns for credential commands - more specific to reduce false positives
  local history_patterns=(
    "[-][-]password=[^ ]+"
    "curl.*[-]u .*:.*"
    "wget.*[-][-]password=[^ ]+"
    "mysql .*[-]p[a-zA-Z0-9]+"
    "psql .*[-]W.*password"
    "sshpass [-]p [^ ]+"
    "git clone https://[^@]+:[^@]+@"
    "git push https://[^@]+:[^@]+@"
    "export +[A-Z_]*TOKEN=[^ ]+"
    "export +[A-Z_]*SECRET=[^ ]+"
    "export +[A-Z_]*PASSWORD=[^ ]+"
    "export +[A-Z_]*KEY=[^ ]+"
    "aws configure set aws_access_key_id"
    "aws configure set aws_secret_access_key"
    "aws .* --secret"
    "openssl .* -pass"
    "heroku auth:token"
    "gh auth login"
    "htpasswd [-]b .* [^ ]+"
  )
  
  # List of patterns to exclude as false positives
  local false_positive_patterns=(
    "github.com/[^:]+$"
    "gitlab.com/[^:]+$"
    "bitbucket.org/[^:]+$"
    "password-stdin"
    "echo.*password"
    "password="
    "SECRET=dummy"
  )
  
  for file in "${history_files[@]}"; do
    if [ -r "$file" ]; then
      print_warning "Found history file: ${YELLOW}$file${NC}"
      
      # Build regex pattern for grep
      local pattern=$(echo "${history_patterns[@]}" | tr ' ' '|')
      
      # Find matching lines
      found_creds=0
      grep -n -E "$pattern" "$file" 2>/dev/null | head -n 20 | while read -r line; do
        line_num=${line%%:*}
        line_content=${line#*:}
        
        # Skip if line is too short or just a command name
        if [ ${#line_content} -lt 10 ] || echo "$line_content" | grep -qE "^(curl|wget|mysql|psql|ssh|git)$"; then
          continue
        fi
        
        # Check for false positives
        is_false_positive=0
        for fp in "${false_positive_patterns[@]}"; do
          if echo "$line_content" | grep -q "$fp"; then
            is_false_positive=1
            break
          fi
        done
        
        # Skip basic git clones without credentials
        if echo "$line_content" | grep -qE "^git clone https://github.com/|^git clone https://gitlab.com/"; then
          # Only skip if it doesn't have credentials in the URL
          if ! echo "$line_content" | grep -qE "@github.com|@gitlab.com"; then
            is_false_positive=1
          fi
        fi
        
        if [ $is_false_positive -eq 0 ]; then
          # Check if command looks like it has sensitive data
          if echo "$line_content" | grep -qiE "(password|token|secret|key|pass|cred|auth|login)"; then
            # Mask sensitive information
            masked_line=$(mask_sensitive_data "$line_content")
            print_warning "Found credential command in history (line $line_num): ${YELLOW}$masked_line${NC}"
            found_creds=1
          elif echo "$line_content" | grep -qE -- "-p[^ ]|--password="; then
            # Commands with password params
            masked_line=$(mask_sensitive_data "$line_content")
            print_warning "Found credential command in history (line $line_num): ${YELLOW}$masked_line${NC}"
            found_creds=1
          fi
        fi
      done
      
      # Check if any real credentials were found
      if [ $found_creds -eq 0 ]; then
        print_success "No obvious credentials found in history file."
      fi
    fi
  done
}

# Scan for database credentials
check_db_credentials() {
  print_subtitle "Database Credentials"
  
  print_info "Searching for database credentials..."
  
  # Check for MySQL credentials in common locations
  local mysql_conf_files=(
    "/etc/mysql/my.cnf"
    "/etc/my.cnf"
    "$HOME/.my.cnf"
    "/var/www/*/.my.cnf"
  )
  
  for pattern in "${mysql_conf_files[@]}"; do
    # Handle wildcard patterns
    if [[ "$pattern" == *"*"* ]]; then
      eval "files=($pattern)"
      for file in "${files[@]}"; do
        if [ -f "$file" ] && [ -r "$file" ]; then
          print_warning "Found MySQL configuration: ${YELLOW}$file${NC}"
          grep -E "^[[:space:]]*(user|password|host)" "$file" 2>/dev/null | grep -v "^#" | while read -r line; do
            masked_line=$(mask_sensitive_data "$line")
            print_critical "  ${RED}→ $masked_line${NC}"
          done
        fi
      done
    else
      if [ -f "$pattern" ] && [ -r "$pattern" ]; then
        print_warning "Found MySQL configuration: ${YELLOW}$pattern${NC}"
        grep -E "^[[:space:]]*(user|password|host)" "$pattern" 2>/dev/null | grep -v "^#" | while read -r line; do
          masked_line=$(mask_sensitive_data "$line")
          print_critical "  ${RED}→ $masked_line${NC}"
        done
      fi
    fi
  done
  
  # PostgreSQL credentials
  local pgpass_files=(
    "/var/lib/pgsql/.pgpass"
    "/var/lib/postgresql/.pgpass"
    "$HOME/.pgpass"
  )
  
  for file in "${pgpass_files[@]}"; do
    if [ -f "$file" ] && [ -r "$file" ]; then
      print_critical "Found PostgreSQL password file: ${RED}$file${NC}"
      cat "$file" 2>/dev/null | head -n 5 | while read -r line; do
        # Format: hostname:port:database:username:password
        # Only display hostname, database and username, mask the password
        if [ -n "$line" ] && [[ "$line" == *":"* ]]; then
          host=$(echo "$line" | cut -d: -f1)
          db=$(echo "$line" | cut -d: -f3)
          user=$(echo "$line" | cut -d: -f4)
          print_critical "  ${RED}→ Host: $host, DB: $db, User: $user, Password: ********${NC}"
        else
          print_critical "  ${RED}→ $line${NC}"
        fi
      done
    fi
  done
  
  # MongoDB credentials
  find "/etc" -maxdepth 2 -name "mongodb*.conf" 2>/dev/null | while read -r file; do
    if [ -r "$file" ]; then
      print_warning "Found MongoDB configuration: ${YELLOW}$file${NC}"
      grep -E "^[[:space:]]*(auth|security.authorization|setParameter.authenticationMechanisms)" "$file" 2>/dev/null | while read -r line; do
        print_warning "  ${YELLOW}→ $line${NC}"
      done
    fi
  done
}

# Scan for cloud credentials
check_cloud_credentials() {
  print_subtitle "Cloud Service Credentials"
  
  print_info "Searching for cloud service credentials..."
  
  # AWS credentials
  if [ -d "$HOME/.aws" ]; then
    aws_files=$(find "$HOME/.aws" -type f -name "credentials" -o -name "config" 2>/dev/null)
    if [ -n "$aws_files" ]; then
      print_critical "Found AWS credential files:"
      echo "$aws_files" | while read -r file; do
        if [ -r "$file" ]; then
          print_critical "  ${RED}→ $file${NC}"
          # Look for profiles
          grep -E "^\[" "$file" 2>/dev/null | while read -r profile; do
            print_critical "    ${RED}→ Profile: $profile${NC}"
          done
          # Look for access keys (only show partially masked)
          if grep -q "aws_access_key_id" "$file" 2>/dev/null; then
            access_keys=$(grep -E "aws_access_key_id" "$file" 2>/dev/null | sed -E 's/.*aws_access_key_id[[:space:]]*=[[:space:]]*([A-Z0-9]+).*/\1/')
            for key in $access_keys; do
              # Show first 4 and last 4 characters, mask the middle
              if [ ${#key} -gt 8 ]; then
                start=${key:0:4}
                end=${key: -4}
                masked="${start}****${end}"
                print_critical "    ${RED}→ Access Key: ${masked}${NC}"
              fi
            done
          fi
        fi
      done
    else
      print_success "AWS credentials directory exists but no credential files found."
    fi
  else
    print_success "No AWS credentials directory found."
  fi
  
  # GCP credentials
  if [ -d "$HOME/.config/gcloud" ]; then
    gcp_files=$(find "$HOME/.config/gcloud" -type f -name "application_default_credentials.json" -o -name "legacy_credentials" -o -name "*adc.json" 2>/dev/null)
    if [ -n "$gcp_files" ]; then
      print_critical "Found Google Cloud credential files:"
      echo "$gcp_files" | while read -r file; do
        if [ -r "$file" ]; then
          print_critical "  ${RED}→ $file${NC}"
          # Check if it contains oauth2_access_token or client_id
          if grep -q -E "\"oauth2_access_token\"|\"client_id\"" "$file" 2>/dev/null; then
            print_critical "    ${RED}→ Contains authentication tokens!${NC}"
          fi
        fi
      done
    else
      print_success "Google Cloud credentials directory exists but no credential files found."
    fi
  else
    print_success "No Google Cloud credentials directory found."
  fi
  
  # Azure credentials
  if [ -d "$HOME/.azure" ]; then
    azure_files=$(find "$HOME/.azure" -type f -name "accessTokens.json" -o -name "azureProfile.json" 2>/dev/null)
    if [ -n "$azure_files" ]; then
      print_critical "Found Azure credential files:"
      echo "$azure_files" | while read -r file; do
        if [ -r "$file" ]; then
          print_critical "  ${RED}→ $file${NC}"
          # Check for token information
          if grep -q -E "\"accessToken\"|\"refreshToken\"" "$file" 2>/dev/null; then
            print_critical "    ${RED}→ Contains authentication tokens!${NC}"
          fi
        fi
      done
    else
      print_success "Azure credentials directory exists but no credential files found."
    fi
  else
    print_success "No Azure credentials directory found."
  fi
}

# Main function: run all credential checks
credentials_hunter_main() {
  print_title "Credentials Hunter"
  
  # Check for potentially exposed passwords
  check_credential_files
  
  # Check history files
  check_history_files
  
  # Check for database credentials
  check_db_credentials
  
  # Check for cloud service credentials
  check_cloud_credentials
  
  # Wait for user if wait mode is enabled
  wait_for_user
}

# Call the main function if this script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  credentials_hunter_main
fi 