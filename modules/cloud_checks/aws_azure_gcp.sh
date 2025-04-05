#!/bin/bash

# Title: Cloud Environment Checker
# Description: Detect and analyze AWS, Azure, and GCP environments for misconfigurations
# Author: Jonas Resch

# Check for AWS environment indicators
check_aws_environment() {
  print_subtitle "AWS Environment"
  
  print_info "Checking for AWS environment indicators..."
  
  # Variables to track AWS presence
  AWS_DETECTED=0
  
  # Check for EC2 metadata service
  if command_exists curl; then
    ec2_metadata=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null)
    
    if [ -n "$ec2_metadata" ]; then
      AWS_DETECTED=1
      print_critical "${RED}AWS EC2 instance detected!${NC}"
      print_critical " ${RED}→ EC2 metadata service is accessible${NC}"
      
      # Extract critical metadata
      instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
      instance_type=$(curl -s http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null)
      region=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null | sed 's/[a-z]$//')
      account_id=$(curl -s http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info 2>/dev/null | grep -o "AccountId.*" | cut -d'"' -f3)
      
      if [ -n "$instance_id" ]; then
        print_critical " ${RED}→ Instance ID: $instance_id${NC}"
      fi
      
      if [ -n "$instance_type" ]; then
        print_critical " ${RED}→ Instance Type: $instance_type${NC}"
      fi
      
      if [ -n "$region" ]; then
        print_critical " ${RED}→ Region: $region${NC}"
      fi
      
      if [ -n "$account_id" ]; then
        print_critical " ${RED}→ AWS Account ID: $account_id${NC}"
      fi
      
      # Check for IMDSv2 enforcement (more secure)
      token_response=$(curl -s -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token 2>/dev/null)
      if [ -n "$token_response" ]; then
        print_warning "${YELLOW}→ IMDSv2 token service is available${NC}"
        
        # Test if IMDSv1 still works (less secure)
        imdsv1_test=$(curl -s http://169.254.169.254/latest/meta-data/ami-id 2>/dev/null)
        if [ -n "$imdsv1_test" ]; then
          print_critical " ${RED}→ IMDSv1 is still accessible (security risk)${NC}"
        else
          print_success " → IMDSv1 is disabled (more secure)"
        fi
      else
        print_critical " ${RED}→ IMDSv2 token service not available, using IMDSv1 (security risk)${NC}"
      fi
      
      # Check for IAM role
      iam_info=$(curl -s http://169.254.169.254/latest/meta-data/iam/info 2>/dev/null)
      if [ -n "$iam_info" ] && ! echo "$iam_info" | grep -q "404 - Not Found"; then
        print_warning "${YELLOW}→ IAM role is attached to this instance${NC}"
        
        # Extract role name
        role_name=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
        if [ -n "$role_name" ]; then
          print_warning " ${YELLOW}→ Role name: $role_name${NC}"
          
          # Get temporary credentials
          if [ "$THOROUGH" ]; then
            print_warning " ${YELLOW}→ Retrieving temporary credentials...${NC}"
            temp_creds=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role_name" 2>/dev/null)
            if [ -n "$temp_creds" ]; then
              print_critical " ${RED}→ Temporary credentials are accessible!${NC}"
              # Don't print the actual credentials for security
            fi
          fi
        fi
      fi
      
      # Check for user data (could contain secrets)
      if [ "$THOROUGH" ]; then
        user_data=$(curl -s http://169.254.169.254/latest/user-data 2>/dev/null)
        if [ -n "$user_data" ] && [ "$user_data" != "404 - Not Found" ]; then
          print_critical "${RED}→ EC2 user-data is accessible and not empty!${NC}"
          print_critical " ${RED}→ User-data may contain credentials or secrets${NC}"
          
          # Check for common secrets in user-data
          if echo "$user_data" | grep -qi "password\|secret\|key\|token\|credential"; then
            print_critical " ${RED}→ User-data contains potential secrets!${NC}"
          fi
        fi
      fi
    fi
  fi
  
  # Check for ECS container metadata
  if [ -n "$ECS_CONTAINER_METADATA_URI" ]; then
    AWS_DETECTED=1
    print_critical "${RED}AWS ECS container detected!${NC}"
    print_critical " ${RED}→ ECS container metadata is available${NC}"
    print_critical " ${RED}→ Metadata URI: $ECS_CONTAINER_METADATA_URI${NC}"
    
    # Retrieve container metadata
    if command_exists curl; then
      ecs_metadata=$(curl -s "$ECS_CONTAINER_METADATA_URI" 2>/dev/null)
      if [ -n "$ecs_metadata" ]; then
        print_critical " ${RED}→ ECS metadata is accessible${NC}"
      fi
    fi
  fi
  
  # Check for AWS credentials files
  if [ -f "$HOME/.aws/credentials" ]; then
    AWS_DETECTED=1
    print_critical "${RED}AWS credentials file found: $HOME/.aws/credentials${NC}"
    
    # Check permissions on credentials file
    perms=$(ls -la "$HOME/.aws/credentials" | awk '{print $1}')
    if [[ "$perms" =~ [g|o][r|w|x] ]]; then
      print_critical " ${RED}→ Credentials file has insecure permissions: $perms${NC}"
    fi
    
    # Count profiles
    profile_count=$(grep -c "^\[" "$HOME/.aws/credentials" 2>/dev/null)
    print_critical " ${RED}→ File contains $profile_count profile(s)${NC}"
    
    # List profile names
    profiles=$(grep "^\[" "$HOME/.aws/credentials" 2>/dev/null | tr -d '[]')
    for profile in $profiles; do
      print_critical " ${RED}→ Profile: $profile${NC}"
    done
  fi
  
  # Check for AWS CLI configuration
  if [ -f "$HOME/.aws/config" ]; then
    AWS_DETECTED=1
    print_warning "${YELLOW}AWS config file found: $HOME/.aws/config${NC}"
    
    # Extract regions
    regions=$(grep "region" "$HOME/.aws/config" 2>/dev/null | awk '{print $3}' | sort -u)
    if [ -n "$regions" ]; then
      print_warning " ${YELLOW}→ Configured regions:${NC}"
      for region in $regions; do
        print_warning "   ${YELLOW}→ $region${NC}"
      done
    fi
  fi
  
  # Check for AWS CLI in PATH
  if command_exists aws; then
    AWS_DETECTED=1
    print_warning "${YELLOW}AWS CLI is installed${NC}"
    
    # If credentials are found, try to determine identity
    if [ -f "$HOME/.aws/credentials" ] || [ -n "$AWS_ACCESS_KEY_ID" ]; then
      if [ "$THOROUGH" ]; then
        print_warning " ${YELLOW}→ Checking current AWS identity...${NC}"
        aws_id=$(aws sts get-caller-identity 2>/dev/null)
        
        if [ -n "$aws_id" ]; then
          account=$(echo "$aws_id" | grep -o "Account.*" | cut -d'"' -f3)
          user_id=$(echo "$aws_id" | grep -o "UserId.*" | cut -d'"' -f3)
          arn=$(echo "$aws_id" | grep -o "Arn.*" | cut -d'"' -f3)
          
          print_critical " ${RED}→ AWS Identity:${NC}"
          if [ -n "$account" ]; then print_critical "   ${RED}→ Account: $account${NC}"; fi
          if [ -n "$user_id" ]; then print_critical "   ${RED}→ UserID: $user_id${NC}"; fi
          if [ -n "$arn" ]; then print_critical "   ${RED}→ ARN: $arn${NC}"; fi
        fi
      fi
    fi
  fi
  
  # Check for AWS environment variables
  if [ -n "$AWS_ACCESS_KEY_ID" ] || [ -n "$AWS_SECRET_ACCESS_KEY" ] || [ -n "$AWS_SESSION_TOKEN" ]; then
    AWS_DETECTED=1
    print_critical "${RED}AWS credentials found in environment variables!${NC}"
    
    if [ -n "$AWS_ACCESS_KEY_ID" ]; then
      masked_key="${AWS_ACCESS_KEY_ID:0:4}...${AWS_ACCESS_KEY_ID: -4}"
      print_critical " ${RED}→ AWS_ACCESS_KEY_ID: $masked_key${NC}"
    fi
    
    if [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
      print_critical " ${RED}→ AWS_SECRET_ACCESS_KEY is set${NC}"
    fi
    
    if [ -n "$AWS_SESSION_TOKEN" ]; then
      print_critical " ${RED}→ AWS_SESSION_TOKEN is set${NC}"
    fi
  fi
  
  # Summary
  if [ "$AWS_DETECTED" -eq 1 ]; then
    print_warning "${YELLOW}AWS environment detected - check for potential cloud privilege escalation vectors${NC}"
  else
    print_success "No AWS environment indicators found"
  fi
}

# Check for Azure environment indicators
check_azure_environment() {
  print_subtitle "Azure Environment"
  
  print_info "Checking for Azure environment indicators..."
  
  # Variables to track Azure presence
  AZURE_DETECTED=0
  
  # Check for Azure instance metadata service
  if command_exists curl; then
    azure_metadata=$(curl -s -H "Metadata:true" --connect-timeout 2 "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)
    
    if [ -n "$azure_metadata" ] && ! echo "$azure_metadata" | grep -q "error"; then
      AZURE_DETECTED=1
      print_critical "${RED}Azure VM instance detected!${NC}"
      print_critical " ${RED}→ Azure metadata service is accessible${NC}"
      
      # Extract compute name
      compute_name=$(echo "$azure_metadata" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
      if [ -n "$compute_name" ]; then
        print_critical " ${RED}→ VM Name: $compute_name${NC}"
      fi
      
      # Extract resource group
      resource_group=$(echo "$azure_metadata" | grep -o '"resourceGroupName":"[^"]*"' | head -1 | cut -d'"' -f4)
      if [ -n "$resource_group" ]; then
        print_critical " ${RED}→ Resource Group: $resource_group${NC}"
      fi
      
      # Extract subscription ID
      subscription=$(echo "$azure_metadata" | grep -o '"subscriptionId":"[^"]*"' | head -1 | cut -d'"' -f4)
      if [ -n "$subscription" ]; then
        print_critical " ${RED}→ Subscription ID: $subscription${NC}"
      fi
      
      # Check for managed identity
      if [ "$THOROUGH" ]; then
        identity_token=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null)
        
        if [ -n "$identity_token" ] && ! echo "$identity_token" | grep -q "error"; then
          print_critical " ${RED}→ Managed Identity is enabled and accessible!${NC}"
          print_critical " ${RED}→ This can be used for privilege escalation${NC}"
        fi
      fi
    fi
  fi
  
  # Check for Azure CLI credentials
  azure_creds_dir="$HOME/.azure"
  if [ -d "$azure_creds_dir" ]; then
    AZURE_DETECTED=1
    print_critical "${RED}Azure credentials directory found: $azure_creds_dir${NC}"
    
    # Check for profile files
    profile_files=$(find "$azure_creds_dir" -name "*.json" 2>/dev/null)
    if [ -n "$profile_files" ]; then
      print_critical " ${RED}→ Azure profile files:${NC}"
      echo "$profile_files" | while read -r file; do
        perms=$(ls -la "$file" | awk '{print $1}')
        print_critical "   ${RED}→ $file${NC} [$perms]"
        
        # Look for tokens in the files
        if grep -q "accessToken" "$file" 2>/dev/null; then
          print_critical "     ${RED}→ File contains access tokens!${NC}"
        fi
      done
    fi
  fi
  
  # Check for Azure CLI in PATH
  if command_exists az; then
    AZURE_DETECTED=1
    print_warning "${YELLOW}Azure CLI is installed${NC}"
    
    # Try to get account info if allowed
    if [ "$THOROUGH" ]; then
      account_info=$(az account show 2>/dev/null)
      
      if [ -n "$account_info" ] && ! echo "$account_info" | grep -q "error"; then
        print_critical " ${RED}→ Azure account is logged in!${NC}"
        
        # Extract account details
        subscription=$(echo "$account_info" | grep -o '"id":\s*"[^"]*"' | head -1 | cut -d'"' -f4)
        tenant=$(echo "$account_info" | grep -o '"tenantId":\s*"[^"]*"' | head -1 | cut -d'"' -f4)
        user=$(echo "$account_info" | grep -o '"name":\s*"[^"]*"' | head -1 | cut -d'"' -f4)
        
        if [ -n "$subscription" ]; then print_critical "   ${RED}→ Subscription: $subscription${NC}"; fi
        if [ -n "$tenant" ]; then print_critical "   ${RED}→ Tenant: $tenant${NC}"; fi
        if [ -n "$user" ]; then print_critical "   ${RED}→ User: $user${NC}"; fi
      fi
    fi
  fi
  
  # Check for Azure environment variables
  if [ -n "$AZURE_CLIENT_ID" ] || [ -n "$AZURE_CLIENT_SECRET" ] || [ -n "$AZURE_TENANT_ID" ]; then
    AZURE_DETECTED=1
    print_critical "${RED}Azure credentials found in environment variables!${NC}"
    
    if [ -n "$AZURE_CLIENT_ID" ]; then
      print_critical " ${RED}→ AZURE_CLIENT_ID: $AZURE_CLIENT_ID${NC}"
    fi
    
    if [ -n "$AZURE_TENANT_ID" ]; then
      print_critical " ${RED}→ AZURE_TENANT_ID: $AZURE_TENANT_ID${NC}"
    fi
    
    if [ -n "$AZURE_CLIENT_SECRET" ]; then
      print_critical " ${RED}→ AZURE_CLIENT_SECRET is set${NC}"
    fi
  fi
  
  # Summary
  if [ "$AZURE_DETECTED" -eq 1 ]; then
    print_warning "${YELLOW}Azure environment detected - check for potential cloud privilege escalation vectors${NC}"
  else
    print_success "No Azure environment indicators found"
  fi
}

# Check for GCP environment indicators
check_gcp_environment() {
  print_subtitle "Google Cloud Environment"
  
  print_info "Checking for GCP environment indicators..."
  
  # Variables to track GCP presence
  GCP_DETECTED=0
  
  # Check for GCP metadata service
  if command_exists curl; then
    gcp_metadata=$(curl -s -H "Metadata-Flavor: Google" --connect-timeout 2 "http://metadata.google.internal/computeMetadata/v1/instance/" 2>/dev/null)
    
    if [ -n "$gcp_metadata" ] && ! echo "$gcp_metadata" | grep -q "Error"; then
      GCP_DETECTED=1
      print_critical "${RED}Google Cloud instance detected!${NC}"
      print_critical " ${RED}→ GCP metadata service is accessible${NC}"
      
      # Extract instance details
      instance_id=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/id" 2>/dev/null)
      if [ -n "$instance_id" ]; then
        print_critical " ${RED}→ Instance ID: $instance_id${NC}"
      fi
      
      instance_name=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/name" 2>/dev/null)
      if [ -n "$instance_name" ]; then
        print_critical " ${RED}→ Instance Name: $instance_name${NC}"
      fi
      
      zone=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/zone" 2>/dev/null | awk -F/ '{print $NF}')
      if [ -n "$zone" ]; then
        print_critical " ${RED}→ Zone: $zone${NC}"
      fi
      
      project_id=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id" 2>/dev/null)
      if [ -n "$project_id" ]; then
        print_critical " ${RED}→ Project ID: $project_id${NC}"
      fi
      
      # Check for service accounts
      service_accounts=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" 2>/dev/null)
      if [ -n "$service_accounts" ]; then
        print_critical " ${RED}→ Service accounts:${NC}"
        echo "$service_accounts" | tr -d '/' | while read -r sa; do
          print_critical "   ${RED}→ $sa${NC}"
          
          # If in thorough mode, get token info
          if [ "$THOROUGH" ] && [ -n "$sa" ]; then
            sa_scopes=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/scopes" 2>/dev/null)
            if [ -n "$sa_scopes" ]; then
              print_critical "     ${RED}→ Scopes:${NC}"
              echo "$sa_scopes" | while read -r scope; do
                print_critical "       ${RED}→ $scope${NC}"
              done
            fi
            
            # Check if we can get a token (don't print it)
            sa_token=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$sa/token" 2>/dev/null)
            if [ -n "$sa_token" ] && ! echo "$sa_token" | grep -q "Error"; then
              print_critical "     ${RED}→ Can obtain access token for this service account!${NC}"
            fi
          fi
        done
      fi
    fi
  fi
  
  # Check for GCP credentials files
  if [ -d "$HOME/.config/gcloud" ]; then
    GCP_DETECTED=1
    print_critical "${RED}Google Cloud credentials directory found: $HOME/.config/gcloud${NC}"
    
    # Check for credentials files
    cred_files=$(find "$HOME/.config/gcloud" -name "credentials.*" 2>/dev/null)
    if [ -n "$cred_files" ]; then
      print_critical " ${RED}→ Credential files:${NC}"
      echo "$cred_files" | while read -r file; do
        perms=$(ls -la "$file" | awk '{print $1}')
        print_critical "   ${RED}→ $file${NC} [$perms]"
      done
    fi
    
    # Check for active config
    if [ -f "$HOME/.config/gcloud/active_config" ]; then
      active_config=$(cat "$HOME/.config/gcloud/active_config" 2>/dev/null)
      if [ -n "$active_config" ]; then
        print_warning " ${YELLOW}→ Active config: $active_config${NC}"
      fi
    fi
    
    # Check configurations
    if [ -d "$HOME/.config/gcloud/configurations" ]; then
      configs=$(find "$HOME/.config/gcloud/configurations" -name "config_*" 2>/dev/null)
      if [ -n "$configs" ]; then
        print_warning " ${YELLOW}→ GCloud configurations:${NC}"
        echo "$configs" | while read -r config; do
          config_name=$(basename "$config" | sed 's/config_//')
          print_warning "   ${YELLOW}→ $config_name${NC}"
          
          # Extract account
          account=$(grep "account" "$config" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
          if [ -n "$account" ]; then
            print_warning "     ${YELLOW}→ Account: $account${NC}"
          fi
          
          # Extract project
          project=$(grep "project" "$config" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
          if [ -n "$project" ]; then
            print_warning "     ${YELLOW}→ Project: $project${NC}"
          fi
        done
      fi
    fi
  fi
  
  # Check for GCP service account key files
  sa_key_files=$(find "$HOME" -name "*.json" -exec grep -l "\"type\": \"service_account\"" {} \; 2>/dev/null)
  if [ -n "$sa_key_files" ]; then
    GCP_DETECTED=1
    print_critical "${RED}Google Cloud service account key files found:${NC}"
    echo "$sa_key_files" | while read -r file; do
      perms=$(ls -la "$file" | awk '{print $1}')
      print_critical " ${RED}→ $file${NC} [$perms]"
      
      # Extract key info
      project_id=$(grep "\"project_id\":" "$file" 2>/dev/null | head -1 | cut -d'"' -f4)
      client_email=$(grep "\"client_email\":" "$file" 2>/dev/null | head -1 | cut -d'"' -f4)
      
      if [ -n "$project_id" ]; then print_critical "   ${RED}→ Project ID: $project_id${NC}"; fi
      if [ -n "$client_email" ]; then print_critical "   ${RED}→ Service Account: $client_email${NC}"; fi
    done
  fi
  
  # Check for gcloud CLI in PATH
  if command_exists gcloud; then
    GCP_DETECTED=1
    print_warning "${YELLOW}Google Cloud SDK (gcloud) is installed${NC}"
    
    # Try to get account info if allowed
    if [ "$THOROUGH" ]; then
      account_info=$(gcloud auth list 2>/dev/null)
      
      if [ -n "$account_info" ] && ! echo "$account_info" | grep -q "No credentialed accounts"; then
        print_critical " ${RED}→ Google Cloud account is logged in!${NC}"
        
        # Extract active account
        active_account=$(echo "$account_info" | grep "*" | awk '{print $2}')
        if [ -n "$active_account" ]; then
          print_critical "   ${RED}→ Active Account: $active_account${NC}"
        fi
        
        # Get current project
        current_project=$(gcloud config get-value project 2>/dev/null)
        if [ -n "$current_project" ] && [ "$current_project" != "(unset)" ]; then
          print_critical "   ${RED}→ Current Project: $current_project${NC}"
        fi
      fi
    fi
  fi
  
  # Check for GCP environment variables
  if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
    GCP_DETECTED=1
    print_critical "${RED}Google Cloud credentials found in environment variables!${NC}"
    print_critical " ${RED}→ GOOGLE_APPLICATION_CREDENTIALS: $GOOGLE_APPLICATION_CREDENTIALS${NC}"
    
    # Check if the file exists
    if [ -f "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
      perms=$(ls -la "$GOOGLE_APPLICATION_CREDENTIALS" | awk '{print $1}')
      print_critical "   ${RED}→ File exists with permissions: $perms${NC}"
      
      # Extract key info
      if grep -q "\"type\": \"service_account\"" "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null; then
        project_id=$(grep "\"project_id\":" "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null | head -1 | cut -d'"' -f4)
        client_email=$(grep "\"client_email\":" "$GOOGLE_APPLICATION_CREDENTIALS" 2>/dev/null | head -1 | cut -d'"' -f4)
        
        if [ -n "$project_id" ]; then print_critical "   ${RED}→ Project ID: $project_id${NC}"; fi
        if [ -n "$client_email" ]; then print_critical "   ${RED}→ Service Account: $client_email${NC}"; fi
      fi
    fi
  fi
  
  # Summary
  if [ "$GCP_DETECTED" -eq 1 ]; then
    print_warning "${YELLOW}Google Cloud environment detected - check for potential cloud privilege escalation vectors${NC}"
  else
    print_success "No Google Cloud environment indicators found"
  fi
}

# Check for common cloud credentials files
check_common_cloud_credentials() {
  print_subtitle "Common Cloud Credentials"
  
  print_info "Checking for common cloud credential files..."
  
  # Create an array to store found credential files
  found_creds=()
  
  # Common credential files and directories to check
  cred_paths=(
    "$HOME/.aws"
    "$HOME/.azure"
    "$HOME/.config/gcloud"
    "$HOME/.terraform.d"
    "$HOME/.kube/config"
    "$HOME/.config/doctl"
    "$HOME/.digitalocean"
    "$HOME/.aliyun"
    "$HOME/.alibabacloud"
    "$HOME/.oracle_cloud"
    "$HOME/.oci"
    "$HOME/.ibmcloud"
    "$HOME/.config/ibmcloud"
    "$HOME/.ovhcloud"
    "$HOME/.linode"
    "$HOME/.vultr"
  )
  
  # Check each path
  for path in "${cred_paths[@]}"; do
    if [ -e "$path" ]; then
      found_creds+=("$path")
    fi
  done
  
  # Report findings
  if [ ${#found_creds[@]} -gt 0 ]; then
    print_warning "${YELLOW}Found cloud credential files/directories:${NC}"
    for cred in "${found_creds[@]}"; do
      # Determine the cloud provider
      if [[ "$cred" == *"aws"* ]]; then
        provider="AWS"
      elif [[ "$cred" == *"azure"* ]]; then
        provider="Azure"
      elif [[ "$cred" == *"gcloud"* ]]; then
        provider="Google Cloud"
      elif [[ "$cred" == *"terraform"* ]]; then
        provider="Terraform"
      elif [[ "$cred" == *"kube"* ]]; then
        provider="Kubernetes"
      elif [[ "$cred" == *"doctl"* || "$cred" == *"digitalocean"* ]]; then
        provider="DigitalOcean"
      elif [[ "$cred" == *"aliyun"* || "$cred" == *"alibabacloud"* ]]; then
        provider="Alibaba Cloud"
      elif [[ "$cred" == *"oracle"* || "$cred" == *"oci"* ]]; then
        provider="Oracle Cloud"
      elif [[ "$cred" == *"ibmcloud"* ]]; then
        provider="IBM Cloud"
      elif [[ "$cred" == *"ovhcloud"* ]]; then
        provider="OVH Cloud"
      elif [[ "$cred" == *"linode"* ]]; then
        provider="Linode"
      elif [[ "$cred" == *"vultr"* ]]; then
        provider="Vultr"
      else
        provider="Unknown"
      fi
      
      print_warning " ${YELLOW}→ $provider: $cred${NC}"
    done
  else
    print_success "No common cloud credential files/directories found"
  fi
}

# Main function to run all cloud environment checks
cloud_environment_checks() {
  print_title "Cloud Environment"
  
  # Run all cloud environment checks
  check_aws_environment
  check_azure_environment
  check_gcp_environment
  check_common_cloud_credentials
  
  # Wait for user if wait mode is enabled
  wait_for_user
} 