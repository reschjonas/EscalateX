# EscalateX

A Linux privilege escalation scanner built to help security professionals find potential vectors for privilege escalation during penetration tests and security audits.

```
███████╗███████╗ ██████╗ █████╗ ██╗      █████╗ ████████╗███████╗██╗  ██╗
██╔════╝██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
█████╗  ███████╗██║     ███████║██║     ███████║   ██║   █████╗   ╚███╔╝ 
██╔══╝  ╚════██║██║     ██╔══██║██║     ██╔══██║   ██║   ██╔══╝   ██╔██╗ 
███████╗███████║╚██████╗██║  ██║███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗
╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

## About

EscalateX scans Linux systems for common privilege escalation vulnerabilities and misconfigurations. I built this tool after getting tired of manually checking the same things during every pentest engagement. 

What it does:
- Checks system configs, permissions, and security settings
- Identifies SUID/SGID binaries and capabilities that could be abused
- Finds writable files and directories in sensitive locations
- Detects kernel vulnerabilities that might lead to privilege escalation
- Evaluates container escape vectors

## Installation

Pretty simple setup:

```bash
# Clone it
git clone https://github.com/reschjonas/EscalateX.git

# Go to the directory
cd EscalateX

# Make it executable
chmod +x escalatex.sh
```

### Requirements

Runs on most Linux distros with:
- Bash 4.0+
- Standard Unix tools (find, grep, ls, etc.)
- The `timeout` command is nice to have but not required

## Usage

### Basic Usage

Just run it:

```bash
./escalatex.sh
```

### More Options

```bash
# Run a more thorough scan (takes longer but finds more)
./escalatex.sh --thorough

# Only check for specific things
./escalatex.sh --only system_info,suid_sgid

# Use sudo to get more info
./escalatex.sh --multi --password yourpassword

# The kitchen sink (all checks, maximum depth)
./escalatex.sh --extreme
```

### Command Line Options

#### Core Options
- `-a, --all` - Run all checks (thorough mode)
- `-t, --thorough` - More comprehensive but slower scan
- `-x, --extreme` - Maximum depth scan for critical systems
- `-o, --only CHECKS` - Run specific checks (comma-separated)
- `-d, --dir PATH` - Check a specific directory
- `-m, --multi` - Use multiple threads (default)
- `-s, --single` - Single-threaded mode
- `--threads N` - Set number of threads for multithreaded mode

#### Output Options
- `-q, --quiet` - Minimal output
- `-n, --no-color` - Turn off colors
- `-w, --wait` - Pause between check groups

#### Advanced Options
- `-p, --password PWD` - For sudo operations
- `-S, --sudo-pass` - Prompt for sudo password for privilege escalation attempts
- `-D, --debug` - Verbose logging
- `-h, --help` - Show help

## What It Checks For

### System Information
- OS details and kernel version
- Security configurations and patch status
- Hardware info and resource usage
- Filesystem mounts and permissions
- Boot configuration and services

### User & Permissions
- Current user privileges
- User enumeration and group memberships
- Password policy issues
- Sudo rules that could be abused
- Home directory permissions

### Privilege Escalation Vectors
- SUID/SGID binaries (especially exploitable ones)
- Files with dangerous capabilities
- Custom privilege escalation paths
- Container security issues

### Filesystem Issues
- Writable files in sensitive locations
- Misconfigured home directory permissions
- PATH manipulation vulnerabilities
- Wildcard injection opportunities

## Sample Output

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━ System Information ━━━━━━━━━━━━━━━━━━━━━━━━━━┓

╔════════[ Operating System Information ]════════╗
[+] OS: Ubuntu 20.04.3 LTS (ubuntu)
[+] Kernel version: 5.11.0-27-generic
[+] Architecture: x86_64
[+] Running on physical hardware

╔════════[ Hardware Information ]════════╗
[+] CPU: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz (8 cores)
[+] Memory: 6453MB / 16000MB (40% used)
[+] Swap: 2048MB / 4096MB (50% used)

...

┏━━━━━━━━━━━━━━━━━━━━━━━━━━ SUID/SGID Binaries and Capabilities ━━━━━━━━━━━━━━━━━━━━━━━━━━┓

╔════════[ SUID/SGID Binaries ]════════╗
[*] Looking for SUID binaries (might take a while)...
[+] Found 35 SUID/SGID binaries:
[!] /usr/bin/sudo [Owner: root]
   → Purpose: Execute commands as root with proper permissions
[!] /usr/bin/pkexec [Owner: root]
   → Purpose: Execute commands as another user with policykit
[CRITICAL] /usr/bin/python3 [Owner: root]
   → Exploitable: python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

...

┏━━━━━━━━━━━━━━━━━━━━━━━━━━ Scan Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━┓

[*] EscalateX scan completed at Wed Feb 14 14:32:18 EST 2024
[*] Remember to check the most promising privilege escalation vectors highlighted in red

Thank you for using EscalateX!
```

## Custom Modules

You can write your own modules if you want to check for specific things. Here's how:

1. Create a script in the modules directory
2. Use this basic structure:

```bash
#!/bin/bash

# Title: My Custom Check
# Description: What this thing does

check_something_interesting() {
  print_subtitle "My Interesting Check"
  
  # Your check logic here
  print_info "Checking something..."
  
  # Found something worth noting
  print_warning "Hmm, that's interesting"
  
  # Found something bad
  print_critical "This is definitely exploitable"
}

# Main function
custom_checks() {
  print_title "My Custom Stuff"
  
  # Run your checks
  check_something_interesting
  
  # Pause if wait mode is on
  wait_for_user
}
```

3. Add your module to loader.sh

## Important Warning

This is a security tool. Use it responsibly:

- Only run it on systems you own or have permission to test
- Some checks might trigger security alerts or monitoring
- Be careful in production environments
- Don't be a jerk - never use this for unauthorized access

## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0) - see the [LICENSE](LICENSE.md) file for details.

This means you can freely use, modify, and distribute this software, as long as:
- You give appropriate credit to the original author
- You don't use it for commercial purposes

For more information, visit: https://creativecommons.org/licenses/by-nc/4.0/

## Contributing

Contributions welcome! To contribute:

1. Fork the repo
2. Create a branch (`git checkout -b cool-new-feature`)
3. Commit your changes (`git commit -m 'Added some cool feature'`)
4. Push to your branch (`git push origin cool-new-feature`)
5. Open a PR 