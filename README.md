# Quick&Dirty Port Scanner Documentation

## Overview
A simple TCP port scanner for Linux systems that provides detailed information about open ports, running services, and associated processes.

## Technical Specifications

### Development Environment
- **Language**: C (C11 standard)
- **Architecture**: x86-64
- **Operating System**: Linux (Tested on Arch Linux)
- **Compiler**: GCC 13.2.1
- **Build System**: Make

### Dependencies
Required system libraries:
```bash
# Core system libraries
libc6        # GNU C Library
libpthread   # POSIX threads library

# Network libraries
libnss       # Network Security Services
libnspr      # Netscape Portable Runtime

# Process information
procps       # /proc filesystem utilities
```

Required header files:
- `<stdio.h>`
- `<stdlib.h>`
- `<string.h>`
- `<unistd.h>`
- `<errno.h>`
- `<ctype.h>`
- `<sys/socket.h>`
- `<arpa/inet.h>`
- `<netdb.h>`
- `<dirent.h>`
- `<pwd.h>`

## Features
1. **Port Scanning**
   - Full TCP port range (1-65535)
   - Connection state detection
   - Service name resolution

2. **Process Information**
   - Process name and PID
   - User ownership
   - Process state detection

3. **Service Detection**
   - System service database integration
   - Known port mapping
   - Service name resolution

4. **Output Format**
   ```
   PORT    STATE        SERVICE     PROCESS
   80      LISTENING    http        nginx (PID: 1234, User: www-data)
   443     ESTABLISHED  https       apache2 (PID: 5678, User: www-data)
   ```

## System Requirements
- Linux kernel 4.0 or later
- Root/sudo privileges for complete system access
- Access to /proc filesystem
- Minimum 512MB RAM
- Network interface (supports localhost scanning)

## Installation
```bash
# Compile the program
gcc -o portscan permutations.c

# Run with root privileges
sudo ./portscan
```

## Limitations
1. Linux-specific implementation (/proc filesystem dependency)
2. Requires root privileges for complete functionality
3. CPU-intensive during full port range scan
4. Memory usage scales with number of open ports
5. Limited to localhost scanning

## Performance Considerations
- Full port scan (1-65535) may take several minutes
- CPU usage increases with concurrent connections
- Memory usage typically under 10MB
- File descriptor usage: 1 per port check

## Security Notes
- Requires root privileges
- Creates temporary socket connections
- Accesses system process information
- May trigger security software alerts

## Error Handling
- Socket creation failures
- Permission denied errors
- Process access restrictions
- Memory allocation failures
- File system access errors

## License
MIT License - Free to use, modify, and distribute

## Author
[Lars EBERHART]
[2025]
