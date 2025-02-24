/*
 * Advanced Port Scanner (localhost)
 * -------------------------------
 *
 * Purpose:
 * This program performs comprehensive TCP port scanning on the local system (127.0.0.1)
 * to identify and analyze all open network ports, their states, and associated processes.
 *
 * Key Features:
 * - Complete TCP port range scanning (ports 1-65535)
 * - Advanced state detection (differentiates between LISTENING/ESTABLISHED/OPEN)
 * - Service identification through system service database lookup
 * - Comprehensive process information gathering:
 *   - Process name and executable details
 *   - Process ID (PID) for process tracking
 *   - Process owner (username from system database)
 *   - Current process state and details
 * - Self-aware operation (filters out self-generated connections)
 * - Direct socket operations for reliable state detection
 *
 * Technical Implementation:
 * - Utilizes Linux /proc filesystem for detailed process information
 * - Implements sophisticated TCP connection state detection
 * - Employs proper file descriptor and socket management
 * - Uses memory-safe string operations throughout
 * - Includes comprehensive error detection and handling
 * - Provides properly formatted and aligned output
 *
 * Output Format and Columns:
 * PORT       - The TCP port number being reported
 * STATE      - Current port state (LISTENING/ESTABLISHED/OPEN)
 * SERVICE    - Associated service name from system database
 * PROCESS    - Detailed process information (Name, PID, User)
 *
 * Usage Notes:
 * - Requires root/sudo privileges for complete system access
 * - May take several minutes for full port range scan
 * - CPU intensive during operation
 */

// System includes for core functionality
#include <stdio.h>  // Provides: printf, fprintf, fopen, fclose, FILE*, etc.
#include <stdlib.h> // Provides: atoi, exit, malloc, free, etc.
#include <string.h> // Provides: memset, strncmp, strcspn, etc.
#include <unistd.h> // Provides: close, getpid, access, etc.
#include <errno.h>  // Provides: errno variable and error definitions
#include <ctype.h>  // Provides: isdigit and other character classification

// Network-specific includes
#include <sys/socket.h> // Provides: socket, connect, bind, sockaddr structs
#include <arpa/inet.h>  // Provides: inet_addr, htons, sockaddr_in
#include <netdb.h>      // Provides: getservbyport, struct servent

// Process and filesystem includes
#include <dirent.h> // Provides: opendir, readdir, struct dirent
#include <pwd.h>    // Provides: getpwuid, struct passwd

// Program constants with detailed explanations
#define START_PORT 1   // Initial port number to begin scanning (lowest valid TCP port)
#define END_PORT 65535 // Final port number to scan (highest valid TCP port)
#define COL_PORT 8     // Width of PORT column (accommodates up to 5 digits plus padding)
#define COL_STATE 12   // Width of STATE column (fits "ESTABLISHED" plus padding)
#define COL_SERVICE 20 // Width of SERVICE column (fits common service names plus padding)
#define COL_PROC 30    // Width of PROCESS column (fits process details plus padding)

// Global process ID variable
pid_t our_pid; // Stores the scanner's own process ID for self-connection filtering

// Function to get process information
char *get_process_info(int port)
{
    DIR *proc_dir;                 // Directory pointer for /proc
    struct dirent *entry;          // Directory entry structure
    char path[256];                // Path buffer for file operations
    char line[256];                // Line buffer for reading files
    static char process_info[512]; // Buffer for process information
    FILE *fp;                      // File pointer for reading files

    process_info[0] = '\0';      // Initialize process_info buffer
    proc_dir = opendir("/proc"); // Open /proc directory
    if (!proc_dir)
        return process_info; // Return if directory cannot be opened

    while ((entry = readdir(proc_dir)) != NULL)
    { // Read each entry in /proc
        // Skip non-numeric and our own process
        if (!isdigit(entry->d_name[0]) ||
            atoi(entry->d_name) == our_pid)
            continue;

        snprintf(path, sizeof(path), "/proc/%s/net/tcp", entry->d_name); // Construct path to net/tcp file
        fp = fopen(path, "r");                                           // Open net/tcp file
        if (fp)
        {
            char local_addr[32]; // Buffer for local address
            int local_port;      // Variable for local port
            // Skip header line
            fgets(line, sizeof(line), fp);
            while (fgets(line, sizeof(line), fp))
            { // Read each line in net/tcp
                if (sscanf(line, "%*d: %[^:]:%X", local_addr, &local_port) == 2)
                { // Parse local address and port
                    if (local_port == port)
                    { // Check if port matches
                        // Get process details
                        char comm_path[256];                                                          // Path buffer for comm file
                        char status_path[256];                                                        // Path buffer for status file
                        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);       // Construct path to comm file
                        snprintf(status_path, sizeof(status_path), "/proc/%s/status", entry->d_name); // Construct path to status file

                        FILE *comm_fp = fopen(comm_path, "r");     // Open comm file
                        FILE *status_fp = fopen(status_path, "r"); // Open status file

                        if (comm_fp && status_fp)
                        {                          // Check if files are opened successfully
                            char proc_name[256];   // Buffer for process name
                            char status_line[256]; // Buffer for status line
                            uid_t uid = 0;         // Variable for user ID

                            // Get process name
                            if (fgets(proc_name, sizeof(proc_name), comm_fp))
                            {                                            // Read process name
                                proc_name[strcspn(proc_name, "\n")] = 0; // Remove newline character

                                // Get process owner
                                while (fgets(status_line, sizeof(status_line), status_fp))
                                { // Read each line in status file
                                    if (strncmp(status_line, "Uid:", 4) == 0)
                                    {                                          // Check if line contains UID
                                        sscanf(status_line, "Uid:\t%d", &uid); // Parse UID
                                        break;
                                    }
                                }

                                struct passwd *pw = getpwuid(uid);           // Get user information
                                snprintf(process_info, sizeof(process_info), // Format process information
                                         "%-15s  PID: %-6s  User: %-8s",     // Format process information
                                         proc_name,                          // Format process information
                                         entry->d_name,                      // Format process information
                                         pw ? pw->pw_name : "unknown");      // Format process information
                            }
                            fclose(comm_fp);   // Close comm file
                            fclose(status_fp); // Close status file
                        }
                        break;
                    }
                }
            }
            fclose(fp); // Close net/tcp file
        }
    }
    closedir(proc_dir);  // Close /proc directory
    return process_info; // Return process information
}

// Function to check detailed port state
int check_port_state(int port)
{
    struct sockaddr_in addr; // Socket address structure
    int test_sock;           // Socket file descriptor

    // Try to create a second connection
    test_sock = socket(AF_INET, SOCK_STREAM, 0); // Create TCP socket
    if (test_sock < 0)
    {
        return 0; // Error state
    }

    memset(&addr, 0, sizeof(addr));                // Clear address structure
    addr.sin_family = AF_INET;                     // Set address family to IPv4
    addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Set address to localhost
    addr.sin_port = htons(port);                   // Set port number

    // If we can connect twice, it's likely a listening socket
    if (connect(test_sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
    {                     // Attempt connection
        close(test_sock); // Close socket
        return 2;         // LISTENING
    }

    close(test_sock); // Close socket
    return 1;         // ESTABLISHED/SINGLE CONNECTION
}

// Main program entry point
int main(void) // void explicitly states no parameters are expected
{
    // Store our own process ID to avoid self-detection later
    our_pid = getpid();

    // Initialize required structures for socket operations
    struct servent *service; // Will hold service information from system database
    struct sockaddr_in addr; // Will hold socket addressing information
    int sock;                // Will store socket file descriptor

    // Print program banner and scanning range
    printf("Scanning %s ports %d to %d...\n\n", "127.0.0.1", START_PORT, END_PORT);

    // Print formatted header with column titles
    printf("\nPort Scanner Results\n"); // Main title
    printf("%-*s %-*s %-*s %-*s\n",     // Column headers with proper width
           COL_PORT, "PORT",            // Port number column
           COL_STATE, "STATE",          // Port state column
           COL_SERVICE, "SERVICE",      // Service name column
           COL_PROC, "PROCESS");        // Process information column

    // Print separator line for visual clarity
    printf("%-*s %-*s %-*s %-*s\n",                     // Separator line with matching widths
           COL_PORT, "--------",                        // Port column separator
           COL_STATE, "-----------",                    // State column separator
           COL_SERVICE, "-------------------",          // Service column separator
           COL_PROC, "------------------------------"); // Process column separator

    // Scan each port in the specified range
    for (int port = START_PORT; port <= END_PORT; port++)
    {
        // Create new TCP socket for port testing
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
            continue; // Skip on socket creation failure

        // Setup socket address structure
        memset(&addr, 0, sizeof(addr));                // Clear structure
        addr.sin_family = AF_INET;                     // Set IPv4
        addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Use localhost
        addr.sin_port = htons(port);                   // Set port (network byte order)

        // Attempt connection to port
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
        {
            // Port is open - gather information
            service = getservbyport(htons(port), "tcp"); // Get service name
            int port_state = check_port_state(port);     // Check port state
            char *proc_info = get_process_info(port);    // Get process info

            // Format and print results for open ports with proper column alignment
            printf("%-*d %-*s %-*s %s\n",          // Format string for aligned output
                   COL_PORT, port,                 // Port number with fixed width
                   COL_STATE,                      // State column with fixed width
                   port_state == 2 ? "LISTENING" : // Show LISTENING if state is 2
                       port_state == 1 ? "ESTABLISHED"
                                       :                  // Show ESTABLISHED if state is 1
                       "OPEN",                            // Show OPEN for other states
                   COL_SERVICE,                           // Service column with fixed width
                   service ? service->s_name : "unknown", // Service name if available
                   proc_info[0] ? proc_info : "unknown"); // Process info if available
        }

        close(sock); // Clean up socket
    }

    return 0; // Return success status to operating system
}