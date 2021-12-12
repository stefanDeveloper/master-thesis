...
//===========================================================================
// # sshd-honeypot: add code start
// Most of the variables we need are defined here */

// Redefining variables to avoid name collisions between libssh and openssh
typedef struct Session* Session_sshd_honey;
typedef struct Channel* Channel_sshd_honey;
typedef struct Authctxt* Authctxt_sshd_honey;
typedef struct ssh_channel_struct* ssh_channel_sshd_honey;
typedef struct ssh_session_struct* ssh_session_sshd_honey;

// Stores options for the MasterServer(MS),i.e. Cowrie, parsed by sshd_config
struct sshd_honey_options_defined
{
    int port;                                               // Port
    char ip[256];                                           // IPv4 address
    char username[256];                                     // Username in case specified
    char server_version[256];                               // Server identification string
    int tcpForwardingPort;                                  // Port for port forwarding
    char tcpForwardingHost[256];                            // IPv4 address for port forwarding
};
struct sshd_honey_options_defined sshd_honey_options;


// Stores sshd-cowrie session and channel
struct channel_rw_defined
{
    int type;                                                          // Channel type: 1 = shell, 2 = direct-tcp
    ssh_session_sshd_honey session_data;                               // SSH MS session
    ssh_channel_sshd_honey channel_data;                               // SSH MS channel
    ssh_channel_sshd_honey channel_data_1;                             // SSH MS channel

};
struct channel_rw_defined channel_rw1;                                 // Structure for the SSH MS connection



// Stores details of incoming connections
struct ssh_client_chan_session_defined
{
    ssh_session_sshd_honey initial_session;
    Session_sshd_honey session;             // SSH session
    Channel_sshd_honey channel;             // SSH channel
    char ip[17];                            // IPv4 address
    char port[6];                           // Port number
    char ip_port[23];                       // Stores client IPv4 addresses and ports (SourceID)
    char laddr_lport[23];                   // Stores local Ipv4 address
    int authenticated;                      // Stores if the client is authenticated 0=no, 1=yes
    int to_disconnect;                      // Indicates if the client is to be disconnected 0=no, 1=yes
    int counter_disconnect;                 // Indicates how often we asked to disconnect
    char command[65507];                    // Saves a command from exec request
    int got_command;                        // Indicates an exec request has been received (1/0)
    int rfd;                                // Channel File descriptor to read
    int wfd;                                // Channel File descriptor to write
    int efd;                                // Channel File descriptor extended (escape sequences)
    int s_rfd;                              // Session file descriptor to read
    int s_wfd;                              // Session file descriptor to write
    Authctxt_sshd_honey authctxt;           // Authentication context of the session (must be set to 1 to proceed)
    int s_pid;                              // Pid of session
    int sent_details;                       // Indicates an exec request has been received (1/0)
    char client_version[256];               // Stores the remote client version string
    char target_ip[17];                     // IPv4 address
    char target_port[6];                    // Port number
    char initial_comm[512];                 //Ipv4 address, source port and remote version of clients
    int error;                              // Indicates that something went terribly wrong (e.g. no Connection to Cowrie)
    int subsystem_req;                      // Indicates if a subsystem has been requested


};
struct ssh_client_chan_session_defined ssh_client_conns1[1];

// Functions for the SSH Connection to Cowrie
void start_honeypot();
void finish_connection_setup();
int authenticate_password();

// # sshd-honeypot: add code end
//===========================================================================
...