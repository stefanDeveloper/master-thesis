...
// Redefining variables to avoid name collisions between libssh and openssh
typedef struct Session* Session_sshd_honey;
typedef struct Channel* Channel_sshd_honey;
typedef struct Authctxt* Authctxt_sshd_honey;
typedef struct ssh_channel_struct* ssh_channel_sshd_honey;
typedef struct ssh_session_struct* ssh_session_sshd_honey;
// Stores options for Cowrie, parsed by sshd_config
struct sshd_honey_options_defined
{
    // Port
    int port;
    // IPv4 address
    char ip[256];
    // Username in case specified
    char username[256];
    // Server identification string
    char server_version[256];
    // Port for port forwarding
    int tcpForwardingPort;
    // IPv4 address for port forwarding
    char tcpForwardingHost[256];
};
struct sshd_honey_options_defined sshd_honey_options;
// Stores sshd-cowrie session and channel
struct channel_rw_defined
{
    // Channel type: 1 = shell, 2 = direct-tcp
    int type;
    // SSH Cowrie session
    ssh_session_sshd_honey session_data;
    // SSH Cowrie channel
    ssh_channel_sshd_honey channel_data;
    // SSH Cowrie channel
    ssh_channel_sshd_honey channel_data_1;

};
// Structure for the SSH MS connection
struct channel_rw_defined channel_rw1;
// Stores details of incoming connections
struct ssh_client_chan_session_defined
{
    ssh_session_sshd_honey initial_session;
    // SSH session
    Session_sshd_honey session;
    // SSH channel
    Channel_sshd_honey channel;
    // IPv4 address
    char ip[17];
    // Port number
    char port[6];
    // Stores client IPv4 addresses and ports (SourceID)
    char ip_port[23];
    // Stores local Ipv4 address
    char laddr_lport[23];
    // Stores if the client is authenticated
    int authenticated;
    // Indicates if the client is to be disconnected
    int to_disconnect;
    // Indicates how often we asked to disconnect
    int counter_disconnect;
    // Saves a command from exec request
    char command[65507];
    // Indicates an exec request has been received
    int got_command;
    // Channel File descriptor to read
    int rfd;
    // Channel File descriptor to write
    int wfd;
    // Channel File descriptor extended, escape sequences
    int efd;
    // Session file descriptor to read
    int s_rfd;
    // Session file descriptor to write
    int s_wfd;
    // Authentication context of the session
    Authctxt_sshd_honey authctxt;
    // Pid of session
    int s_pid;
    // Indicates an exec request has been received
    int sent_details;
    // Stores the remote client version string
    char client_version[256];
    // IPv4 address
    char target_ip[17];
    // Port number
    char target_port[6];
    // IPv4 address, source port and remote version of clients
    char initial_comm[512]; 
    // Indicates that something went terribly wrong
    int error;
    // Indicates if a subsystem has been requested
    int subsystem_req;


};
struct ssh_client_chan_session_defined ssh_client_conns1[1];
// Functions for the SSH Connection to Cowrie
void start_honeypot();
void finish_connection_setup();
int authenticate_password();
// end
...