#include "ssh_new/libssh.h"

int ssh_ms_is_running = 0;
int const size_buffer = 65507; // Define buffer size (MAX UDP SIZE 65507)

void start_honeypot()
// Creates the SSH connection to Cowrie
// 1. Raw socket
// 2. SSH logic
{
    // Initialisation for 1. Raw socket
    int clientSocket;
    struct sockaddr_in serverAddr;
    socklen_t addr_size;

    // Initialisation for 2. SSH logic
    int rc;
    int verbosity = SSH_LOG_WARNING;
    // SSH session
    ssh_session session;
    // Create a new session
    session = ssh_new();


    /* 1. Connect to Cowrie - raw socket*/
    clientSocket = socket(PF_INET, SOCK_STREAM, 0);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(sshd_honey_options.ip);
    serverAddr.sin_port = htons(sshd_honey_options.port);
    addr_size = sizeof serverAddr;

    if (connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size) < 0)
    {
        ssh_client_conns1[0].error = 1;
    }
    else
    {
        /* Communicate the clients IPv4 address, port number and ssh client version via the raw socket to Cowrie */
        sprintf(ssh_client_conns1[0].initial_comm, "%s%s", ssh_client_conns1[0].ip_port, ssh_client_conns1[0].client_version);
        if(send(clientSocket , ssh_client_conns1[0].initial_comm, strlen(ssh_client_conns1[0].initial_comm) , 0) < 0)
        {
            ssh_client_conns1[0].error = 1;
        }
        else
        {    /* 2. Setup the SSH logic*/
            ssh_options_set(session, SSH_OPTIONS_FD, &clientSocket);
            // SSH Master Server IP
            ssh_options_set(session, SSH_OPTIONS_HOST, sshd_honey_options.ip);
            // SSH Master Server Port
            ssh_options_set(session, SSH_OPTIONS_PORT, &sshd_honey_options.port);
            // SSH Verbosity Level
            ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
            // Create a SSH connection with the specified session options
            rc = ssh_connect(session);
            if (rc != SSH_OK)
            {
                ssh_client_conns1[0].error = 1;
            }
            else
            {
                // Save session
                ssh_client_conns1[0].initial_session = session;
                // Set defaults
                ssh_client_conns1[0].got_command = 0;
                ssh_client_conns1[0].sent_details = 0;
                ssh_client_conns1[0].subsystem_req = 0;
                ssh_client_conns1[0].counter_disconnect = 0;
            }
        }
    }
}

int rc;
int authenticate_password(const char *username, const char *password)
{
    fatal("sshd-honeypot: Auth with username: %s, password: %s", username, password);
    /* We do not allow logins if we could not connect to Cowrie */
    if (ssh_client_conns1[0].error != 1)
    {
        rc = ssh_userauth_password(ssh_client_conns1[0].initial_session, username, password);
    }
    else
    {
        rc = -1;
    }
    return rc;
}


void finish_connection_setup()
{
    // Create a channel pair
    ssh_channel channel;
    ssh_channel channel_1;
    channel = ssh_channel_new(ssh_client_conns1[0].initial_session);
    channel_rw1.channel_data = channel;
    channel_1 = ssh_channel_new(ssh_client_conns1[0].initial_session);
    channel_rw1.channel_data_1 = channel_1;
    // Open/request a channel
    ssh_channel_open_session(channel_rw1.channel_data);
    // Set type to 1, i.e. shell
    channel_rw1.type = 1;
    // Save session
    channel_rw1.session_data = ssh_client_conns1[0].initial_session;
}
// end

/*
 * Main program for the daemon.
 */
int
main(int ac, char **av)
{
    ...
    start_honeypot();
    ...
    // edit, reset server configurations
    // Set banner if not defined in sshd config
    if (strlen(sshd_honey_options.server_version) <= 0)
    {
        sprintf(sshd_honey_options.server_version, "%s", SSH_VERSION);
    }
    logit("sshd_honey: Deamon started with %s as server version", sshd_honey_options.server_version);
    ...
    // Get the socket and save ip address and port
    // Get IPv4 address and port number of the SSH connection
    sprintf(ssh_client_conns1[0].ip_port, "%s;%d;", ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
    sprintf(ssh_client_conns1[0].ip, "%s",ssh_remote_ipaddr(ssh));
    sprintf(ssh_client_conns1[0].port, "%d",ssh_remote_port(ssh));
    free(laddr);
    ...
}