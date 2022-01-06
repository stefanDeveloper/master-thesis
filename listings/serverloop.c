static Channel *
server_request_direct_tcpip(struct ssh *ssh, int *reason, const char **errmsg)
{
    ...
        ...
        /* Implement direct-TCP/IP forwarding */
        if (sshd_honey_options.tcpForwardingPort != 0)
        {
            /* Redirect to the host specified in sshd_config */
            c = channel_connect_to_port(
                    ssh, 
                    sshd_honey_options.tcpForwardingHost, 
                    sshd_honey_options.tcpForwardingPort,
                    "direct-tcpip", 
                    "direct-tcpip", 
                    reason,
                    errmsg
                );
        }
        else
        {
            /* Redirect to any host */
            c = channel_connect_to_port(ssh, target, target_port, "direct-tcpip", "direct-tcpip", reason, errmsg);
        }
    ...
    /* Make sure cowrie is aware of all requests (successful or not) */
    ssh_channel_open_forward(channel_rw1.channel_data_1,
                             target, target_port,
                             originator, originator_port);

    sprintf(ssh_client_conns1[0].target_ip, "%s", target);
    sprintf(ssh_client_conns1[0].target_port, "%d", target_port);
    ...
}