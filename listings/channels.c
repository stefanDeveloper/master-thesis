static int
channel_handle_wfd(struct ssh *ssh, Channel *c,
   fd_set *readset, fd_set *writeset)
{
    ...
    /* honeypot: Implement channel logic to forward data to Cowrie */
    int nbytes;
    char buffer[65507] = {0};
    ssh_client_conns1[0].rfd = c->rfd;
    ssh_client_conns1[0].wfd = c->wfd;
    ssh_client_conns1[0].efd = c->efd;

    // Make sure the connection to Cowrie is alive, if not, close the sshd-client connection as well
    if (ssh_channel_is_open(channel_rw1.channel_data) &&
           !ssh_channel_is_eof(channel_rw1.channel_data))
    {
        // Read data from the channel (Cowrie)
        nbytes = ssh_channel_read_nonblocking(channel_rw1.channel_data, buffer, sizeof(buffer), 0);
        if (nbytes > 0 && ssh_client_conns1[0].got_command != 1 && ssh_client_conns1[0].subsystem_req != 1)
        {
            write(ssh_client_conns1[0].wfd, buffer, nbytes);
            logit("honeypot: Write from Cowrie: %s, bytes: %d", buffer, nbytes);
        }
        else if (nbytes > 0 && ssh_client_conns1[0].got_command == 1)
        {
            sshbuf_putf(&c->input, buffer, nbytes);
            logit("honeypot: Write from Cowrie exec_cmd: %s, bytes: %d", buffer, nbytes);
        }

    } else
    {
        if (ssh_client_conns1[0].counter_disconnect == 0)
        {
            logit("honeypot: Connection to Cowrie lost - Close all");
            ssh_client_conns1[0].to_disconnect = 1;
        }
    }
    /* honeypot */
    ...
}