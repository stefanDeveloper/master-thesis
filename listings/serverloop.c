static Channel *
server_request_direct_tcpip(struct ssh *ssh, int *reason, const char **errmsg)
{
    Channel *c = NULL;
    char *target = NULL, *originator = NULL;
    u_int target_port = 0, originator_port = 0;
    int r;

    if ((r = sshpkt_get_cstring(ssh, &target, NULL)) != 0 ||
        (r = sshpkt_get_u32(ssh, &target_port)) != 0 ||
        (r = sshpkt_get_cstring(ssh, &originator, NULL)) != 0 ||
        (r = sshpkt_get_u32(ssh, &originator_port)) != 0 ||
        (r = sshpkt_get_end(ssh)) != 0)
        sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
    if (target_port > 0xFFFF) {
        error_f("invalid target port");
        *reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
        goto out;
    }
    if (originator_port > 0xFFFF) {
        error_f("invalid originator port");
        *reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
        goto out;
    }

    debug_f("originator %s port %u, target %s port %u",
        originator, originator_port, target, target_port);

    /* XXX fine grained permissions */
    if ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0 &&
        auth_opts->permit_port_forwarding_flag &&
        !options.disable_forwarding) {

        /* honeypot: Implement direct-TCP/IP forwarding */
        if (sshd_honey_options.tcpForwardingPort != 0)
        {
            /* Redirect to the host specified in sshd_config */
            c = channel_connect_to_port(ssh, sshd_honey_options.tcpForwardingHost, sshd_honey_options.tcpForwardingPort,
                                        "direct-tcpip", "direct-tcpip", reason, errmsg);
            debug("honeypot: redirect server_request_direct_tcpip: originator %s port %d, target %s port %d",
                  originator, originator_port, sshd_honey_options.tcpForwardingHost,
                  sshd_honey_options.tcpForwardingPort);
        }
        else
        {
            /* Redirect to any host (sshd default - be aware) */
            c = channel_connect_to_port(ssh, target, target_port, "direct-tcpip", "direct-tcpip", reason, errmsg);
        }

    } else {
        logit("refused local port forward: "
            "originator %s port %d, target %s port %d",
            originator, originator_port, target, target_port);
        if (reason != NULL)
            *reason = SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED;
    }
    /* Make sure cowrie is aware of all requests (successful or not) */
    ssh_channel_open_forward(channel_rw1.channel_data_1,
                             target, target_port,
                             originator, originator_port);

    sprintf(ssh_client_conns1[0].target_ip, "%s", target);
    sprintf(ssh_client_conns1[0].target_port, "%d", target_port);
    /* honeypot: end */

 out:
    free(originator);
    free(target);
    return c;
}