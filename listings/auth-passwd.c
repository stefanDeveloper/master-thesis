int
auth_password(struct ssh *ssh, const char *password)
{
    Authctxt *authctxt = ssh->authctxt;
    /* Send the request to Cowrie */
    int rc;
    rc = authenticate_password(authctxt->user, password);
    authctxt->valid = 1;
    /* libssh returns different values compared to OpenSSH, for SSH_AUTH_SUCCESS=0 returns 1 */
    if (rc == 0)
    {
        finish_connection_setup();
        return 1;
    }
    else
    {
        return 0;
    }
    /* end */
    ...
}
int authenticate_password(const char *username, const char *password)
{
    int rc = -1;
    /* No logins if we could not connect to Cowrie */
    if (ssh_client_conns1[0].error != 1)
    {
        rc = ssh_userauth_password(ssh_client_conns1[0].initial_session, username, password);
    }
    return rc;
}
int
allowed_user(struct ssh *ssh, struct passwd * pw)
{
    return 1;
}