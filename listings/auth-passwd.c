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