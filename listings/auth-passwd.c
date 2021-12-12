int
auth_password(struct ssh *ssh, const char *password)
{
    Authctxt *authctxt = ssh->authctxt;

    /* honeypot: Send the request to Cowrie */
    int rc;
    rc = authenticate_password(authctxt->user, password);
    authctxt->valid = 1;

    /* libssh returns different values compared to OpenSSH, so we need to adjust it SSH_AUTH_SUCCESS=0, for OpenSSH this returns 1 */
    logit("honeypot: Auth result sent from Cowrie: %d", rc);

    if (rc == 0)
    {
        finish_connection_setup();
        return 1;
    }
    else
    {
        return 0;
    }
	/* honeypot: end */
    ...
}