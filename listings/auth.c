int
allowed_user(struct ssh *ssh, struct passwd * pw)
{
    /* OpenSSH Support: - allow any user */
    return 1;
    /* OpenSSH Support: end */
    ...
}