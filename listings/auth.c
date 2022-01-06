int
allowed_user(struct ssh *ssh, struct passwd * pw)
{
    /* allow any user */
    return 1;
    /* end */
    ...
}