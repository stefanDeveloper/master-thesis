def _unsupportedVersionReceived(self, remoteVersion: bytes) -> None:
    """
    Change message to be like OpenSSH
    """
    self.transport.write(b"Protocol major versions differ.\n")
    self.transport.loseConnection()

def dataReceived(self, data: bytes) -> None
    ...
    if not self.gotVersion:
        ...
        self.otherVersionString = self.buf.split(b"\n")[0].strip()
        ...
        # Checks if the version string has a correct format
        m = re.match(br"SSH-(\d+.\d+)-(.*)", self.otherVersionString)
        if m is None:
            ...
            self.transport.write(b"Invalid SSH identification string.\n")
            self.transport.loseConnection()
            return
        else:
            ...
            # Checks if version string is either 1.99 or 2.0
            if remote_version not in self.supportedVersions:
                self._unsupportedVersionReceived(self.otherVersionString)
                return
            ...
        ...
    ...