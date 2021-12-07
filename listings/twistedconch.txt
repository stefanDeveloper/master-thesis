def getPacket(self):
    ...
    if packetLen > 1048576: # 1024 ** 2
        self.sendDisconnect(DISCONNECT_PROTOCOL_ERROR,
                            'bad packet length %s' % packetLen)
    return
    ...