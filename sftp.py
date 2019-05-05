#!/bin/env python
#-*- coding:utf-8 -*-
import struct

from twisted.internet import defer
from twisted.python import log, failure
from twisted.python.filepath import FilePath

from twisted.conch import error
from twisted.conch.ssh.common import NS
from twisted.conch.ssh import keys, userauth
from twisted.conch.ssh.channel import SSHChannel
from twisted.conch.client.connect import connect
from twisted.conch.scripts.cftp import ClientOptions
from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.client.default import isInKnownHosts
from twisted.conch.ssh.filetransfer import FileTransferClient, FXF_WRITE, FXF_CREAT, FXF_READ

def verifyHostKey(transport, host, pubKey, fingerprint):
    
    retVal = isInKnownHosts(host, pubKey, transport.factory.options)
    if retVal == 1:
        return defer.succeed(retVal)
    elif retVal == 0:
        errmsg = "Not existent key"
    elif retVal == 2:
        errmsg = "Changed key"
    else:
        errmsg = "Unknown return %s" % retVal
    log.err(errmsg)
    return defer.fail(error.ConchError(errmsg))

class SSHUserAuthClient(userauth.SSHUserAuthClient):
    def __init__(self, user, options, *args):
        userauth.SSHUserAuthClient.__init__(self, user, *args)
        self.options = options
        self._tried_key = False

    def getPublicKey(self):
        if self._tried_key:
            return
        pubkey = FilePath(self.options["pubkey"])
        if not pubkey.isfile():
            log.err("PublicKey is not file: %s" % pubkey.path)
            return None
        try:
            key = keys.Key.fromFile(pubkey.path)
            self._tried_key = True
            return key
        except keys.BadKeyError:
            log.err("PublicKey is bad: %s" % pubkey.path)
            return None
        
    def getPrivateKey(self):
        privkey = FilePath(self.options["privkey"])
        if not privkey.isfile():
            log.err("Privkey is not file: %s" % privkey.path)
            return None
        try:
            #log.msg(privkey.path)
            return defer.succeed(keys.Key.fromFile(privkey.path))
        except keys.EncryptedKeyError:
            errmsg = "Encrypted private-key: %s" % privkey.path
            log.err(errmsg)
            return defer.fail(error.ConchError(errmsg))

class SFTPSession(SSHChannel):
    name = "session"

    def channelOpen(self, whatever):
        d = self.conn.sendRequest(
            self, "subsystem", NS("sftp"), wantReply=True)
        d.addCallbacks(self._cbSFTP)

    def _cbSFTP(self, result):
        client = FileTransferClient()
        client.makeConnection(self)
        self.dataReceived = client.dataReceived
        self.conn._sftp.callback((self.conn.transport, client))
        
class SFTPConnection(SSHConnection):
    def serviceStarted(self):
        self.openChannel(SFTPSession())

    def adjustWindow(self, channel, bytesToAdd):
        """
        rewrite 'adjustWindow' method, shielding log display
        """
        if channel.localClosed:
            return # we're already closed
        self.transport.sendPacket(93, struct.pack(">2L", self.channelsToRemoteChannel[channel], bytesToAdd))
        channel.localWindowLeft += bytesToAdd        

class SftpClient(object):
    numRequests = 5
    bufferSize = 32768
    deferListFail = [(False, 1)]
    def __init__(self, conn, client):
        self.conn = conn
        self.client = client
        
    def _getNextChunk(self, chunks):
        end = 0
        for chunk in chunks:
            if end == "eof":
                return # nothing more to get
            if end != chunk[0]:
                i = chunks.index(chunk)
                chunks.insert(i, (end, chunk[0]))
                return (end, chunk[0] - end)
            end = chunk[1]
        chunks.append((end, end + self.bufferSize))
        return (end, self.bufferSize)

    def close(self):
        self.conn.transport.loseConnection()
        self.client.transport.loseConnection()
        
    @defer.inlineCallbacks    
    def put(self, local_file, remote_file):
        lf = FilePath(local_file)
        if not lf.isfile():
            log.err("Cannot find file: %s" % local_file)
            defer.returnValue(1)
        rv = yield self._putRemoteFile(self.client, local_file, remote_file)
        defer.returnValue(rv)
    
    @defer.inlineCallbacks
    def _putRemoteFile(self, client, local_file, remote_file):
        lf = file(local_file, "rb")
        rf  = yield client.openFile(remote_file, FXF_WRITE | FXF_CREAT, dict())
        rv = yield self._cbPutOpenFile(lf, rf)
        defer.returnValue(rv)
    
    @defer.inlineCallbacks
    def _cbPutOpenFile(self, lf, rf):
        dList = []
        chunks = []
        for i in range(self.numRequests):
            d = self._cbPutWrite(None, lf, rf, chunks)
            if d:
                dList.append(d)
        try:
            lr = yield defer.DeferredList(dList, fireOnOneErrback=1, consumeErrors=1)
        except Exception, e:
            lr = self.deferListFail
            log.err(e.__str__())
        rv = self._transferDone(lr, lf, rf)
        defer.returnValue(rv)
        
    def _cbPutWrite(self, ignored, lf, rf, chunks):
        chunk = self._getNextChunk(chunks)
        start, size = chunk
        lf.seek(start)
        data = lf.read(size)
        if data:
            d = rf.writeChunk(start, data)
            d.addCallback(self._cbPutWrite, lf, rf, chunks)
            return d
        else:
            return 0
    
    def _transferDone(self, result_list, file_1, file_2):
        file_1.close()
        file_2.close()
        fail_list = filter(lambda _x:_x[1] != 0 or not _x[0], result_list)
        if not fail_list:    
            log.msg("Transferred %s to %s done" % (file_1.name, file_2.name))
            return 0
        else:
            log.msg("Transferred %s to %s fail" % (file_1.name, file_2.name))
            return 1

    @defer.inlineCallbacks
    def get(self, local_file, remote_file):
        lf = FilePath(local_file)
        if lf.isfile():
            log.err("File already exists: %s" % local_file)
            defer.returnValue(1)
        rv = yield self._getRemoteFile(self.client, local_file, remote_file)
        defer.returnValue(rv)
        
    @defer.inlineCallbacks
    def _getRemoteFile(self, client, local_file, remote_file):
        lf = file(local_file, "wb", 0)
        rf = yield client.openFile(remote_file, FXF_READ, dict())
        rv = yield self._cbGetOpenFile(lf, rf)
        defer.returnValue(rv)
    
    @defer.inlineCallbacks    
    def _cbGetOpenFile(self, lf , rf):
        dList = []
        chunks = []
        for i in range(self.numRequests):
            d = self._cbGetRead("", lf, rf, chunks, 0, self.bufferSize)
            dList.append(d)
        try:
            lr = yield defer.DeferredList(dList, fireOnOneErrback=1, consumeErrors=1)
        except Exception, e:
            lr = self.deferListFail
            log.err(e.__str__())
        rv = self._transferDone(lr, rf, lf)
        defer.returnValue(rv)
    
    def _cbGetRead(self, data, lf, rf, chunks, start, size):
        if data and isinstance(data, failure.Failure):
            #log.err("Get read err: %s" % data)
            reason = data
            reason.trap(EOFError)
            i = chunks.index((start, start + size))
            del chunks[i]
            chunks.insert(i, (start, "eof"))
        elif data:
            lf.seek(start)
            lf.write(data)
            if len(data) != size:
                log.err("Got less than we asked for: %i < %i" % (len(data), size))
                i = chunks.index((start, start + size))
                del chunks[i]
                chunks.insert(i, (start, start + len(data)))
        chunk = self._getNextChunk(chunks)
        if not chunk:
            return 0
        else:
            start, length = chunk
        d = rf.readChunk(start, length)
        d.addBoth(self._cbGetRead, lf, rf, chunks, start, length)
        return d
        
@defer.inlineCallbacks       
def doSFTPConnect(host, port=22, user="root", pubkey=None, privkey=None):
    options = ClientOptions()
    options["host"] = host
    options["port"] = port
    options["pubkey"] = pubkey
    options["privkey"] = privkey
    conn = SFTPConnection()
    conn._sftp = defer.Deferred()
    auth = SSHUserAuthClient(user, options, conn)
    yield connect(host, port, options, verifyHostKey, auth)
    server_conn, server_client = yield conn._sftp
    sftp_client = SftpClient(server_conn, server_client)
    defer.returnValue(sftp_client)
    
@defer.inlineCallbacks    
def transferFiles():
    # my test
    sftp_client = yield doSFTPConnect("192.168.1.236", port=22, user="root", pubkey="ftp_ssh_key.pub", 
                 privkey="ftp_ssh_key")
    pv = yield sftp_client.put("/usr/local/src/Django-1.8.4.tar.gz", "/root/Django-1.8.4.tar.gz")
    gv = yield sftp_client.get("glibc-2.15.tar.gz", "glibc-2.15.tar.gz")
    print "pv:%s \n gv:%s" % (pv, gv)
    yield sftp_client.close()     #  close this sftp client
    
if __name__ == "__main__":
    from sys import stdout
    from twisted.internet import reactor
    
    log.startLogging(stdout)
    transferFiles()
    reactor.run()
