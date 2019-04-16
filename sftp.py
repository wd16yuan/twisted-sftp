#!/bin/env python
#-*- coding:utf-8 -*-
from sys import stdout

from twisted.python import log, failure
from twisted.conch import error
from twisted.internet import defer
from twisted.python.log import startLogging, err

from twisted.internet import reactor

from twisted.conch.ssh.common import NS
from twisted.conch.scripts.cftp import ClientOptions
from twisted.conch.ssh.filetransfer import FileTransferClient, FXF_WRITE, FXF_CREAT, FXF_READ
from twisted.conch.client.connect import connect
from twisted.conch.client.default import isInKnownHosts

from twisted.conch.ssh.connection import SSHConnection
from twisted.conch.ssh.channel import SSHChannel

from twisted.conch.ssh import keys, userauth
from twisted.python.filepath import FilePath

def verifyHostKey(transport, host, pubKey, fingerprint):
    
    isr = isInKnownHosts(host, pubKey, transport.factory.options)
    if isr == 0:
        return defer.fail(error.ConchError('Not existent key'))
    elif isr == 1:
        return defer.succeed(isr)
    elif isr == 2:
        return defer.fail(error.ConchError('Changed key'))
    else:
        return defer.fail(error.ConchError('Unknown return %s' % isr))

class SSHUserAuthClient(userauth.SSHUserAuthClient):
    def __init__(self, user, options, *args):
        userauth.SSHUserAuthClient.__init__(self, user, *args)
        self.options = options
        self._tried_key = False

    def getPublicKey(self):
        if self._tried_key:
            return
        pubkey = FilePath(self.options['pubkey'])
        if not pubkey.isfile():
            return None
        try:
            key = keys.Key.fromFile(pubkey.path)
            self._tried_key = True
            return key
        except keys.BadKeyError:
            return None
        
    def getPrivateKey(self):
        privkey = FilePath(self.options['privkey'])
        if not privkey.isfile():
            return None
        try:
            log.msg(privkey.path)
            return defer.succeed(keys.Key.fromFile(privkey.path))
        except keys.EncryptedKeyError:
            return defer.fail(ConchError("Encrypted private-key: %s" % privkey.path))

class SFTPSession(SSHChannel):
    name = 'session'

    def channelOpen(self, whatever):
        d = self.conn.sendRequest(
            self, 'subsystem', NS('sftp'), wantReply=True)
        d.addCallbacks(self._cbSFTP)

    def _cbSFTP(self, result):
        client = FileTransferClient()
        client.makeConnection(self)
        self.dataReceived = client.dataReceived
        self.conn._sftp.callback(client)
        
class SFTPConnection(SSHConnection):
    def serviceStarted(self):
        self.openChannel(SFTPSession())

class SftpClient(object):
    port = 22
    user = "root"
    privkey = "ftp_ssh_key"
    pubkey = "ftp_ssh_key.pub"
    numRequests = 5
    bufferSize = 32768
    def __init__(self, host):
        self.host = host
    
    @defer.inlineCallbacks    
    def put(self, local_file, remote_file):
        lf = FilePath(local_file)
        if not lf.isfile():
            defer.returnValue("Cannot find file: %s" % local_file)
        
        conn = yield self.doConnect()
        yield self._putRemoteFile(conn, local_file, remote_file)
        
    def doConnect(self):
        options = ClientOptions()
        options['host'] = self.host
        options['port'] = self.port
        options['pubkey'] = self.pubkey
        options['privkey'] = self.privkey
        conn = SFTPConnection()
        conn._sftp = defer.Deferred()
        auth = SSHUserAuthClient(self.user, options, conn)
        connect(self.host, self.port, options, verifyHostKey, auth)
        return conn._sftp
    
    @defer.inlineCallbacks
    def _putRemoteFile(self, conn, local_file, remote_file):
        lf = file(local_file, "rb")
        rf  = yield conn.openFile(remote_file, FXF_WRITE | FXF_CREAT, dict())
        yield self._cbPutOpenFile(lf, rf)
    
    @defer.inlineCallbacks
    def _cbPutOpenFile(self, lf, rf):
        dList = []
        chunks = []
        for i in range(self.numRequests):
            d = self._cbPutWrite(None, lf, rf, chunks)
            if d:
                dList.append(d)
        lr = yield defer.DeferredList(dList, fireOnOneErrback=1)
        self._cbPutDone(lr, lf, rf)
        
    @defer.inlineCallbacks
    def _cbPutWrite(self, ignored, lf, rf, chunks):
        chunk = self._getNextChunk(chunks)
        start, size = chunk
        lf.seek(start)
        data = lf.read(size)
        if data:
            ignored = yield rf.writeChunk(start, data)
            _pwr = yield self._cbPutWrite(ignored, lf, rf, chunks)
            defer.returnValue(_pwr)
        else:
            defer.returnValue("Write completion")
    
    def _cbPutDone(self, ignored, lf, rf):
        lf.close()
        rf.close()
        return 'Transferred %s to %s' % (lf.name, rf.name)
    
    def _cbGetDone(self, ignored, lf, rf):
        lf.close()
        rf.close()
        return "Transferred %s to %s" % (rf.name, lf.name)

    def _getNextChunk(self, chunks):
        end = 0
        for chunk in chunks:
            if end == 'eof':
                return # nothing more to get
            if end != chunk[0]:
                i = chunks.index(chunk)
                chunks.insert(i, (end, chunk[0]))
                return (end, chunk[0] - end)
            end = chunk[1]
        chunks.append((end, end + self.bufferSize))
        return (end, self.bufferSize)
    
    @defer.inlineCallbacks
    def get(self, local_file, remote_file):
        lf = FilePath(local_file)
        if lf.isfile():
            defer.returnValue("File already exists: %s" % local_file)
        
        conn = yield self.doConnect()
        yield self._getRemoteFile(conn, local_file, remote_file)
        
    @defer.inlineCallbacks
    def _getRemoteFile(self, conn, local_file, remote_file):
        lf = file(local_file, "wb", 0)
        rf = yield conn.openFile(remote_file, FXF_READ, dict())
        yield self._cbGetOpenFile(lf, rf)
    
    @defer.inlineCallbacks    
    def _cbGetOpenFile(self, lf , rf):
        dList = []
        chunks = []
        for i in range(self.numRequests):
            d = self._cbGetRead("", lf, rf, chunks, 0, self.bufferSize)
            dList.append(d)
        lr = yield defer.DeferredList(dList, fireOnOneErrback=1)
        self._cbGetDone(lr, lf, rf)
    
    @defer.inlineCallbacks
    def _cbGetRead(self, data, lf, rf, chunks, start, size):
        if data and isinstance(data, failure.Failure):
            log.err("Get read err: %s" % data)
            reason = data
            try:
                reason.trap(EOFError)
            except Exception, e:
                defer.returnValue(e.message)
            i = chunks.index((start, start + size))
            del chunks[i]
            chunks.insert(i, (start, 'eof'))
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
            defer.returnValue("Read completion")
        else:
            start, length = chunk
        try:
            _cbr = yield rf.readChunk(start, length)
        except Exception, e:
            _cbr = failure.Failure(e)
        _grr = yield self._cbGetRead(_cbr, lf, rf, chunks, start, length)
        defer.returnValue(_grr)
        
if __name__ == '__main__':
    log.startLogging(stdout)
    sc = SftpClient("your_host")
    sc.get("local_filename", "host_filename")
    #sc.put("local_filename", "host_filename")
    reactor.run()
