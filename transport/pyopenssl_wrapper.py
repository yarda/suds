"""
This is just a simple copy of the ssl.py module contained in the Python
standard library. It was modified to work with PyOpenSSL and only to the
extent that it works with the DS server. It might not work for any other
purpose.
"""

import textwrap

import _ssl             # if we can't import it, let the error propagate

from _ssl import SSLError
from _ssl import CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
from _ssl import PROTOCOL_SSLv2, PROTOCOL_SSLv3, PROTOCOL_SSLv23, PROTOCOL_TLSv1
from _ssl import RAND_status, RAND_egd, RAND_add
from _ssl import \
     SSL_ERROR_ZERO_RETURN, \
     SSL_ERROR_WANT_READ, \
     SSL_ERROR_WANT_WRITE, \
     SSL_ERROR_WANT_X509_LOOKUP, \
     SSL_ERROR_SYSCALL, \
     SSL_ERROR_SSL, \
     SSL_ERROR_WANT_CONNECT, \
     SSL_ERROR_EOF, \
     SSL_ERROR_INVALID_ERROR_CODE

from socket import socket, _fileobject
from socket import getnameinfo as _getnameinfo
import base64        # for DER-to-PEM translation

# the OpenSSL stuff

import OpenSSL

_ssl_to_openssl_cert_op_remap = {
  CERT_NONE: OpenSSL.SSL.VERIFY_NONE,
  CERT_OPTIONAL: OpenSSL.SSL.VERIFY_PEER,
  CERT_REQUIRED: OpenSSL.SSL.VERIFY_PEER|OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT
  }
  
_ssl_to_openssl_version_remap = {
  PROTOCOL_SSLv2: OpenSSL.SSL.SSLv2_METHOD, 
  PROTOCOL_SSLv3: OpenSSL.SSL.SSLv3_METHOD, 
  PROTOCOL_SSLv23: OpenSSL.SSL.SSLv23_METHOD, 
  PROTOCOL_TLSv1: OpenSSL.SSL.TLSv1_METHOD,                                   
  }
  
class PyOpenSSLSocket (socket):

    """This class implements a subtype of socket.socket that wraps
    the underlying OS socket in an SSL context when necessary, and
    provides read and write methods over that channel."""

    def __init__(self, sock, keyfile=None, certfile=None,
                 server_side=False, cert_reqs=CERT_NONE,
                 ssl_version=PROTOCOL_SSLv23, ca_certs=None,
                 do_handshake_on_connect=True,
                 suppress_ragged_eofs=True,
                 keyobj=None, certobj=None):
        socket.__init__(self, _sock=sock._sock)
        # the initializer for socket trashes the methods (tsk, tsk), so...
        self.send = lambda data, flags=0: PyOpenSSLSocket.send(self, data, flags)
        self.sendto = lambda data, addr, flags=0: PyOpenSSLSocket.sendto(self, data, addr, flags)
        self.recv = lambda buflen=1024, flags=0: PyOpenSSLSocket.recv(self, buflen, flags)
        self.recvfrom = lambda addr, buflen=1024, flags=0: PyOpenSSLSocket.recvfrom(self, addr, buflen, flags)
        self.recv_into = lambda buffer, nbytes=None, flags=0: PyOpenSSLSocket.recv_into(self, buffer, nbytes, flags)
        self.recvfrom_into = lambda buffer, nbytes=None, flags=0: PyOpenSSLSocket.recvfrom_into(self, buffer, nbytes, flags)

        if certfile and not keyfile:
            keyfile = certfile
        # see if it's connected
        try:
            socket.getpeername(self)
        except:
            # no, no connection yet
            self._sslobj = None
        else:
            # yes, create the SSL object
            self._sslobj = sslwrap(self._sock, server_side,
                                   keyfile, certfile,
                                   cert_reqs, ssl_version, ca_certs,
                                   keyobj=keyobj, certobj=certobj)
            if do_handshake_on_connect:
                timeout = self.gettimeout()
                try:
                    self.settimeout(None)
                    self.do_handshake()
                finally:
                    self.settimeout(timeout)
        self.keyfile = keyfile
        self.certfile = certfile
        self.cert_reqs = cert_reqs
        self.ssl_version = ssl_version
        self.ca_certs = ca_certs
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self._makefile_refs = 0
        self.keyobj = keyobj
        self.certobj = certobj

    def read(self, len=1024):

        """Read up to LEN bytes and return them.
        Return zero-length string on EOF."""

        try:
            return self._sslobj.read(len)
        except SSLError, x:
            if x.args[0] == SSL_ERROR_EOF and self.suppress_ragged_eofs:
                return ''
            else:
                raise

    def write(self, data):

        """Write DATA to the underlying SSL channel.  Returns
        number of bytes of DATA actually transmitted."""

        return self._sslobj.write(data)

    def getpeercert(self, binary_form=False):

        """Returns a formatted version of the data in the
        certificate provided by the other end of the SSL channel.
        Return None if no certificate was provided, {} if a
        certificate was provided, but not validated."""

        return self._sslobj.get_peer_certificate()

    def cipher (self):

        if not self._sslobj:
            return None
        else:
            return self._sslobj.cipher()

    def send (self, data, flags=0):
        if self._sslobj:
            if flags != 0:
                raise ValueError(
                    "non-zero flags not allowed in calls to send() on %s" %
                    self.__class__)
            while True:
                try:
                    v = self._sslobj.write(data)
                except SSLError, x:
                    if x.args[0] == SSL_ERROR_WANT_READ:
                        return 0
                    elif x.args[0] == SSL_ERROR_WANT_WRITE:
                        return 0
                    else:
                        raise
                else:
                    return v
        else:
            return socket.send(self, data, flags)

    def sendto (self, data, addr, flags=0):
        if self._sslobj:
            raise ValueError("sendto not allowed on instances of %s" %
                             self.__class__)
        else:
            return socket.sendto(self, data, addr, flags)

    def sendall (self, data, flags=0):
        if self._sslobj:
            if flags != 0:
                raise ValueError(
                    "non-zero flags not allowed in calls to sendall() on %s" %
                    self.__class__)
            amount = len(data)
            count = 0
            while (count < amount):
                v = self.send(data[count:])
                count += v
            return amount
        else:
            return socket.sendall(self, data, flags)

    def recv (self, buflen=1024, flags=0):
        if self._sslobj:
            if flags != 0:
                raise ValueError(
                    "non-zero flags not allowed in calls to sendall() on %s" %
                    self.__class__)
            while True:
                try:
                    return self.read(buflen)
                except SSLError, x:
                    if x.args[0] == SSL_ERROR_WANT_READ:
                        continue
                    else:
                        raise x
        else:
            return socket.recv(self, buflen, flags)

    def recv_into (self, buffer, nbytes=None, flags=0):
        if buffer and (nbytes is None):
            nbytes = len(buffer)
        elif nbytes is None:
            nbytes = 1024
        if self._sslobj:
            if flags != 0:
                raise ValueError(
                  "non-zero flags not allowed in calls to recv_into() on %s" %
                  self.__class__)
            while True:
                try:
                    tmp_buffer = self.read(nbytes)
                    v = len(tmp_buffer)
                    buffer[:v] = tmp_buffer
                    return v
                except SSLError, x:
                    if x.args[0] == SSL_ERROR_WANT_READ:
                        continue
                    else:
                        raise x
        else:
            return socket.recv_into(self, buffer, nbytes, flags)

    def recvfrom (self, addr, buflen=1024, flags=0):
        if self._sslobj:
            raise ValueError("recvfrom not allowed on instances of %s" %
                             self.__class__)
        else:
            return socket.recvfrom(self, addr, buflen, flags)

    def recvfrom_into (self, buffer, nbytes=None, flags=0):
        if self._sslobj:
            raise ValueError("recvfrom_into not allowed on instances of %s" %
                             self.__class__)
        else:
            return socket.recvfrom_into(self, buffer, nbytes, flags)

    def pending (self):
        if self._sslobj:
            return self._sslobj.pending()
        else:
            return 0

    def unwrap (self):
        if self._sslobj:
            s = self._sslobj.shutdown()
            self._sslobj = None
            return s
        else:
            raise ValueError("No SSL wrapper around " + str(self))

    def shutdown (self, how):
        self._sslobj = None
        socket.shutdown(self, how)

    def close (self):
        if self._makefile_refs < 1:
            self._sslobj = None
            socket.close(self)
        else:
            self._makefile_refs -= 1

    def do_handshake (self):

        """Perform a TLS/SSL handshake."""

        self._sslobj.do_handshake()

    def connect(self, addr):

        """Connects to remote ADDR, and then wraps the connection in
        an SSL channel."""

        # Here we assume that the socket is client-side, and not
        # connected at the time of the call.  We connect it, then wrap it.
        if self._sslobj:
            raise ValueError("attempt to connect already-connected PyOpenSSLSocket!")
        socket.connect(self, addr)
        self._sslobj = sslwrap(self._sock, False, self.keyfile, self.certfile,
                               self.cert_reqs, self.ssl_version,
                               self.ca_certs,
                               keyobj=self.keyobj, certobj=self.certobj)
        if self.do_handshake_on_connect:
            self.do_handshake()

    def accept(self):

        """Accepts a new connection from a remote client, and returns
        a tuple containing that new connection wrapped with a server-side
        SSL channel, and the address of the remote client."""

        newsock, addr = socket.accept(self)
        return (PyOpenSSLSocket(newsock,
                          keyfile=self.keyfile,
                          certfile=self.certfile,
                          server_side=True,
                          cert_reqs=self.cert_reqs,
                          ssl_version=self.ssl_version,
                          ca_certs=self.ca_certs,
                          do_handshake_on_connect=self.do_handshake_on_connect,
                          suppress_ragged_eofs=self.suppress_ragged_eofs),
                addr)

    def makefile(self, mode='r', bufsize=-1):

        """Make and return a file-like object that
        works with the SSL connection.  Just use the code
        from the socket module."""

        self._makefile_refs += 1
        return _fileobject(self, mode, bufsize)



def wrap_socket(sock, keyfile=None, certfile=None,
                server_side=False, cert_reqs=CERT_NONE,
                ssl_version=PROTOCOL_SSLv23, ca_certs=None,
                do_handshake_on_connect=True,
                suppress_ragged_eofs=True):

    return PyOpenSSLSocket(sock, keyfile=keyfile, certfile=certfile,
                     server_side=server_side, cert_reqs=cert_reqs,
                     ssl_version=ssl_version, ca_certs=ca_certs,
                     do_handshake_on_connect=do_handshake_on_connect,
                     suppress_ragged_eofs=suppress_ragged_eofs)


def verify_connection(conn, x509, error_code, depth, ret_code):
    # no extra validation - just return whatever OpenSSL already
    # decided during its check
    return bool(ret_code)

def sslwrap(sock, server_side=False, keyfile=None, certfile=None,
            cert_reqs=CERT_NONE, ssl_version=PROTOCOL_SSLv23,
            ca_certs=None, keyobj=None, certobj=None):
    """this is modification of _ssl.sslwrap that uses PyOpenSSL,
    keyobj and certobj are new parameters allowing setting the 
    key and cert not by filename, but from internal PyOpenSSL
    structures.
    """
    ctx = OpenSSL.SSL.Context(_ssl_to_openssl_version_remap[ssl_version])
    if ca_certs:
      ctx.load_verify_locations(ca_certs)
    ctx.set_verify(_ssl_to_openssl_cert_op_remap[cert_reqs], verify_connection)
    if keyobj:
      ctx.use_privatekey(keyobj)
    elif keyfile:
      ctx.use_privatekey_file(keyfile)
    if certobj:
      ctx.use_certificate(certobj)
    elif certfile:
      ctx.use_certificate_file(certfile)
    ctx.set_options(0x4000) # THIS IS THE KEY TO SUCCESS OF DS
    ssl_sock = OpenSSL.SSL.Connection(ctx, sock)
    ssl_sock.setblocking(True)
    ssl_sock.set_connect_state()
    return ssl_sock
