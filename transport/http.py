# This program is free software; you can redistribute it and/or modify
# it under the terms of the (LGPL) GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the 
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library Lesser General Public License for more details at
# ( http://www.gnu.org/licenses/lgpl.html ).
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# written by: Jeff Ortel ( jortel@redhat.com )

# modifications by: Beda Kosata (bedrich.kosata@nic.cz)

"""
Contains classes for basic HTTP transport implementations.
"""

import urllib2 as u2
import base64
import socket
from sudsds.transport import *
from sudsds.properties import Unskin
from urlparse import urlparse
from cookielib import CookieJar, DefaultCookiePolicy
from logging import getLogger
import httplib
import ssl

try:
    from pyopenssl_wrapper import PyOpenSSLSocket
except ImportError:
    PYOPENSSL_AVAILABLE = False
else:
    PYOPENSSL_AVAILABLE = True

log = getLogger(__name__)


class SUDSHTTPRedirectHandler(u2.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return a Request or None in response to a redirect.

        This is called by the http_error_30x methods,
        it was taken from the original Python version and modified
        to use POST when redirection takes place.
        This allows a SOAP message to be redirected without a loss
        of content.
        """
        m = req.get_method()
        if (code in (301, 302, 303, 307) and m in ("GET", "HEAD")
            or code in (301, 302, 303) and m == "POST"):
            newurl = newurl.replace(' ', '%20')
            newheaders = dict((k,v) for k,v in req.headers.items()
                              if k.lower() not in ("content-length", "content-type")
                             )
            log.debug("Redirecting to %s", newurl)
            return u2.Request(newurl,
                              data=req.data, # here we pass the original data
                              headers=newheaders,
                              origin_req_host=req.get_origin_req_host(),
                              unverifiable=True,
                              )
        else:
            raise u2.HTTPError(req.get_full_url(), code, msg, headers, fp)


class MyHTTPResponse(httplib.HTTPResponse):
  
  def __init__(self, sock, debuglevel=0, strict=0, method=None):
    
    httplib.HTTPResponse.__init__(self, sock, debuglevel, strict, method)


class CheckingHTTPSConnection(httplib.HTTPSConnection):
  """based on httplib.HTTPSConnection code - extended to support 
  server certificate verification and client certificate authorization"""
  
  response_class = MyHTTPResponse
  
  FORCE_SSL_VERSION = None
  SERVER_CERT_CHECK = True # might be turned off when a workaround is needed

  
  def __init__(self, host, ca_certs=None, cert_verifier=None,
               keyobj=None, certobj=None, **kw):
    """cert_verifier is a function returning either True or False
    based on whether the certificate was found to be OK,
    keyobj and certobj represent internal PyOpenSSL structures holding
    the key and certificate respectively.
    """
    httplib.HTTPSConnection.__init__(self, host, **kw)
    self.ca_certs = ca_certs
    self.cert_verifier = cert_verifier
    self.keyobj = keyobj
    self.certobj = certobj
    
  def connect(self):
    sock = socket.create_connection((self.host, self.port), self.timeout)
    if hasattr(self, '_tunnel_host') and self._tunnel_host:
        self.sock = sock
        self._tunnel()
    if self.FORCE_SSL_VERSION:
      add = {'ssl_version': self.FORCE_SSL_VERSION}
    else:
      add = {}
    if self.SERVER_CERT_CHECK and self.ca_certs:
      add['cert_reqs'] = ssl.CERT_REQUIRED
    else:
      add['cert_reqs'] = ssl.CERT_NONE
    # try to use PyOpenSSL by default
    if PYOPENSSL_AVAILABLE:
      wrap_class = PyOpenSSLSocket
      add['keyobj'] = self.keyobj
      add['certobj'] = self.certobj
      add['keyfile'] = self.key_file
      add['certfile'] = self.cert_file
    else:
      wrap_class = ssl.SSLSocket
    self.sock = wrap_class(sock, ca_certs=self.ca_certs, **add)
      #if self.cert_verifier and self.SERVER_CERT_CHECK:
      #  if not self.cert_verifier(self.sock.getpeercert()):
      #    raise Exception("Server certificate did not pass security check.",
      #                    self.sock.getpeercert())


class CheckingHTTPSHandler(u2.HTTPSHandler):
  
  def __init__(self, ca_certs=None, cert_verifier=None,
               client_certfile=None, client_keyfile=None,
               client_keyobj=None, client_certobj=None,
              *args, **kw):
    """cert_verifier is a function returning either True or False
    based on whether the certificate was found to be OK"""
    u2.HTTPSHandler.__init__(self, *args, **kw)
    self.ca_certs = ca_certs
    self.cert_verifier = cert_verifier
    self.client_keyfile = client_keyfile # filename
    self.client_certfile = client_certfile # filename
    self.keyobj = client_keyobj
    self.certobj = client_certobj
    #self.set_http_debuglevel(100)

  def https_open(self, req):
    def open(*args, **kw):
      new_kw = dict(ca_certs=self.ca_certs,
                    cert_verifier=self.cert_verifier,
                    cert_file=self.client_certfile,
                    key_file=self.client_keyfile,
                    keyobj=self.keyobj,
                    certobj=self.certobj)
      new_kw.update(kw)
      return CheckingHTTPSConnection(*args, **new_kw)
    return self.do_open(open, req)

  https_request = u2.AbstractHTTPHandler.do_request_


class HttpTransport(Transport):
    """
    HTTP transport using urllib2.  Provided basic http transport
    that provides for cookies, proxies but no authentication.
    """
    
    def __init__(self, ca_certs=None, cert_verifier=None,
                 client_keyfile=None, client_certfile=None,
                 client_keyobj=None, client_certobj=None,
                 cookie_callback=None, user_agent_string=None,
                 **kwargs):
        """
        @param kwargs: Keyword arguments.
            - B{proxy} - An http proxy to be specified on requests.
                 The proxy is defined as {protocol:proxy,}
                    - type: I{dict}
                    - default: {}
            - B{timeout} - Set the url open timeout (seconds).
                    - type: I{float}
                    - default: 90
            - B{cache} - The http I{transport} cache.  May be set (None) for no caching.
                    - type: L{Cache}
                    - default: L{NoCache}
                    
        cert_verifier is a function returning either True or False
        based on whether the certificate was found to be OK
        """
        Transport.__init__(self)
        Unskin(self.options).update(kwargs)
        self.cookiejar = CookieJar(DefaultCookiePolicy())
        self.cookie_callback = cookie_callback
        self.user_agent_string = user_agent_string
        log.debug("Proxy: %s", self.options.proxy)
        from dslib.network import ProxyManager
        proxy_handler = ProxyManager.HTTPS_PROXY.create_proxy_handler()
        proxy_auth_handler = ProxyManager.HTTPS_PROXY.create_proxy_auth_handler()
        if ca_certs or (client_keyfile and client_certfile):
          https_handler = CheckingHTTPSHandler(ca_certs=ca_certs,
                                               cert_verifier=cert_verifier,
                                               client_keyfile=client_keyfile,
                                               client_certfile=client_certfile,
                                               client_keyobj=client_keyobj,
                                               client_certobj=client_certobj)
        else:
          https_handler = u2.HTTPSHandler()
        self.urlopener = u2.build_opener(SUDSHTTPRedirectHandler(),
                                         u2.HTTPCookieProcessor(self.cookiejar),
                                         https_handler)
        if proxy_handler:
          self.urlopener.add_handler(proxy_handler)
        if proxy_auth_handler:
          self.urlopener.add_handler(proxy_auth_handler)
        self.urlopener.addheaders = [('User-agent', self.user_agent_string)]
          
    def _fill_in_cookies(self, force_refresh=False):
        if self.cookie_callback:
            jar = self.cookie_callback(force_refresh=force_refresh)
            if jar:
                for cookie in jar:
                    self.cookiejar.set_cookie(cookie)
                                                              
    def open(self, request):
        if not request.url.startswith("file://"):
            self._fill_in_cookies()
        try:
            url = request.url
            cache = self.options.cache
            fp = cache.get(url)
            if fp is not None:
                log.debug('opening (%s), cached', url)
                return fp
            log.debug('opening (%s)', url)
            u2request = u2.Request(url)
            #self.__setproxy(url, u2request)
            fp = self.__open(u2request)
            return cache.put(url, fp)
        except u2.HTTPError, e:
            raise TransportError(str(e), e.code, e.fp)

    def send(self, request):
        if not request.url.startswith("file://"):
            self._fill_in_cookies()
        result = None
        url = request.url
        msg = request.message
        headers = request.headers
        force_cookie_refresh = False
        while True:
          if force_cookie_refresh:
            self._fill_in_cookies(force_refresh=True)
          try:            
              u2request = u2.Request(url, msg, headers)
              self.__addcookies(u2request)
              #self.__setproxy(url, u2request)
              request.headers.update(u2request.headers)
              log.debug('sending:\n%s', request)
              if self.options.proxy:
                if not u2request._tunnel_host and u2request.origin_req_host != u2request.host:
                  u2request._tunnel_host = u2request.origin_req_host
              fp = self.__open(u2request)
              self.__getcookies(fp, u2request)
              result = Reply(200, fp.headers.dict, fp.read())
              log.debug('received:\n%s', result)
          except u2.HTTPError, e:
              if e.code in (202,204):
                  result = None
                  return result
              elif e.code == 400 and self.cookie_callback:
                  force_cookie_refresh = True
              else:
                  raise TransportError(e.msg, e.code, e.fp)
          else:
            return result

    def __addcookies(self, u2request):
        self.cookiejar.add_cookie_header(u2request)
        u2request.type = None # nasty hack to get around a bug in urllib2
                              # that causes infinite loop when type==https
                              # and has_proxy is called (it looks for non-existent
                              # __r_host
        
    def __getcookies(self, fp, u2request):
        self.cookiejar.extract_cookies(fp, u2request)
        
    def __open(self, u2request):
        def do():
          if self.urlopener is None:
              return u2.urlopen(u2request)
          else:
              return self.urlopener.open(u2request)

        socket.setdefaulttimeout(self.options.timeout)
        for i in range(3):
          # try this 3 times to allow for all workarounds to be applied
          try:
              return do()
          except u2.URLError, e:
              if "SSL23_GET_SERVER_HELLO" in str(e):
                # this is a work-around for an incompatibility of openssl-1.0.0beta
                # with the login.czebox.cz sites HTTPS interface
                # more info here: https://bugzilla.redhat.com/show_bug.cgi?id=537822
                # the workaround breaks things on other systems, so it is applied
                # on an on-demand basis
                log.warning("Activating SSL workaround")
                CheckingHTTPSConnection.FORCE_SSL_VERSION = ssl.PROTOCOL_SSLv3
              elif "ASN1_item_verify:unknown message digest algorithm" in str(e):
                # this bug was reported but is present for now
                # see: http://bugs.python.org/issue8484
                log.warning("Turning off server certificate check to work \
around a bug in Python")
                CheckingHTTPSConnection.SERVER_CERT_CHECK = False
              else:
                raise e
        # if we get here, we passed three rounds and did not return
        # - something went wrong
        raise
        
    def __setproxy(self, url, u2request):
        protocol = urlparse(url)[0]
        proxy = self.options.proxy.get(protocol, None)
        if proxy is None:
            return
        protocol = u2request.type
        u2request.set_proxy(proxy, protocol)
        
    def __deepcopy__(self, memo={}):
        clone = self.__class__()
        p = Unskin(self.options)
        cp = Unskin(clone.options)
        cp.update(p)
        return clone


class HttpAuthenticated(HttpTransport):
    """
    Provides basic http authentication for servers that don't follow
    the specified challenge / response model.  This implementation
    appends the I{Authorization} http header with base64 encoded
    credentials on every http request.
    """
    
    def send(self, request):
        credentials = self.credentials()
        if not (None in credentials):
            encoded = base64.encodestring(':'.join(credentials))
            basic = 'Basic %s' % encoded[:-1]
            request.headers['Authorization'] = basic
        return HttpTransport.send(self, request)
                 
    def credentials(self):
        return (self.options.username, self.options.password)
