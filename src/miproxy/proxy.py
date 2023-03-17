from __future__ import annotations

from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from os import path, listdir
from re import compile
from socket import socket
from socketserver import ThreadingMixIn, BaseServer
from ssl import wrap_socket
from sys import argv
from tempfile import gettempdir
from typing import Any, Callable, Union, Type
from urllib.parse import urlparse, urlunparse, ParseResult

from OpenSSL.crypto import FILETYPE_PEM, X509Extension, X509, dump_privatekey, dump_certificate, load_certificate, \
    load_privatekey, PKey, TYPE_RSA, X509Req

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PyMiProxy Project'
__credits__ = ['Nadeem Douba']

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

__all__ = [
    'CertificateAuthority',
    'ProxyHandler',
    'RequestInterceptorPlugin',
    'ResponseInterceptorPlugin',
    'MitmProxy',
    'AsyncMitmProxy',
    'InvalidInterceptorPluginException'
]


class CertificateAuthority:

    def __init__(self, ca_file: str = 'ca.pem', cache_dir: str = gettempdir()) -> None:
        self.ca_file: str = ca_file
        self.cache_dir: str = cache_dir
        self._serial: int = self._get_serial()
        if not path.exists(path=ca_file):
            self._generate_ca()
        else:
            self._read_ca(file=ca_file)

    def _get_serial(self) -> int:
        serial_number = 1
        for certificate in filter(lambda x: x.startswith('.pymp_'), listdir(self.cache_dir)):
            with open(file=path.join(self.cache_dir, certificate), mode='rb') as certificate_file:
                certificate_opened_file = certificate_file.read()
            certificate = load_certificate(type=FILETYPE_PEM, buffer=certificate_opened_file)
            certificate_serial_number = certificate.get_serial_number()
            if certificate_serial_number > serial_number:
                serial_number = certificate_serial_number
            del certificate
        return serial_number

    def _generate_ca(self) -> None:
        # Generate key
        self.key = PKey()
        self.key.generate_key(type=TYPE_RSA, bits=2048)

        # Generate certificate
        self.cert = X509()
        self.cert.set_version(version=3)
        self.cert.set_serial_number(serial=1)
        self.cert.get_subject().CN = 'ca.mitm.com'
        self.cert.gmtime_adj_notBefore(amount=0)
        self.cert.gmtime_adj_notAfter(amount=315360000)
        self.cert.set_issuer(issuer=self.cert.get_subject())
        self.cert.set_pubkey(pkey=self.key)
        self.cert.add_extensions(extensions=[X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
                                             X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
                                             X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=self.cert)])
        self.cert.sign(pkey=self.key, digest="sha1")

        with open(file=self.ca_file, mode='wb+') as certificate_authority:
            certificate_authority.write(dump_privatekey(FILETYPE_PEM, self.key))
            certificate_authority.write(dump_certificate(FILETYPE_PEM, self.cert))
        return

    def _read_ca(self, file: str) -> None:
        with open(file=file, mode='rb') as opened_file:
            opened_file = opened_file.read()
        self.cert = load_certificate(type=FILETYPE_PEM, buffer=opened_file)
        self.key = load_privatekey(type=FILETYPE_PEM, buffer=opened_file)
        return

    def __getitem__(self, cn: Any) -> str:
        cnp = path.join(self.cache_dir, '.pymp_%s.pem' % cn)
        if not path.exists(path=cnp):
            # create certificate
            key = PKey()
            key.generate_key(type=TYPE_RSA, bits=2048)

            # Generate CSR
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(pkey=key)
            req.sign(pkey=key, digest='sha1')

            # Sign CSR
            cert = X509()
            cert.set_subject(subject=req.get_subject())
            cert.set_serial_number(serial=self.serial)
            cert.gmtime_adj_notBefore(amount=0)
            cert.gmtime_adj_notAfter(amount=31536000)
            cert.set_issuer(issuer=self.cert.get_subject())
            cert.set_pubkey(pkey=req.get_pubkey())
            cert.sign(pkey=self.key, digest='sha1')

            with open(file=cnp, mode='wb+') as cnp_file:
                cnp_file.write(dump_privatekey(FILETYPE_PEM, key))
                cnp_file.write(dump_certificate(FILETYPE_PEM, cert))
        return cnp

    @property
    def serial(self) -> int:
        self._serial += 1
        return self._serial


class UnsupportedSchemeException(Exception):
    pass


class ProxyHandler(BaseHTTPRequestHandler):
    # TODO: Fix it please, because I have no idea, i just moded (?i)
    # r = compile(r'http://[^/]+(/?.*)(?i)')
    r = compile(r'(?i)http://[^/]+(/?.*)')

    def __init__(self, request: bytes, client_address: tuple[str, int], server: BaseServer) -> None:
        self.is_connect = False
        self.ssl_host = None
        BaseHTTPRequestHandler.__init__(self, request=request, client_address=client_address, server=server)

    def _connect_to_host(self) -> None:
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            parsed_url = urlparse(url=self.path)
            if parsed_url.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(parsed_url.scheme))
            self.hostname = parsed_url.hostname
            self.port = parsed_url.port or 80
            self.path = urlunparse(ParseResult(scheme='', netloc='', params=parsed_url.params,
                                               path=parsed_url.path or '/', query=parsed_url.query,
                                               fragment=parsed_url.fragment, typename='ParseResult'))

        # Connect to destination
        self._proxy_sock = socket()
        self._proxy_sock.settimeout(10)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            self._proxy_sock = wrap_socket(sock=self._proxy_sock)
        return

    def _transition_to_ssl(self) -> None:
        self.request = wrap_socket(sock=self.request, server_side=True,
                                   certfile=self.server.ca[self.path.split(':')[0]])
        return

    def do_connect(self) -> None:
        self.is_connect = True
        try:
            # Connect to destination first
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(code=200, message='Connection established')
            self.end_headers()
            # self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)
            self._transition_to_ssl()
        except Exception as exc:
            self.send_error(code=500, message=str(exc))
            return

        # Reload!
        self.setup()
        self.ssl_host = 'https://%s' % self.path
        self.handle_one_request()
        return

    def do_command(self) -> None:

        # Is this an SSL tunnel?
        if not self.is_connect:
            try:
                # Connect to destination
                self._connect_to_host()
            except Exception as exc:
                self.send_error(code=500, message=str(exc))
                return
            # Extract path

        # Build request
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)

        # Add headers to the request
        req += '%s\r\n' % self.headers

        # Append message body if present to the request
        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        # Send it down the pipe!
        self._proxy_sock.sendall(self.mitm_request(req))

        # Parse response
        h = HTTPResponse(self._proxy_sock)
        h.begin()

        # Get rid of the pesky header
        del h.msg['Transfer-Encoding']

        # Time to relay the message across
        res = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
        res += '%s\r\n' % h.msg
        res += h.read()

        # Let's close off the remote end
        h.close()
        self._proxy_sock.close()

        # Relay the message
        self.request.sendall(self.mitm_response(res))
        return

    def mitm_request(self, data):
        for plugin in self.server._req_plugins:
            data = plugin(self.server, self).do_request(data)
        return data

    def mitm_response(self, data):
        for plugin in self.server._res_plugins:
            data = plugin(self.server, self).do_response(data)
        return data

    def __getattr__(self, item: str) -> Callable[[], None]:
        if item.startswith('do_'):
            return self.do_command


class InterceptorPlugin:

    def __init__(self, server: BaseServer, msg: str):
        self.server = server
        self.message = msg


class RequestInterceptorPlugin(InterceptorPlugin):

    def do_request(self, data):
        return data


class ResponseInterceptorPlugin(InterceptorPlugin):

    def do_response(self, data):
        return data


class InvalidInterceptorPluginException(Exception):
    pass


class MitmProxy(HTTPServer):

    def __init__(self, server_address: tuple[str, int] = ('', 8080), request_handler: ProxyHandler = ProxyHandler,
                 bind_and_activate: bool = True, ca_file: str = 'ca.pem') -> None:
        HTTPServer.__init__(self, server_address=server_address, RequestHandlerClass=request_handler,
                            bind_and_activate=bind_and_activate)
        self.ca = CertificateAuthority(ca_file=ca_file)
        self._res_plugins = []
        self._req_plugins = []

    def register_interceptor(self,
                             interceptor_class: Union[
                                 Type[RequestInterceptorPlugin], Type[ResponseInterceptorPlugin], Type[
                                     DebugInterceptor]]) -> None:
        if not issubclass(interceptor_class, InterceptorPlugin):
            raise InvalidInterceptorPluginException(
                'Expected type InterceptorPlugin got %s instead' % type(interceptor_class))
        if issubclass(interceptor_class, RequestInterceptorPlugin):
            self._req_plugins.append(interceptor_class)
        if issubclass(interceptor_class, ResponseInterceptorPlugin):
            self._res_plugins.append(interceptor_class)


class AsyncMitmProxy(ThreadingMixIn, MitmProxy):
    pass


class MitmProxyHandler(ProxyHandler):

    def mitm_request(self, data):
        print('>> %s' % repr(data[:100]))
        return data

    def mitm_response(self, data):
        print('<< %s' % repr(data[:100]))
        return data


class DebugInterceptor(RequestInterceptorPlugin, ResponseInterceptorPlugin):

    def do_request(self, data):
        print('>> %s' % repr(data[:100]))
        return data

    def do_response(self, data):
        print('<< %s' % repr(data[:100]))
        return data


if __name__ == '__main__':
    proxy = None
    if not argv[1:]:
        proxy = AsyncMitmProxy()
    else:
        proxy = AsyncMitmProxy(ca_file=argv[1])
    proxy.register_interceptor(interceptor_class=DebugInterceptor)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        proxy.server_close()
