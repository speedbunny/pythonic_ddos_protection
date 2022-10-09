from .core import *
from .exceptions import *
from .middlewares import *
from .storage import *
from .utils import *


__version__ = '0.1.4'


__all__ = [
    'core',
    'exceptions',
    'middlewares',
    'storage',
    'utils',
]


class Website(object):
    """
    Website class.
    """

    def __init__(self, name):
        """
        Initializes Website.

        :param name: Website name.
        :type name: str
        """
        self.name = name
        self.logger = logging.getLogger(self.name)

        self.storage = RedisStorage(self.name)
        self.storage.initialize()

        self.middleware = Middleware(self)


    def on_request(self, request):
        """
        Called when request arrives.

        :param request: Request object.
        :type request: Request
        """
        request.website = self
        self.logger.info('%s -> %s', request.ip, request.url)


    def on_response(self, response):
        """
        Called when response has been sent.

        :param response: Response object.
        :type response: Response
        """
        pass


    def __repr__(self):
        return '<Website %s>' % self.name


class BaseMiddleware(object):
    """
    Base Middleware.
    """


    def __init__(self, website):
        """
        Initializes Middleware.

        :param website: Website instance.
        :type website: Website
        """
        self.website = website


    def on_request(self, request):
        """
        Called when request arrives.

        :param request: Request object.
        :type request: Request
        """
        pass


    def on_response(self, response):
        """
        Called when response has been sent.

        :param response: Response object.
        :type response: Response
        """
        pass


    def __repr__(self):
        return '<Middleware %s>' % self.__class__.__name__


class Middleware(object):
    """
    Middleware manager.
    """


    def __init__(self, website):
        """
        Initializes Middleware manager.

        :param website: Website instance.
        :type website: Website
        """
        self.website = website
        self.middlewares = []


    def register(self, middleware):
        """
        Registers new middleware.

        :param middleware: Middleware instance.
        :type middleware: Middleware
        """
        if middleware not in self.middlewares:
            self.middlewares.append(middleware)


    def unregister(self, middleware):
        """
        Unregisters middleware.

        :param middleware: Middleware instance.
        :type middleware: Middleware
        """
        if middleware in self.middlewares:
            self.middlewares.remove(middleware)


    def on_request(self, request):
        """
        Called when request arrives.

        :param request: Request object.
        :type request: Request
        """
        for middleware in self.middlewares:
            middleware.on_request(request)

        return request


    def on_response(self, response):
        """
        Called when response has been sent.

        :param response: Response object.
        :type response: Response
        """
        for middleware in self.middlewares:
            middleware.on_response(response)

        return response


    def __repr__(self):
        return '<Middleware manager>'


class Request(object):
    """
    Request object.
    """


    def __init__(self, method, url, headers, ip, website=None):
        """
        Initializes Request object.

        :param method: Request method.
        :type method: str

        :param url: Request URL.
        :type url: str

        :param headers: Request headers.
        :type headers: dict

        :param ip: IP address.
        :type ip: str

        :param website: Website name.
        :type website: str
        """
        self.method = method
        self.url = url
        self.headers = headers
        self.ip = ip

        self.website = website
        self.logger = logging.getLogger(self.website)


    def __repr__(self):
        return '<Request %s>' % self.url


class Response(object):
    """
    Response object.
    """


    def __init__(self, status, headers, content):
        """
        Initializes Response object.

        :param status: Response status.
        :type status: int

        :param headers: Response headers.
        :type headers: dict

        :param content: Response content.
        :type content: str
        """
        self.status = status
        self.headers = headers
        self.content = content


    def __repr__(self):
        return '<Response %s>' % self.status


class LoggingMiddleware(BaseMiddleware):
    """
    Logging Middleware.

    This middleware logs requests.
    """


    def on_request(self, request):
        """
        Called when request arrives.

        :param request: Request object.
        :type request: Request
        """
        self.website.logger.info('%s -> %s', request.ip, request.url)


    def on_response(self, response):
        """
        Called when response has been sent.

        :param response: Response object.
        :type response: Response
        """
        pass


class LimitMiddleware(BaseMiddleware):
    """
    Limit Middleware.

    This middleware limits request count per IP.
    """


    def on_request(self, request):
        """
        Called when request arrives.

        :param request: Request object.
        :type request: Request
        """
        if not self.website.storage.is_allowed(request.ip):
            raise RequestDenied(request.ip)


    def on_response(self, response):
        """
        Called when response has been sent.

        :param response: Response object.
        :type response: Response
        """
        pass


class ExposeMiddleware(BaseMiddleware):
    """
    Expose Middleware.

    This middleware exposes statistics to request.
    """


    def on_request(self, request):
        """
        Called when request arrives.

        :param request: Request object.
        :type request: Request
        """
        if request.url == '/stats':
            data = self.website.storage.get_stats()
            return Response(200, {'content-type': 'application/json'}, json.dumps(data))


    def on_response(self, response):
        """
        Called when response has been sent.

        :param response: Response object.
        :type response: Response
        """
        pass


class BlacklistMiddleware(BaseMiddleware):
    """
    Blacklist Middleware.

    This middleware blocks IPs.
    """


    def on_request(self, request):
        """
        Called when request arrives.

        :param request: Request object.
        :type request: Request
        """
        if self.website.storage.is_blocked(request.ip):
            raise RequestDenied(request.ip)


    def on_response(self, response):
        """
        Called when response has been sent.

        :param response: Response object.
        :type response: Response
        """
        pass


class WhiteListMiddleware(BaseMiddleware):
    """
    Whitelist Middleware.

    This middleware allows IPs to bypass other middlewares.
    """


    def on_request(self, request):
        """
        Called when request arrives.

        :param request: Request object.
        :type request: Request
        """
        if self.website.storage.is_allowed(request.ip):
            return Response(200, {'content-type': 'text/plain'}, 'OK')


    def on_response(self, response):
        """
        Called when response has been sent.

        :param response: Response object.
        :type response: Response
        """
        pass


class DDoSProtection(object):
    """
    DDoS Protection class.
    """


    def __init__(self):
        """
        Initializes DDoS Protection.
        """
        self.logger = logging.getLogger(__name__)

        self.websites = {}


    def register_website(self, name, website):
        """
        Registers new website.

        :param name: Website name.
        :type name: str

        :param website: Website object.
        :type website: Website
        """
        website.logger = logging.getLogger(name)
        self.websites[name] = website


    def unregister_website(self, name):
        """
        Unregisters website.

        :param name: Website name.
        :type name: str
        """
        if name in self.websites:
            del self.websites[name]


    def handle_request(self, method, url, headers, ip, website=None):
        """
        Handles request.

        :param method: Request method.
        :type method: str

        :param url: Request URL.
        :type url: str

        :param headers: Request headers.
        :type headers: dict

        :param ip: IP address.
        :type ip: str

        :param website: Website name.
        :type website: str
        """
        if website is None:
            for name, website in self.websites.items():
                try:
                    website.on_request(Request(method, url, headers, ip))
                except RequestDenied:
                    break
        else:
            try:
                self.websites[website].on_request(Request(method, url, headers, ip))
            except RequestDenied:
                pass


    def handle_response(self, method, url, headers, ip, website=None):
        """
        Handles response.

        :param method: Request method.
        :type method: str

        :param url: Request URL.
        :type url: str

        :param headers: Request headers.
        :type headers: dict

        :param ip: IP address.
        :type ip: str

        :param website: Website name.
        :type website: str
        """
        if website is None:
            for name, website in self.websites.items():
                try:
                    website.on_response(Response(200, {}, ''))
                except RequestDenied:
                    break
        else:
            try:
                self.websites[website].on_response(Response(200, {}, ''))
            except RequestDenied:
                pass


    def __repr__(self):
        return '<DDoS Protection>'


def ddos_protect(website):
    """
    Decorator for request handlers.

    This decorator passes request to DDoS Protection.

    :param website: Website name.
    :type website: str

    :return: Decorated request handler.
    :rtype: function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, environ, start_response):
            protection = environ.get('ddos.protection')
            protection.handle_request(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'), website)

            response = func(self, environ, start_response)

            protection.handle_response(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'), website)
            return response
        return wrapper
    return decorator


def ddos_protect_all(func):
    """
    Decorator for request handlers.

    This decorator passes request to DDoS Protection.

    :return: Decorated request handler.
    :rtype: function
    """
    @functools.wraps(func)
    def wrapper(self, environ, start_response):
        protection = environ.get('ddos.protection')
        protection.handle_request(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'))

        response = func(self, environ, start_response)

        protection.handle_response(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'))
        return response
    return wrapper


class WSGIHandler(object):
    """
    WSGI Handler.
    """


    def __init__(self, app):
        """
        Initializes WSGI Handler.

        :param app: WSGI Application.
        :type app: callable
        """
        self.app = app


    def __call__(self, environ, start_response):
        """
        Handles request.

        :param environ: WSGI environment.
        :type environ: dict

        :param start_response: WSGI start response.
        :type start_response: function
        """
        return self.app(environ, start_response)


    def __repr__(self):
        return '<WSGI Handler>'


class WSGIRequestHandler(WSGIHandler):
    """
    WSGI Request Handler.
    """


    def __call__(self, environ, start_response):
        """
        Handles request.

        :param environ: WSGI environment.
        :type environ: dict

        :param start_response: WSGI start response.
        :type start_response: function
        """
        protection = environ.get('ddos.protection')
        protection.handle_request(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'))

        response = self.app(environ, start_response)

        protection.handle_response(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'))
        return response


class WSGIResponseHandler(WSGIHandler):
    """
    WSGI Response Handler.
    """


    def __call__(self, environ, start_response):
        """
        Handles request.

        :param environ: WSGI environment.
        :type environ: dict

        :param start_response: WSGI start response.
        :type start_response: function
        """
        response = self.app(environ, start_response)

        protection = environ.get('ddos.protection')
        protection.handle_response(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'))
        return response


class WSGIRequestResponseHandler(WSGIHandler):
    """
    WSGI Request/Response Handler.
    """


    def __call__(self, environ, start_response):
        """
        Handles request.

        :param environ: WSGI environment.
        :type environ: dict

        :param start_response: WSGI start response.
        :type start_response: function
        """
        protection = environ.get('ddos.protection')
        protection.handle_request(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'))

        response = self.app(environ, start_response)

        protection.handle_response(environ['REQUEST_METHOD'], environ['PATH_INFO'], environ, environ.get('REMOTE_ADDR'))
        return response


    def get_request(self, raw_request):
        """
        Creates Request object from raw request.

        :param raw_request: Raw request.
        :type raw_request: str
        """
        return Request.from_raw_request(raw_request)


    def get_response(self, raw_response):
        """
        Creates Response object from raw response.

        :param raw_response: Raw response.
        :type raw_response: str
        """
        return Response.from_raw_response(raw_response)



class WSGIPyDdos(WSGIContainer):
    """
    WSGI Container.
    """


    def __init__(self, app, name):
        """
        Initializes WSGIPyDdos.

        :param app: WSGI application.
        :type app: WSGI application

        :param name: Website name.
        :type name: str
        """
        super(WSGIPyDdos, self).__init__(app)
        self.website = Website(name)


    def handle_request(self, method, path, headers, ip):
        """
        Handles request.

        :param method: Request method.
        :type method: str

        :param path: Request path.
        :type path: str

        :param headers: Request headers.
        :type headers: dict

        :param ip: Request ip.
        :type ip: str
        """
        request = Request(method, path, headers, ip)
        self.website.on_request(request)
        self.website.middleware.before_request(request)


    def handle_response(self, method, path, headers, ip):
        """
        Handles response.

        :param method: Request method.
        :type method: str

        :param path: Request path.
        :type path: str

        :param headers: Request headers.
        :type headers: dict

        :param ip: Request ip.
        :type ip: str
        """
        response = Response(headers)
        self.website.on_response(response)
        self.website.middleware.after_response(response)


    def __call__(self, environ, start_response):
        """
        Handles request.

        :param environ: WSGI environment.
        :type environ: dict

        :param start_response: WSGI start response.
        :type start_response: function
        """
        environ['ddos.protection'] = self
        return super(WSGIPyDdos, self).__call__(environ, start_response)



def make_wsgi_app(app, name):
    """
    Builds and returns WSGI application.

    :param app: WSGI application.
    :type app: WSGI application

    :param name: Website name.
    :type name: str

    :returns: WSGI application.
    :rtype: WSGIContainer
    """
    return WSGIPyDdos(app, name)



def get_request(environ):
    """
    Returns request object.

    :param environ: WSGI environment.
    :type environ: dict

    :returns: Request object.
    :rtype: Request
    """
    return environ['ddos.protection'].website.request



def get_response(environ):
    """
    Returns response object.

    :param environ: WSGI environment.
    :type environ: dict

    :returns: Response object.
    :rtype: Response
    """
    return environ['ddos.protection'].website.response



def get_website(environ):
    """
    Returns Website object.

    :param environ: WSGI environment.
    :type environ: dict

    :returns: Website object.
    :rtype: Website
    """
    return environ['ddos.protection'].website
