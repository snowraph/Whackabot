#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A script to parse and analyze webserver access logs.
Find abusers easily.
https://github.com/snowraph
"""

import sys
import logging
import argparse
import ipaddress
import threading
import re
from time import perf_counter, sleep
from datetime import datetime, timedelta
from socket import gethostbyaddr
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode


class Whackabot:
    __version__ = '0.3'

    formats = {
        'combined':  {'ip': 0, 'time': 3, 'req': 4, 'status': 5, 'bytes': 6, 'ua': 8, '_spec': '%h %l %u %t \"%r\" %>s %O "%{Referer}i" "%{User-Agent}i"'},
        'vcombined': {'ip': 1, 'time': 4, 'req': 5, 'status': 6, 'bytes': 7, 'ua': 9, '_spec': '%v:%p %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'}
    }

    # https://developers.cloudflare.com/cache/concepts/default-cache-behavior/
    static_exts = ('7z', 'apk', 'avi', 'avif', 'bin', 'bmp', 'bz2', 'class', 'css', 'csv', 'dmg',
                'doc', 'docx', 'ejs', 'eot', 'eps', 'exe', 'flac', 'gif', 'gz', 'ico', 'iso',
                'jar', 'jpeg', 'jpg', 'js', 'mid', 'midi', 'mkv', 'mp3', 'mp4', 'ogg', 'otf',
                'pdf', 'pict', 'pls', 'png', 'ppt', 'pptx', 'ps', 'rar', 'svg', 'svgz', 'swf',
                'tar', 'tif', 'tiff', 'ttf', 'webm', 'webp', 'woff', 'woff2', 'xls', 'xlsx', 'zip', 'zst')

    # default fields colors
    colors = {'ip': 'lightblue', 'ua': 'lightmagenta', 'rq': 'yellow', 'rv': 'green'}

    def __init__(self, config):
        self._config = config
        self.logger = logging.getLogger('Whackabot')
        loglevel = logging.DEBUG if self.config('verbose')>1 else logging.INFO if self.config('verbose') else logging.ERROR
        logging.basicConfig(format='[%(levelname)s] %(message)s', level=loglevel)
        self._hosts = {}
        self._times = {}
        self._uas = {}
        self._reqs = {}
        self.hits = 0
        self.format = self.formats[self.config('log_format')]

    def config(self, name):
        return self._config[name] if name in self._config else None

    @staticmethod
    def arg_parse():
        parser = argparse.ArgumentParser(prog='whack', description='Find top traffic sources in Apache/Nginx access logs.')
        parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='Logfile (defaut: stdin)')
        parser.add_argument('-f', '--format', default='vcombined', help='Log format (default: vcombined)')
        parser.add_argument('--list-formats', action='store_true', help='List available log formats')
        parser.add_argument('-c', '--count', type=int, default=10, help='Get top COUNT results for hosts, user-agents and requests modes (default: 10). Format "-COUNT" is also accepted.')
        parser.add_argument('-t', '--timestamps', action='store_true', help='Show timestamps (first/last) for hosts, user-agents and requests modes')
        parser.add_argument('-x', '--output-extended', action='store_true', default=False, help="Show detailed view for user-agents and requests modes")
        parser.add_argument('--no-progress', action='store_true', help='Hide progress status')
        parser.add_argument('--no-color', action='store_true', help="Don't color output")
        parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity')
        parser.add_argument('-V', '--version', action='version', version=f"%(prog)s {__class__.__version__}", help='Get program version')

        hmode = parser.add_argument_group("Hosts mode (default)")
        hmode.add_argument('-r', '--reverse-lookup', action='store_true', default=False, help="Try to resolve IP addresses (slow)")
        hmode.add_argument('-w', '--whois-lookup', action='store_true', default=False, help="Get IP info from Whois (unreliable)")
        hmode.add_argument('-u', '--show-user-agents', nargs='?', type=int, const=10, default=None, metavar='COUNT', help='Show top N (default: 10) user-agents per host')
        hmode.add_argument('-p', '--network-prefix', type=int, default=None, metavar='PREFIX', help='Network prefix in CIDR notation (eg. "24" for x.x.x.x/24), to narrow down subnets. Caution: prefixing both IPv4 and IPv6 makes no sense')

        umode = parser.add_argument_group('User agents mode', 'Show top user agents')
        umode.add_argument('-a', '--user-agents', action='store_true', default=False, help="User agents mode")

        rmode = parser.add_argument_group('Requests mode', 'Show top requests')
        rmode.add_argument('-q', '--requests', action='store_true', default=False, help="Requests mode")
        rmode.add_argument('-s', '--requests-ignore-static', action='store_true', default=False, help="Ignore static resources")
        rmode.add_argument('-m', '--requests-remove-query-string', action='store_true', default=False, help="Remove query string")
        rmode.add_argument('-z', '--requests-dont-anonymize-parameters', action='store_true', default=False, help="Don't anonymize query string parameters")

        tmode = parser.add_argument_group('Time distribution mode', 'Show hits by time interval')
        tmode.add_argument('-d', '--time-distribution', nargs='?', type=int, const=1, default=None, metavar='interval', help="Time distribution mode (default interval: 1 minute)")

        # handle option "-c X" as "-X" like tail or head
        args = sys.argv[1:]
        for i, a in enumerate(args):
            if m := re.fullmatch('-([0-9]+)', a):
                args[i] = '-c' + m.group(1)

        return parser.parse_args(args)

    def run(self):
        start_time = perf_counter()

        func_add = (self.add_time if self.config('td_mode')
                    else self.add_ua if self.config('ua_mode')
                    else self.add_req if self.config('req_mode')
                    else self.add_host)

        # progress monitor
        if self.config('show_progress'):
            threading.Thread(target=self._thread_progress, daemon=True).start()

        # main loop
        try:
            for line in self.config('infile'):
                self.hits += 1
                func_add(self.get_parts(line))
        except KeyboardInterrupt:
            self.logger.error('Aborted by user')
            exit(1)

        self.stop_thread_progress = 1

        if self.config('td_mode'):
            self.logger.info(f"Showing time distribution with interval {self.config('td_mode')}m (total hits: {self.hits})")
            self.format_output_times()
        elif self.config('ua_mode'):
            self.logger.info(f"Showing top {self.config('limit')} of {len(self._uas)} user-agents (total hits: {self.hits})")
            self.format_output_uas()
        elif self.config('req_mode'):
            self.logger.info(f"Showing top {self.config('limit')} of {len(self._reqs)} requests (total hits: {self.hits})")
            self.format_output_reqs()
        else:
            self.logger.info(f"Showing top {self.config('limit')} of {len(self._hosts)} hosts (total hits: {self.hits})")
            self.format_output()

        self.logger.debug('Execution time: %ss' % round(perf_counter() - start_time, 4))

    def _thread_progress(self):
        d = threading.local()
        d.c = 0
        while True:
            sleep(1)
            if hasattr(self, 'stop_thread_progress'):
                break
            d.c += 1
            print(f'{self.hits} hits ({(self.hits/d.c/1000):.0f}K/s)', end='\r', file=sys.stderr)

    @staticmethod
    def list_formats():
        print("Available log formats, Apache style:")
        for f in Whackabot.formats:
            print(f'- {f}: {Whackabot.formats[f]["_spec"]}')
        exit()

    @staticmethod
    def _split_line(line):
        '''
        Fast split on Apache2 log lines
        https://stackoverflow.com/a/29376301/4222767
        TODO: bench Vs regex Vs ?
        '''
        row = []
        qe = qp = None # quote end character (qe) and quote parts (qp)
        for s in line.replace('\n','').split(' '):
            if qp:
                qp.append(s)
            elif '' == s: # blanks
                row.append('')
            elif '"' == s[0]: # begin " quote "
                qp = [ s ]
                qe = '"'
            elif '[' == s[0]: # begin [ quote ]
                qp = [ s ]
                qe = ']'
            else:
                row.append(s)

            if qe:
                l = len(s)
                if l and qe == s[-1]: # end quote
                    if l == 1 or s[-2] != '\\': # don't end on escaped quotes
                        row.append(' '.join(qp)[1:-1].replace('\\'+qe, qe))
                        qp = qe = None
        return row

    def get_parts(self, line):
        """
        Split log line in multiple fields
        This is the tricky part:
            - multiple formats (autoguess?)
            - performance
        """
        parts = self._split_line(line)
        
        # minimal validation: ip of first row
        if self.hits == 0 and not self.valid_ip(parts[self.format['ip']]):
            self.logger.critical(f'"{parts[self.format["ip"]]}" is not a valid IP address, please verify log format')
            exit(1)

        try:
            res = {
                'ip':     parts[self.format['ip']],
                'time':   parts[self.format['time']],
                'ua':     parts[self.format['ua']],
                'status': parts[self.format['status']],
                'bytes':  0 if parts[self.format['bytes']] == '-' else int(parts[self.format['bytes']])
            }
            if len(parts[self.format['req']]):#sometimes it's empty
                res['method'] = parts[self.format['req']].split()[0].lower()
                if self.config('req_mode'):
                    res['req'] = parts[self.format['req']].split()[1]
            else:
                res['method'] = ''
                if self.config('req_mode'):
                    res['req'] = ''
        except Exception as e:
            self.logger.critical(f'Split error at line: {self.hits} ({e})')
            self.logger.critical(line)
            exit(1)

        return res

    @staticmethod
    def valid_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    def sort_hosts(self, by='hits'):
        return dict(sorted(self._hosts.items(), key=lambda item: item[1]['count'], reverse=True))

    def get_top_hosts(self):
        res = {}
        for i, k in enumerate(self.sort_hosts(self._hosts)):# https://stackoverflow.com/a/64516802/4222767
            if i == self.config('limit'):
                break
            res[k] = self._hosts[k]
        return res

    def resolve(self, ip):
        h = '-'
        if self.config('resolve'):
            try:
                if '/' in ip:
                    ip = ip.split('/')[0]
                if self.config('whois'):
                    h = self._resolve_whois(ip)
                else:
                    h = self._resolve_native(ip)
            except:
                pass
        return h

    @staticmethod
    def _resolve_native(ip):
        return gethostbyaddr(ip)[0]

    @staticmethod
    def _resolve_whois(ip):
        import subprocess
        h, n, c = '-', None, None
        with subprocess.Popen(['whois', ip], stdout=subprocess.PIPE) as proc:
            while line := proc.stdout.readline().decode('utf-8'):
                if m := re.search('^(netname|country):\s+(.*)$', line, re.IGNORECASE):
                    if m.group(1).lower() == 'netname':
                        n = m.group(2)
                    else:
                        c = m.group(2).upper()[:2]
        if n and c:
            h = f"{c}/{n}"
        return h

    @staticmethod
    def format_methods(methods):
        m = [0, 0, 0, 0] # get, post, head, other
        for k, v in methods.items():
            if   k == 'get': m[0] = v
            elif k == 'post': m[1] = v
            elif k == 'head': m[2] = v
            else: m[3] += v
        return '/'.join(map(str, m))

    @staticmethod
    def format_statuses(statuses):
        m = [0, 0, 0, 0, 0] #2xx, 3xx, 4xx, 5xx, other
        for k, v in statuses.items():
            if   k[0] == '2': m[0] += v
            elif k[0] == '3': m[1] += v
            elif k[0] == '4': m[2] += v
            elif k[0] == '5': m[3] += v
            else: m[4] += v
        return '/'.join(map(str, m))

    @staticmethod
    def format_hps(start, end, count):
        td = (end - start).total_seconds()
        hps = count / (td if td>0 else 1)
        return str(round(hps) if hps >= 1 else "<1")

    @staticmethod
    def format_get_row_format(rows):
        """Dynamic fields width"""
        lengths = []
        nfields = len(rows[0])
        for row in rows:
            for i, field in enumerate(row):
                l = len(str(field))
                if len(lengths) < nfields:
                   lengths.append(l)
                elif lengths[i] < l and nfields > i+1:# last field dont need filling
                    lengths[i] = l
        row_format = ''
        for l in lengths:
            row_format += '{:<'+str(l)+'}  '
        return row_format.rstrip()

    def format_output(self):
        header = ['Host', 'Reverse', 'Hits', 'H/s', 'Bytes', 'UA', 'G/P/H/o', '2/3/4/5/oxx']
        if self.config('show_timestamps'):
            header += ['First', 'Last']
        top_hosts = self.get_top_hosts()
        res = []
        res.append(header)

        for ip, host in top_hosts.items():
            bytes = round(host['bytes'] / 1024 / 1024, 1)
            start = datetime.strptime(host['start'], '%d/%b/%Y:%H:%M:%S %z')
            end = datetime.strptime(host['end'], '%d/%b/%Y:%H:%M:%S %z')
            row = [
                ip,
                '-',
                host['count'],
                self.format_hps(start, end, host['count']),
                str(bytes) + 'M',
                len(host['uas']),
                self.format_methods(host['methods']),
                self.format_statuses(host['statuses'])
            ]

            if self.config('show_timestamps'):
                row += [str(start), str(end)]
            res.append(row)

        if self.config('resolve'):
            self.logger.info('Started reverse lookup')
            import concurrent.futures# here ?!

            def _threaded_resolve(row):
                row[1] = self.resolve(row[0])

            start_time = perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(res)) as tpe:
                tpe.map(_threaded_resolve, res[1:])# cant make a timeout to work :(
            self.logger.debug('Reverse lookup took %ss' % round(perf_counter() - start_time, 4))

        row_format = self.format_get_row_format(res)
        if self.config('color'):
            cdef = {0: self.colors['ip']}
            if self.config('resolve'):
                cdef[1] = self.colors['rv']
            row_format_color = self.colorize_format_string(row_format, cdef)
        for i, row in enumerate(res):
            print((row_format_color if i and self.config('color') else row_format).format(*row))
            if self.config('show_user_agents') is not None and i:
                self.format_output_host_uas(top_hosts[row[0]]['uas'], self.config('show_user_agents'))

    def format_output_host_uas(self, uas, limit):
        res = {}
        srt = dict(sorted(uas.items(), key=lambda item: item[1], reverse=True))
        for i, k in enumerate(srt):
            if i == limit:
                break
            res[k] = srt[k]

        s = '├'
        l = len(res) - 1
        format = ' {} {}: {}'
        if self.config('color'):
            format = self.colorize_format_string(format, {3:self.colors['ua']}, ' ')
        for i, k in enumerate(res):
            if i == l:
                s = '└'
            print(format.format(s, res[k], k))

    @staticmethod
    def colorize_format_string(format, cdef: dict = None, sep = '  '):
        # cdef = {index: color}
        colors={
            'default': 39,
            'black': 30,
            'red': 31,
            'green': 32,
            'yellow': 33,
            'blue': 34,
            'magenta': 35,
            'cyan': 36,
            'lightgray': 37,
            'darkgray': 90,
            'lightred': 91,
            'lightgreen': 92,
            'lightyellow': 93,
            'lightblue': 94,
            'lightmagenta': 95,
            'lightcyan': 96,
            'white': 97
        }
        res = format.split(sep)
        for i, c in cdef.items():
            res[i] = f"\033[{colors[c]}m{res[i]}\033[0m"
        return sep.join(res)

    @staticmethod
    def inc_dict_property(d, a):
        if a in d:
            d[a] += 1
        else:
            d[a] = 1

    def add_host(self, parts):
        ip = parts['ip']
        if self.config('prefix'):
            ip = ipaddress.ip_network((ip, self.config('prefix')), False).exploded
        if not ip in self._hosts:
            self._hosts[ip] = {
                'count': 0,
                'bytes': 0,
                'start': parts['time'],
                'uas': {},
                'methods': {},
                'statuses': {}
            }

        h = self._hosts[ip]
        h['count'] += 1
        h['bytes'] += parts['bytes']
        h['end'] = parts['time']
        # todo: user-agents global lookup table to save memory
        self.inc_dict_property(h['uas'], parts['ua'])
        self.inc_dict_property(h['methods'], parts['method'])
        self.inc_dict_property(h['statuses'], parts['status'])

    ### User agents mode ###
    def add_ua(self, parts):
        ua = parts['ua']
        if not ua in self._uas:
            self._uas[ua] = {
                'count': 0
            }
            if self.config('output_ext'):
                self._uas[ua].update({
                    'bytes': 0,
                    'start': parts['time'],
                    'ips': {},
                    'methods': {},
                    'statuses': {}
                })

        u = self._uas[ua]
        u['count'] += 1
        if self.config('output_ext'):
            u['bytes'] += parts['bytes']
            u['end'] = parts['time']
            self.inc_dict_property(u['ips'], parts['ip'])
            self.inc_dict_property(u['methods'], parts['method'])
            self.inc_dict_property(u['statuses'], parts['status'])

    def format_output_uas(self):
        uas = dict(sorted(self._uas.items(), key=lambda item: item[1]['count'], reverse=True)[0:self.config('limit')])

        header = ['Hits']
        if self.config('output_ext'):
            header += ['IPs', 'H/s', 'Bytes', 'G/P/H/o', '2/3/4/5/oxx']
            if self.config('show_timestamps'):
                header += ['First', 'Last']
        header += ['User-agent']

        res = [header]
        for ua in uas:
            row = []
            row.append(uas[ua]['count'])
            if self.config('output_ext'):
                start = datetime.strptime(uas[ua]['start'], '%d/%b/%Y:%H:%M:%S %z')
                end = datetime.strptime(uas[ua]['end'], '%d/%b/%Y:%H:%M:%S %z')
                row += [
                    len(uas[ua]['ips']),
                    self.format_hps(start, end, uas[ua]['count']),
                    str(round(uas[ua]['bytes'] / 1024 / 1024, 1)) + 'M',
                    self.format_methods(uas[ua]['methods']),
                    self.format_statuses(uas[ua]['statuses'])
                ]
                if self.config('show_timestamps'):
                    row += [
                        str(start),
                        str(end)
                    ]
            row.append(ua)
            res.append(row)

        row_format = self.format_get_row_format(res)
        if self.config('color'):
            row_format_color = self.colorize_format_string(row_format, {len(res[0])-1:self.colors['ua']})
        for i, row in enumerate(res):
            print((row_format_color if i and self.config('color') else row_format).format(*row))

    ### Time distribution mode ###
    def add_time(self, parts):
        t = datetime.strptime(parts['time'], '%d/%b/%Y:%H:%M:%S %z')
        if self.config('td_mode') > 1:
            # datetime modulo
            # https://gist.github.com/treyhunner/6218526 nice one thanks
            # TODO: speed it up (4x slower than: t = parts['time'][:17])
            #   -> cache t
            sec = int((t - datetime(1970, 1, 1, tzinfo=t.tzinfo)).total_seconds())
            t -= timedelta(
                seconds=sec % timedelta(minutes=self.config('td_mode')).total_seconds(),
                # microseconds = t.microsecond
            )
        t = t.strftime('%Y-%m-%d:%H:%M')
        self.inc_dict_property(self._times, t)

    def format_output_times(self):
        # TODO: sort by max
        m = max(self._times.values())
        mw = len(str(m))
        # say we want a graph of width x
        witdh = 40
        for t in self._times:
            w = int(self._times[t] / m * witdh)
            print(f"[{t}] {self._times[t]:>{mw}} {'*'*w}")

    ### Requests mode ###
    # TODO: 3x slower than hosts mode !?
    def add_req(self, parts):
        req = urlparse(parts['req'])

        if self.config('req_ignore_static'):
            if req.path.split('.')[-1] in self.static_exts:
                return

        if self.config('req_remove_qs'):
            req = req._replace(query='')

        if self.config('req_anon_qsp'):
            qs = parse_qs(req.query, keep_blank_values=True)
            for k in qs:
                for i, v in enumerate(qs[k]):
                    qs[k][i] = '_'
            req = req._replace(query=urlencode(qs, doseq=True))

        req = urlunparse(req)
        if not req in self._reqs:
            self._reqs[req] = {
                'count': 0
            }
            if self.config('output_ext'):
                self._reqs[req].update({
                    'bytes': 0,
                    'start': parts['time'],
                    'ips': {},
                    'methods': {},
                    'statuses': {}
                })

        r = self._reqs[req]
        r['count'] += 1
        if self.config('output_ext'):
            r['bytes'] += parts['bytes']
            r['end'] = parts['time']
            self.inc_dict_property(r['ips'], parts['ip'])
            self.inc_dict_property(r['methods'], parts['method'])
            self.inc_dict_property(r['statuses'], parts['status'])

    def format_output_reqs(self):
        reqs = dict(sorted(self._reqs.items(), key=lambda item: item[1]['count'], reverse=True)[0:self.config('limit')])

        header = ['Hits']
        if self.config('output_ext'):
            header += ['IPs', 'H/s', 'Bytes', 'G/P/H/o', '2/3/4/5/oxx']
            if self.config('show_timestamps'):
                header += ['First', 'Last']
        header += ['Request']

        res = [header]
        for req in reqs:
            row = []
            row.append(reqs[req]['count'])
            if self.config('output_ext'):
                start = datetime.strptime(reqs[req]['start'], '%d/%b/%Y:%H:%M:%S %z')
                end = datetime.strptime(reqs[req]['end'], '%d/%b/%Y:%H:%M:%S %z')
                row += [
                    len(reqs[req]['ips']),
                    self.format_hps(start, end, reqs[req]['count']),
                    str(round(reqs[req]['bytes'] / 1024 / 1024, 1)) + 'M',
                    self.format_methods(reqs[req]['methods']),
                    self.format_statuses(reqs[req]['statuses'])
                ]
                if self.config('show_timestamps'):
                    row += [
                        str(start),
                        str(end)
                    ]
            row.append(req)
            res.append(row)

        row_format = self.format_get_row_format(res)
        if self.config('color'):
            row_format_color = self.colorize_format_string(row_format, {len(res[0])-1:self.colors['rq']})
        for i, row in enumerate(res):
            print((row_format_color if i and self.config('color') else row_format).format(*row))


if __name__ == '__main__':
    args = Whackabot.arg_parse()

    if args.list_formats:
        Whackabot.list_formats()

    conf = {
        'infile': args.infile,
        'verbose': args.verbose,
        'limit': args.count,
        'log_format': args.format,
        'show_user_agents': args.show_user_agents,
        'show_timestamps': args.timestamps,
        'resolve': args.reverse_lookup or args.whois_lookup,
        'whois': args.whois_lookup,
        'prefix': args.network_prefix,
        'td_mode': args.time_distribution,#TODO: control > 0
        'ua_mode': args.user_agents,
        'output_ext': args.output_extended,
        'req_mode': args.requests,
        'req_ignore_static': args.requests_ignore_static,
        'req_remove_qs': args.requests_remove_query_string,
        'req_anon_qsp': not args.requests_dont_anonymize_parameters,
        'show_progress': not args.no_progress,
        'color': sys.stdout.isatty() and not args.no_color
    }
    Whackabot(conf).run()
