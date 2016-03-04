#!/usr/bin/env python

''' Distributed firewall blacklisting based on xt_recent. This is a LINUX based tool.

There's no python output from this class, it's a one way control of the assigned xt_recent
iptables extension.

Being a distributed system, a network reachable SQL table is needed for storing and
sharing the entries. 'Tis up to you to implement a different SQL DB interface if you
don't use py-postgresql. It needs to support LISTEN statements that yield asynchronous
notifications.

This runs as three types of units:

1) the submission client which detects undesirable traffic
    programs import this module and submit IP/penalty info for a given filter when
    they've undesirable traffic triggers certain rules

2) a running daemon which enforces firewall rules
    the module is launched stand-alone as __main__

3) a running daemon which does housekeeping on the SQL DB
    the module is launched stand-alone as __main__ with the additional init value
    of housekeeper=True

BUGS:
   - make trigger for updates smarter on recents (and more i suspect). it can miss the fields,
     need to refer to OLD if NEW is void...
   - initial load finds new blocks from the recents file, not blocklist

TODO:
   - i need to write a fake inotify for /proc/net/xt_recent so manually blocked IPs are registered
   - watch /proc/net/xt_recent/* for missing filters and restart said filter when said xt_recent
       file shows up
   - pretty webby gui for managing
   - handle dumbfucked systems where xt_recent is static and limited to 100 rules, aka don't use
      xt_recent, make a say...xt_recent chain
   - handle freebsd systems

'''

__version__  = '1.20'
__author__   = 'David Ford <david@blue-labs.org>'
__email__    = 'david@blue-labs.org'
__date__     = '2016-Feb-19 20:27E'
__license__  = 'Apache 2.0'


import ctypes
import datetime
import io
import netaddr
import json
import logging, logging.handlers
import os
import re
import select
import sys
import time
import traceback
import threading

from configparser import ConfigParser, ExtendedInterpolation

# 3rd party
import psycopg2, psycopg2.extras, psycopg2.extensions
from dateutil import parser

# BlueLabs modules
sys.path.append('/var/bluelabs/python')
import lkhz

# monkey patch threading to set /proc/self/task/[tid]/comm value
import ctypes, ctypes.util, threading
libpthread_path = ctypes.util.find_library("pthread")
if libpthread_path:
    libpthread = ctypes.CDLL(libpthread_path)
    if hasattr(libpthread, "pthread_setname_np"):
        pthread_setname_np = libpthread.pthread_setname_np
        pthread_setname_np.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        pthread_setname_np.restype = ctypes.c_int
        orig_start = threading.Thread.start
        def new_start(self):
            orig_start(self)
            try:
                name = self.name
                if not name or name.startswith('Thread-'):
                    name = self.__class__.__name__
                    if name == 'Thread':
                        name = self.name
                if name:
                    if isinstance(name, str):
                        name = name.encode('ascii', 'replace')
                    ident = getattr(self, "ident", None)
                    if ident is not None:
                        pthread_setname_np(ident, name[:15])
            except Exception as e:
                print('omgwtf: {}'.format(e))
                pass  # Don't care about failure to set name
        threading.Thread.start = new_start

class _nolog():
    def __init__(self):
        pass
    def __call__(self, *arg, **kwargs):
        self.__print(*arg, **kwargs)
    def __print(self, arg, kwargs=None):
        print('{}'.format(datetime.datetime.utcnow().strftime('%F %TZ')),'%s' %arg)
    def error(self, arg):
        self.__print(arg)
    def warn(self, arg):
        self.__print(arg)
    def info(self, arg):
        self.__print(arg)
    def debug(self, arg):
        self.__print(arg)


'''
        need to store the IP, origin node, timestamp when + or -, whether it's punished or
        forgiven

        on startup clients do nothing, managers should:
        a) parse the xt_recent file
        b) fetch the sql data and apply it to their local system

        if xt_recent is empty
            add all IPs in sql to xt_recent

        if the xt_recent file is populated, we will:
            if an ip does exist in sql
                if ip does not exist in xt_recent file
                    if the origin node was ourself
                        push -IP to sql. it seems we manually deleted the ip
                    else
                        add it to xt_recent

            else an ip does not exist in sql
                if ip does exist in the xt_recent file
                    if the ip is not forgiven in sql
                        push +IP to sql


        store recent hit data as well or bots get a free reign to hit <= grace_count on every
        single node. we want to account for _every_ hit in a protected fw cluster

'''



class DFW(threading.Thread, object):
    '''
    init input:
        filter_name:     filename in /proc/net/xt_recent/
        logger:          logging module instance, or None
        dunce_time:      duration of penalty
        grace_count:     how many events before actually firewalling
        grace_period:    must occur > <grace_count> times within <grace_period> to actually get firewalled
    '''

    class __logwrapper(object):
        printer = None
        def __init__(self, printfunc=None):
            if not printfunc:
                self._logger = logging.getLogger('DFW')
                log = self._logger
                log.setLevel(logging.DEBUG)
                log.info('using new logging.Logger')
            else:
                self._logger = printfunc
                self.info('using {}'.format(self._logger))

        def __getattr__(self, k):
            if k in ('st'):
                return ('','')
            else:
                return self.__getattribute__(k)

        def set_printer(self, func):
            self.printer = func

        def critical(self, *args):
            if self.printer:
                self.printer(args)
            else:
                self._logger.critical(args)

        def error(self, *args):
            if self.printer:
                self.printer(args)
            else:
                self._logger.error(args)

        def warning(self, *args):
            if self.printer:
                self.printer(args)
            else:
                self._logger.warning(args)

        def info(self, *args, **kwargs):
            if len(args) > 1:
                print('info args: {!r}'.format(args))
            if len(kwargs):
                print('info kwargs: {!r}'.format(kwargs))
            if self.printer:
                self.printer(*args)
            else:
                self._logger.info(*args)

        def debug(self, *args):
            if self.printer:
                self.printer(args)
            else:
                self._logger.debug(args)


    def __init__(self, name=None, node_address=None, dburi=None, **kwargs):
        if not dburi:
            raise Exception("DFW isn't really a distributed firewall if there's no database to coordinate with; please set dburi")

        if not node_address:
            raise Exception('node_address IP address must be specified')

        filter_name = 'DFW:'+name

        if 'logger' in kwargs:
            _logger = self.__logwrapper(printfunc=kwargs['logger'])

        th_args = {'name':filter_name}
        for kw in ('group','target','daemon'):
            if kw in kwargs:
                th_args[kw]=kwargs.get(kw)
                del kwargs[kw]

        super().__init__(**th_args, kwargs=kwargs)

        self._logger          = _logger
        self.dburi            = dburi
        self.use_nftables     = kwargs.get('use_nftables')
        self.housekeeper      = __name__ == '__main__' and kwargs.get('housekeeper') or False
        self.housekeeper_only = __name__ == '__main__' and kwargs.get('housekeeperonly') or False
        self.xt_recent_online = False

        #if self.use_nftables:
        #    from pyroute2 import

        # in with the new, out with the old -- nftables is the new
        if not self.use_nftables:
            if not filter_name and isinstance(name, str) and re.match('[\w_.-]+$', name):
                raise Exception('filter_name must be a real file name in /proc/net/xt_recent/...')

            try:
                _f = os.path.join('/proc/net/xt_recent', name)
                with open(_f) as f:
                    pass
                self.xt_recent_online = True
            except:
                _logger.warning('a "... -m recent CHECK name: {} ..." rule is not registered in iptables yet, this filter will not be active'.format(filter_name))
        else:
            # we can set up an nftables table and chains, but we need meta information from sql first
            pass


        clienttype = __name__ == '__main__' and 'monitor' or 'client'

        if clienttype == 'monitor' and (self.housekeeper or self.housekeeperonly):
            clienttype += ' (housekeeper)'

        self._logger.info('Distributed Firewall {} startup'.format(clienttype))

        # cache tunables for an hour (this ensures we catch up from lost notifications)
        self.cache_delta     = 3600
        self.cache           = {}

        self.blocklist       = {}


        self.dunce_time      = None
        self.whitelist       = []
        self.filter_name     = filter_name
        self.xt_recent_name  = os.path.join('/proc/net/xt_recent', filter_name)
        self.node_address    = netaddr.IPAddress(node_address)

        self.running         = False
        self._sql_connect()
        self.running         = True

        if not self.use_nftables:
            if not self.xt_recent_online:
                self._logger.warning('no xt_recent filter in place with iptables, this filter is running but cannot act on blocks')
        else:
            # verify we have a table/chain set up for nftables, if not, make one
            # first, do we have 'nft' binary?
            try:
                subprocess.check_output(['nft','-v'])
            except:
                raise Exception('nftables use requested but no "nft" program installed')


    def __contains__(self, ip):
        if ip in self.blocklist:
            return True


    def shutdown(self):
        self._shutdown = True
        try: # only the master has shutdown pipes, just ignore this for the submitters
            os.write(self._shutdown_pipes[1], b'shutdown\n')
        except:
            pass
        self._logger.info('shutting down')


    def run(self):
        ''' entry point for manager thread. we wait 1 second on launch to allow main
            thread to finish printing config messages
        '''

        #time.sleep(1)
        #x = ctypes.CDLL('libc.so.6').syscall(224)
        #prctl.set_name('DFW:'+self.filter_name)
        #print('filter:{} pid:{}'.format(self.filter_name,os.getpid()))
        #print('filter:{} tid:{}'.format(self.filter_name,x))

        try:
            os.mkdir('/run/dfw', 0o755)
        except FileExistsError:
            pass
        except Exception as e:
            self._logger.debug('exc mkdir: {}'.format(e))

        try:
            os.mkfifo('/run/dfw/shutdown')
        except FileExistsError:
            pass
        except Exception as e:
            self._logger.debug('exc mkfifi: {}'.format(e))

        self._shutdown       = False
        self._shutdown_pipes = os.open('/run/dfw/shutdown', os.O_RDONLY|os.O_NONBLOCK), os.open('/run/dfw/shutdown', os.O_WRONLY|os.O_NONBLOCK)

        self.lkhz = lkhz.LKHZ()
        self.lkhz.calibrate()

        self._build_blocklist()

        self._logger.info('initial entry count for {}: {}'.format(self.filter_name, len([x for x,meta in self.blocklist.items() if meta['blocked_at']])))
        self._periodic()



    def _check_online(self):
        reconnect = False
        if not self.conn:
            reconnect = True

        if self.conn.closed:
            reconnect = True

        if not reconnect:
            try:
                with self.conn.cursor() as c:
                    c.execute('SELECT 1')
            except psycopg2.OperationalError:
                reconnect = True

        if not reconnect:
            return

        self._sql_connect()


    def _sql_connect(self):
        # retry forever
        while True:
            try:
                self.conn = psycopg2.connect(self.dburi)
            except Exception as e:
                self._logger.error('Cannot connect to DB: {}'.format(e))
                time.sleep(10)
                continue

            if not self.conn:
                self._logger.error('cannot mate with DB')
                time.sleep(10)
            else:
                break

        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

        self._logger.info('connecting to DFW SQL server with SSL')

        if __name__ == '__main__':
            self._sql_setup()

        # fire off a trigger to populate our meta data for this filter
        # this is intentionally done using our callback so our code paths
        # remain the same regardless of being a submit client or monitor
        _ = '''SELECT row_to_json(row) FROM
            (SELECT 'INSERT' as action, filter_desc,
                protocol,port,
                EXTRACT(epoch FROM grace_period)::integer AS grace_period,
                grace_count,
                grace_score,
                EXTRACT(epoch FROM dunce_time)::integer AS dunce_time
                    FROM  filter_meta
                    WHERE filter_name=%s) row '''

        with self.conn.cursor() as c:
            c.execute(_, (self.filter_name,))
            _ = c.fetchone()
            if not _:
                self._logger.warning('''no metadata for filter:{}, this filter will be null'''.format(self.filter_name))

            else:
                jdict = _[0]
                self._callback_update_filter_meta(self.conn, jdict)

            # get our whitelists
            _ = '''SELECT row_to_json(row) FROM
                (SELECT 'INSERT' as action, address
                        FROM  filter_whitelist
                        WHERE filter_name=%s
                        ORDER BY address) row '''
            c.execute(_, (self.filter_name,))
            _ = c.fetchall()
            if not _:
                self._logger.warning('''CAUTION, no whitelist data for filter:{}'''.format(self.filter_name))
            for _r in _:
                self._callback_update_filter_whitelist(self.conn, _r[0])

            c.execute('''PREPARE upsert AS
WITH new_values (filter_name,node,local_port,ip,ts,blocked,reasons) AS (
    VALUES
        ($1::text, $2::inet, $3::int, $4::inet, $5::timestamp, $6::boolean, $7::text)
),
upsert AS (
    UPDATE    blocklist vc
    SET       node       = nv.node,
              local_port = nv.local_port,
              ts         = nv.ts,
              blocked    = nv.blocked
    FROM      new_values nv
    WHERE     vc.filter_name  = nv.filter_name
        AND   vc.node         = nv.node
        AND   vc.ip           = nv.ip
    RETURNING vc.*
)
INSERT INTO blocklist (filter_name,node,local_port,ip,ts,blocked,reasons)
    SELECT    filter_name,node,local_port,ip,ts,blocked,reasons
    FROM      new_values nv
    WHERE NOT EXISTS (SELECT 1
        FROM   upsert up
        WHERE    up.filter_name  = nv.filter_name
            AND  up.node         = nv.node
            AND  up.ip           = nv.ip
            )
''')


    def _read_xt_recent(self):
        bl_dic = {}

        if not self.dunce_time:
            return bl_dic

        try:
            with open(self.xt_recent_name) as f:
                expire_at = datetime.datetime.utcnow() - self.dunce_time
                expires   = []

                for _ in f.readlines():
                    _    = _.split(' ',7)
                    ip   = netaddr.IPAddress(_[0][4:])
                    _    = _[7]
                    # this collects the whole timestamp list should we have collected them
                    tsl  = [self.lkhz.jiffies_to_datetime(int(ts)) for ts in _.split(', ')]
                    tsl  = sorted([ts for ts in tsl if ts > expire_at])
                    # todo: only store tsl entries if they're inside grace time
                    if tsl:
                        bl_dic[ip] = {'recents':tsl, 'blocked_at':tsl[0]}
                    else:
                        # this entry should have expired
                        expires.append(ip)

                for ip in expires:
                    self._update_xt_recent(ip)
        except FileNotFoundError:
            pass
        except Exception as e:
            self._logger.warning('Unable to read xt_recent file because of: {}'.format(e))

        return bl_dic


    def _sql_setup(self):
        ''' this is a manager only portion of the tool, regular clients shouldn't
            have access to drop and recreate the tables
        '''
        self._logger.debug('ensuring PgSQL tables exist and trigger procs are created')

        with self.conn.cursor(cursor_factory=psycopg2.extras.NamedTupleCursor) as c:
            try:
                c.execute('select * from blocklist where 1=2')
            except:
                _ = '''
                --
                -- "blocklist" table holds information directly applicable to the xt_recent file
                -- this table permits duplicate rows
                --
                CREATE TABLE blocklist (
                    filter_name       text NOT NULL,                          -- this is the xt_recent name, AKA "mail-pit" or "ssh-scan" etc
                    node              inet NOT NULL,                          -- protected node that reported the triggering event
                    local_port        int,                                    -- local port of connection of node reporting event
                    ip                inet NOT NULL,                          -- ip that caused the triggering event, almost always a /32, but possibly a network
                    ts                timestamp without time zone NOT NULL,   -- effective start time of block (can be updated from repeat offenses)
                    blocked           bool DEFAULT True,                      -- when forgiven, this field is set to False and this record will be historical
                    reasons           text                                    -- \\n separated list of reasons for blocking this block
                )'''
                self._logger.info('creating "blocklist" table')
                c.execute(_)

            try:
                c.execute('select * from recents where 1=2')
            except:
                _ = '''
                --
                -- "recents" table holds grace data that every fw node contributes to
                -- no duplicate rows permitted
                --
                CREATE TABLE recents (
                    filter_name   text NOT NULL,
                    node          inet NOT NULL,
                    ip            inet NOT NULL,
                    penalty       int DEFAULT 1,                              -- penalty factor, determined by rules in the submitting client
                    ts            timestamp without time zone NOT NULL
                )'''
                self._logger.info('creating "recents" table')
                c.execute(_)
                c.execute(''' ALTER TABLE recents ADD UNIQUE (filter_name,node,ip,ts) ''')


            try:
                c.execute('select * from filter_meta where 1=2')
            except:
                _ = '''
                --
                -- "filter_meta" table has grace specifics and firewall protocol/port information
                -- this additional information is necessary for building rules on systems that don't
                -- support the xt_recent module, or xt_recent is compiled in with a 100 host limit.
                -- on these systems we'll build an iptables chain instead of using xt_recent
                --
                CREATE TABLE filter_meta (
                    filter_name   text NOT NULL,
                    filter_desc   text,
                    protocol      text NOT NULL,                                    -- service protocol per /etc/services, aka "tcp", "udp", "icmp"
                    port          integer NOT NULL,                                 -- numeric port
                    grace_period  interval NOT NULL DEFAULT '30 minutes'::interval, -- duration of grace period in seconds (1800 == 30 minutes)
                    grace_count   integer DEFAULT 3,                                -- number of violations permitted within grace period
                    grace_score   integer DEFAULT 25,                               -- total spam score permitted within grace period
                    dunce_time    interval NOT NULL DEFAULT '24 hours'::interval    -- how long the firewall ban should last in seconds (86400==24 hours)
                )'''
                self._logger.info('creating "filter_meta" table')
                c.execute(_)


            try:
                c.execute('select * from filter_whitelist where 1=2')
            except:
                _ = '''
                --
                -- "filter_whitelist" indicates IPs or networks that should never be firewalled for this filter
                --
                CREATE TABLE filter_whitelist (
                    filter_name       text NOT NULL,
                    address           inet NOT NULL,                          -- INET representation of whitelisted IP(s)
                    whitelist_desc    text NOT NULL,                          -- text description explaining why they're whitelisted
                    whitelist_owner   text NOT NULL                           -- contact name or similar, person to speak to regarding this whitelist
                )'''
                self._logger.info('creating "filter_whitelist" table')
                c.execute(_)


            _proc = '''
                CREATE OR REPLACE FUNCTION notify_proc() RETURNS trigger AS $$
                DECLARE
                    _json    json;
                    _record  record;
                BEGIN
                    IF TG_OP = 'INSERT' or TG_OP = 'UPDATE' THEN
                        SELECT TG_TABLE_NAME AS table, TG_OP AS action, NEW.*
                        INTO    _record;
                    ELSE
                        SELECT TG_TABLE_NAME AS table, TG_OP AS action, OLD.*
                        INTO    _record;
                    END IF;

                    _json = row_to_json(_record);
                    PERFORM pg_notify(CAST('dfw' AS text), CAST(_json AS text));

                    IF TG_OP = 'INSERT' or TG_OP = 'UPDATE' THEN
                        RETURN NEW;
                    ELSE
                        RETURN OLD;
                    END IF;

                END;
                $$ LANGUAGE plpgsql;
                '''

            _trig = '''
                DO
                $$
                BEGIN
                    IF NOT EXISTS (SELECT *
                        FROM  information_schema.triggers
                        WHERE event_object_table = '{table}'
                        AND   trigger_name = 'dfw_notify_{table}_{op}'
                    )
                    THEN
                        CREATE TRIGGER dfw_notify_{table}_{op} {when} {op}
                                    ON {table}
                          FOR EACH ROW
                               EXECUTE
                             PROCEDURE notify_proc();
                    END IF;
                END;
                $$
                '''

            c.execute(_proc)

            for table in {'blocklist','recents','filter_meta','filter_whitelist'}:
                for op,when in {'insert':'BEFORE','update':'AFTER','delete':'BEFORE'}.items():
                    c.execute(_trig.format(op=op, when=when, table=table))

            _rule = '''
            CREATE OR REPLACE FUNCTION fix_inet_masklen_f() RETURNS TRIGGER AS $$
            DECLARE
                f  int;
            BEGIN
                f  := family(NEW.ip);
                IF not host(NEW.ip) = '0.0.0.0' THEN
                    IF f = 4 THEN
                        NEW.ip := set_masklen(NEW.ip, 32);
                    ELSEIF f = 6 THEN
                        NEW.ip := set_masklen(NEW.ip, 128);
                    END IF;
                END IF;
                return NEW;
            END;
            $$ LANGUAGE plpgsql;
            '''

            c.execute(_rule)

            _trig = '''
            CREATE TRIGGER verify_inet_masklen_t
            BEFORE INSERT ON {table}
            FOR EACH ROW
            WHEN (masklen(NEW.ip) = 0)
            EXECUTE PROCEDURE fix_inet_masklen_f();
            '''

            for table in {'blocklist','recents'}:
                c.execute('DROP TRIGGER IF EXISTS verify_inet_masklen_t ON {}'.format(table))
                c.execute(_trig.format(table=table))


    def _build_blocklist(self, initial=False):
        ''' ex: src=10.5.5.5 ttl: 0 last_seen: 4299918036 oldest_pkt: 1 4299918036

        totally need to rewrite this section. on load, we should sync to what the
        SQL master has of record and purge everything else
        '''

        self._logger.info('synchronizing with master')
        self._check_online()

        _x = self._read_xt_recent()
        _b = self._get_all_rows(blocked=True)
        #_f = self._get_all_rows(blocked=False)

        #self.printme('len of _x: {}'.format(len(_x)))
        #self.printme('len of _b: {}'.format(len(_b)))

        _xl = sorted(list(_x)) # xt list
        _bl = sorted(list(_b)) # blocked
        #_fl = sorted(list(_f)) # forgiven

        #now         = datetime.datetime.utcnow()
        #forgivetime = now - self.dunce_time

        '''
        for ip in [ip for ip in _xl if _x[ip]['blocked_at'] < forgivetime ]:
            # it may be expired locally but the expire time may be more fresh in sql due to our inability to update the xt_recent entry's timestamp
            # from another offense or a manager's manual update
            _forgivetime = _x[ip]['blocked_at']+self.dunce_time
            if ip in _b and _b[ip]['blocked_at'] and _b[ip]['blocked_at'] > forgivetime:
                delta = _b[ip]['blocked_at'] - _x[ip]['blocked_at']
                self.printme('DFW: exp local but not @master: {}, sql: {}, xt: {}'.format(ip,
                    _b[ip]['blocked_at']+self.dunce_time, _x[ip]['blocked_at']+self.dunce_time,
                    ), console=True) #str(delta).split('.')[0]
                continue

            self.printme('DFW: dunce time expired, forgiving locally: {}'.format(ip))
            self._update_xt_recent(ip, False)

            del _x[ip]
            _xl.remove(ip)

            if ip in _b:
                del _b[ip]
                _bl.remove(ip)
        '''

        '''
        # these are in our local xt_recent file
        push=[(-1,ip,_x[ip]['blocked_at'],True,'auto-recovery') for ip in _xl if not (ip in _bl or ip in _fl) ]
        if push:
            self.printme('DFW: pushing locally blocked IPs {} to SQL'.format([str(x[1]) for x in push]))
            self._push_block(push)
        '''

        # these are listed as blocked in sql but i don't have them
        for ip in [ip for ip in _bl if _b[ip]['blocked_at'] and not ip in _xl ]:
            # don't spam on startup
            if not self.running:
                self._logger.info('▶ new block: {}'.format(ip))
            self._update_xt_recent(ip, True)

        # if not found in sql, remove from xt
        for ip in [ip for ip in _xl if not ip in _bl]:
            self._logger.info('▶ removing stale block: {}'.format(ip))
            self._update_xt_recent(ip, False)

        '''
        # these are listed as forgiven in sql
        for ip in [ip for ip in _xl if ip in _fl and _f[ip]['blocked_at'] ]:  # don't let entries by way of recents fool us
            self.printme('DFW: ▶ manager forgave: {}'.format(ip), console=True)
            self._update_xt_recent(ip, False)
        '''


        _x.update(_b)
        self.blocklist = _x
        #for _ in _x.items():
        #    print('de: {}'.format(_))


    def _get_all_rows(self, blocked=None):
        self._check_online()
        with self.conn.cursor() as c:
            if blocked == None: # all in last self.dunce_time
                _ ='''SELECT node,ip,ts
                    FROM blocklist
                    WHERE filter_name=%(filter_name)s
                    AND   ts > current_timestamp AT TIME ZONE 'utc' -
                          (SELECT dunce_time FROM filter_meta WHERE filter_name=%(filter_name)s)
                    ORDER BY ip'''
                c.execute(_, {'filter_name':self.filter_name})

            elif blocked == True: # blocked
                _ ='''SELECT node,ip,ts
                    FROM blocklist
                    WHERE filter_name=%(filter_name)s
                    AND   blocked
                    AND   ts > current_timestamp AT TIME ZONE 'utc' -
                          (SELECT dunce_time FROM filter_meta WHERE filter_name=%(filter_name)s)
                    ORDER BY ip'''
                c.execute(_, {'filter_name':self.filter_name})

            elif blocked == False: # forgiven
                _ ='''SELECT node,ip,ts
                    FROM blocklist
                    WHERE filter_name=%(filter_name)s
                    AND   not blocked
                    AND   ts > current_timestamp AT TIME ZONE 'utc' -
                          (SELECT dunce_time FROM filter_meta WHERE filter_name=%(filter_name)s)
                    ORDER BY ip'''
                c.execute(_, {'filter_name':self.filter_name})

            _ = c.fetchall()

            if not _:
                return {}

            _r = {}
            for node,ip,ts in _:
                if not isinstance(ip, netaddr.IPAddress):
                    ip = netaddr.IPAddress(ip)
                if not isinstance(node, netaddr.IPAddress):
                    node = netaddr.IPAddress(node)
                _r[ip] = {'node':node, 'recents':[], 'blocked_at':ts, 'penalty':0}

            '''
            # let's cache some?
            _ = self._get_recents(self.conn, self.node_address, nodefetch=True)

            for ip,meta in _.items():
                if not ip in _r:
                    _r[ip] = {'node':None, 'recents':[], 'blocked_at':None, 'penalty':0}
                _r[ip]['recents'] = meta['recents']
                _r[ip]['penalty'] = meta['penalty']
            '''

            return _r


    def _forgive_block(self, ip):
        self._check_online()
        _ = ''' UPDATE blocklist
            SET   blocked=False
            WHERE filter_name=%(filter_name)s
            AND   ip=%(ip)s '''
        with self.conn.cursor() as c:
            c.execute(_, {'filter_name':self.filter_name, 'ip':str(ip)})


    def _push_block(self, blocklist):
        ''' spawn a thread to update the sql db with our info, after updating, delete any rows older than X
        '''

        self._check_online()
        with self.conn.cursor() as c:
            for local_port, ip, ts, blocked, reasons in blocklist:
                c.execute('''EXECUTE upsert (%(filter_name)s, %(node)s, %(local_port)s, %(ip)s, %(ts)s, %(blocked)s, %(reasons)s)''',
                  {'filter_name': self.filter_name,
                   'node':        str(self.node_address),
                   'local_port':  local_port,
                   'ip':          str(ip),
                   'ts':          ts,
                   'blocked':     blocked,
                   'reasons':     reasons})
                #self._logger.debug('{};'.format(c.query.decode('utf-8')))


    def _push_recents(self, ip, penalty, recents=[]):
        ''' spawn a thread to update the sql db with our info
        '''
        self._check_online()
        # todo:
        # this should be a list insert, not for each
        for ts in recents:
            try:
                _ = '''INSERT INTO recents (filter_name,node,ip,penalty,ts)
                    VALUES (%(filter_name)s, %(node)s, %(ip)s, %(penalty)s, %(ts)s) '''
                with self.conn.cursor() as c:
                    c.execute(_, {'filter_name':self.filter_name,
                                  'node':       str(self.node_address),
                                  'ip':         str(ip),
                                  'penalty':    penalty,
                                  'ts':         ts})
            except:
                t,v,tb = sys.exc_info()
                self._logger.error('insert to recents error: {}'.format(v))


    def _get_blocked(self, ip):
        self._check_online()
        _ = '''
           SELECT  ts,reasons
             FROM  blocklist b
        LEFT JOIN  filter_whitelist fw
               ON  (fw.address = b.ip AND fw.filter_name = b.filter_name)
            WHERE  b.filter_name=%(filter_name)s
              AND  fw.address IS NULL
              AND  b.ip = %(ip)s
              AND  b.blocked
         ORDER BY  b.ts
            LIMIT  1 '''
        with self.conn.cursor() as c:
            c.execute(_, {'filter_name':self.filter_name, 'ip':str(ip)})
            _ = c.fetchall()
            #self._logger.debug('{};'.format(c.query.decode('latin-1')))
            if _:
                self._logger.debug('block reasons:')
                for r in _:
                    self._logger.debug('   {}'.format(r[0].strftime('%F %T')))
                    for __ in r[1].split('\n'):
                        self._logger.debug('      {}'.format(__))

        if not _:
            return False

        return _[0]


    def _get_recents(self, conn, ip, nodefetch=False):
        self._check_online()
        if nodefetch:
            _ = '''
            SELECT    ip,ts,penalty
            FROM      recents
            WHERE     filter_name = %(filter_name)s
            AND       node        = %(ip)s
            ORDER BY  ts '''
        else:
            _ = '''
            SELECT   r.ip,sum(r.penalty)::integer,count(1)::integer
            FROM     recents r
            JOIN     filter_meta m
            ON       m.filter_name = r.filter_name
            WHERE    r.filter_name = %(filter_name)s
            AND      r.ip <<= %(ip)s
            AND      r.ts + m.grace_period > now()
            GROUP BY r.ip
            '''

        with conn.cursor() as c:
            c.execute(_, {'filter_name':self.filter_name, 'ip':str(ip)})
            if nodefetch:
                _ = c.fetchall()
            else:
                _ = c.fetchone()
            #self._logger.debug('{};'.format(c.query.decode('latin-1')))
            if _:
                self._logger.debug('recents:')
                if not nodefetch:
                    self._logger.debug('   {:<15}  penalty total:{}, events:{}'.format(_[0],_[1],_[2]))
                else:
                    for r in _:
                        self._logger.debug('   {:<15}  {:<19} {}'.format(r[1].strftime('%F %T'),r[0],r[2]))

        if nodefetch:
            _r = {}
            for _ip,ts,p in _:
                if not ip in _r:
                    _r[ip] = {'recents':[], 'penalty':0}
                _r[ip]['recents'].append(ts)
                _r[ip]['penalty'] += p
        else:
            if not _:
                _ = (ip,0,0)

            _r = {'recents':_[1], 'penalty':_[2]}

        return _r


    # this is a master function only
    def _sql_cleanup(self):
        self._check_online()
        _ = ''' DELETE FROM recents
            WHERE filter_name=%(filter_name)s
            AND   ts < current_timestamp AT TIME ZONE 'utc' -
                  (SELECT grace_period FROM filter_meta WHERE filter_name=%(filter_name)s)
        '''
        with self.conn.cursor() as c:
            c.execute(_, {'filter_name':self.filter_name})


        _ = ''' UPDATE blocklist
            SET   blocked=False
            WHERE blocked
            AND   filter_name=%(filter_name)s
            AND   ts < current_timestamp AT TIME ZONE 'utc' -
                  (SELECT dunce_time FROM filter_meta WHERE filter_name=%(filter_name)s)
        '''
        with self.conn.cursor() as c:
            c.execute(_, {'filter_name':self.filter_name})


    def _periodic(self):
        '''
        monitor changes to the xt_recent file that we didn't make, this will entail detecting +/- in our list
        note: driver/pq3.py is NOT threadsafe, we'll use our own connection here.
        '''
        my_ips = list(self.blocklist)

        __running   = True
        poll_timeout = None
        if self.housekeeper or self.housekeeper_only:
            poll_timeout = 1000*60*1 # one minute

        while __running and not self._shutdown:
            try:
                conn = psycopg2.connect(self.dburi)
                conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            except Exception as e:
                self._logger.error('unable to connect to DB for LISTEN: {}'.format(e))
                time.sleep(10)
                continue

            with conn.cursor() as c:
                c.execute('LISTEN dfw')

            p = select.poll()
            p.register(self._shutdown_pipes[0], select.EPOLLERR|select.EPOLLHUP|select.EPOLLIN|select.EPOLLPRI)
            if not self.housekeeper_only:
                p.register(conn, select.EPOLLIN|select.EPOLLERR|select.EPOLLHUP|select.EPOLLPRI)

            while not self._shutdown:
                x = p.poll(poll_timeout)

                if not x:
                    # timeout expired, clean up aged entries
                    self._sql_cleanup()
                if self.housekeeper_only:
                    continue

                try:
                    conn.poll()
                except psycopg2.OperationalError:
                    self._logger.error('OpErr')
                    break
                except Exception as e:
                    self._logger.error('error polling DB: {}'.format(e))
                    break

                while conn.notifies:
                    notify = conn.notifies.pop(0)
                    jdict  = json.loads(notify.payload)
                    table  = jdict['table']
                    _f     = getattr(self, '_callback_update_'+table)
                    _f(conn, jdict)


    ''' NOTE!!!

        all callbacks that are callable from the periodic thread MUST use the thread local
        instance of the database connection. pq3.py is not thread safe
    '''
    def _callback_update_blocklist(self, conn, jdict):
        ''' perform a local filter add/remove
        '''

        #print('jdict:',jdict)
        if not jdict['filter_name'] == self.filter_name:
            return

        ip     = jdict['ip']
        action = jdict['action']

        if action in ('INSERT','UPDATE'):
            if jdict['blocked']:
                self._logger.info('▶ adding block: {}'.format(ip))
                self._update_xt_recent(ip, True)
            else:
                self._logger.info('▶ removing block: {}'.format(ip))
                self._update_xt_recent(ip, False)

        else:
            self._logger.info('▶ removing block: {}'.format(ip))
            self._update_xt_recent(ip, False)


    # i can't think of a reason to keep this around as is, when we need a recents count,
    # we poll for it - having a callback for every recents update is a lot of unnecessary
    # bandwidth
    def _callback_update_recents(self, conn, jdict):
        ''' update recent hits for this IP when we're notified of changes.

            todo: we really don't want to send DELETEs for recents to everyone,
            this is something they can do themselves. how do i then handle when
            a dfw manager manually removes items from the recents list?
        '''

        ip     = jdict['ip']
        action = jdict['action']

        if action in ('INSERT','UPDATE'):
            if not ip in self.blocklist:
                _ = self._get_recents(conn, ip)
                if _ and ip in _:
                    _ = _[ip]
                else:
                    _ = {'recents':[], 'penalty':0}

                self.blocklist[ip] = {'recents':_['recents'], 'blocked_at':False, 'penalty':_['penalty']}
            else:
                self.blocklist[ip]['recents'].append(jdict['ts'])
                self.blocklist[ip]['penalty'] += jdict['penalty']
        else:
            if ip in self.blocklist and jdict['ts'] in self.blocklist[ip]['recents']:
                self.blocklist[ip]['recents'].remove(jdict['ts'])
                self.blocklist[ip]['penalty'] -= jdict['penalty']


    def _callback_update_filter_whitelist(self, conn, jdict):
        ''' get the whitelist entries. we only care about the ip, nothing else
            updates are not important as the address must be immutable. changes will
            require a delete/insert
        '''

        address = netaddr.IPNetwork(jdict['address'])

        if jdict['action'] == 'INSERT':
            self._logger.info('adding whitelisted address: {}'.format(address))
            self.whitelist.append(address)
        elif jdict['action'] == 'DELETE':
            self._logger.info('removing whitelisted address: {}'.format(address))
            self.whitelist.remove(address)


    def _callback_update_filter_meta(self, conn, jdict):
        ''' assign filter meta information
        '''

        # convert our psql interval strings into seconds. SELECT will return a value in seconds, but our update trigger sends us the string value :?
        with conn.cursor() as c:
            if not isinstance(jdict['grace_period'], int):
                c.execute('''SELECT EXTRACT ('epoch' FROM %(grace_period)s ::interval) ::integer''', {'grace_period':jdict['grace_period']})
                jdict['grace_period'] = c.fetchone()[0]

            if not isinstance(jdict['dunce_time'], int):
                c.execute('''SELECT EXTRACT ('epoch' FROM %(dunce_time)s ::interval) ::integer''', {'dunce_time':jdict['dunce_time']})
                jdict['dunce_time'] = c.fetchone()[0]

        if jdict['action'] in ('INSERT','UPDATE'):
            self.grace_count    = jdict['grace_count']
            self._grace_score    = jdict['grace_score']
            self.grace_period   = datetime.timedelta(seconds=jdict['grace_period'])
            self.dunce_time     = datetime.timedelta(seconds=jdict['dunce_time'])
            self.filter_desc    = jdict['filter_desc']
            self.protocol       = jdict['protocol']
            self.port           = jdict['port']
        else:
            self._logger.critical('''Master deleted our filter meta definition on us! We don't handle this yet''')
            # do an exit? not sure how i'll write multiple filters and their add/removal yet


    def _update_xt_recent(self, ip, insert=True):
        ''' write an update to the xt_recent file
        '''

        ip = '{}{}'.format(insert and '+' or '-', ip)
        try:
            with open(self.xt_recent_name, 'w') as f:
                f.write('{}'.format(ip))
            self.xt_recent_online = True
        except FileNotFoundError:
            if self.running and not self.xt_recent_online:
                self._logger.warning('no xt_recent filter in place with iptables, this filter is running but cannot act on blocks')
        except Exception as e:
            self._logger.warning('error updating firewall with: {}; {}'.format(ip,e))


    # this will go away when the manager is built
    # yes, this is now deprecated
    """
    def _forgive(self):
        ''' parse the xt_recent file, analyze the newest timestamp. if the newest timestamp
            is old enough, remove the entry from the file. once done with our own list
        '''

        # do all SQL forgives here
        self._sql_cleanup()

        now = datetime.datetime.utcnow()
        forgivetime = now - self.dunce_time

        #for ip,meta in self.blocklist.items():
        #    print('{} meta: {}'.format(ip,meta))

        jailbirds = [ip for ip,meta in self.blocklist.items()
            if meta['blocked_at'] and meta['blocked_at'] < forgivetime ]

        for ip in jailbirds:
            _ = now - self.grace_period
            obj = self.blocklist[ip]
            obj['recents'] = sorted([x for x in obj['recents'] if x > _ ])
            if not obj['recents']:
                del self.blocklist[ip]
            else:
                obj['blocked_at'] = None

            try:
                # each line must be written by itself, if you try to write multiple
                # lines, you'll get an illegal seek error
                self._update_xt_recent(ip, False)
                self._logger.info('DFW: forgave {}'.format(ip))

            except Exception as e:
                # need a clean way to handle manually removed ips as opposed to
                # any other error
                self._logger.error('failed to forgive {}; {}'.format(ip,e))
    """

    # public methods
    def ignore(self, *args):
        ''' note, this will only append to the local list. it will NOT globally whitelist
        '''
        if isinstance(args[0], list):
            args=args[0]
        for _ in args:
            if not isinstance(_, netaddr.IPNetwork):
                _ = netaddr.IPNetwork(_)
            self.whitelist.append(_)
            self._logger.info('added local whitelist: {}'.format(_))


    def punish(self, local_port, ip, penalty=1, reasons=['unspecified']):
        if isinstance(ip, str):
            if ip.startswith('IPv6'):
                ip = ip[5:]
            ip = netaddr.IPAddress(ip)

        # never punish ourselves
        for _ in self.whitelist:
            ignore = False
            try:
                if ip in _:
                    ignore = True
            except:
                if ip == _:
                    ignore = True

            if ignore:
                self._logger.info('{} is in ignore list'.format(ip), console=True)
                return

        if not ip in self.blocklist:
            self.blocklist[ip] = {'recents':[], 'blocked_at':False, 'penalty':penalty}

        now = datetime.datetime.utcnow()
        if penalty > 0:
            self._push_recents(ip, penalty, [now])

        obj = self.blocklist[ip]
        _ = self._get_blocked(ip)

        if _: obj['blocked_at'],obj['reasons'] = _[0],_[1]
        else: obj['blocked_at'] = False;

        if not 'reasons' in obj or not obj['reasons']:
            obj['reasons'] = []

        if isinstance(obj['reasons'], str):
            if obj['reasons']:
                obj['reasons'] = obj['reasons'].split('\n')

        _ = self._get_recents(self.conn, ip)

        self._logger.info('DFW: incurred penalty for {}: {}'.format(ip,penalty))
        __ = _ and _['recents'] or 0
        self._logger.info('DFW: {} has {} recents objs'.format(ip,__))

        if _:
            obj['recents'] = _['recents']
            obj['penalty'] = _['penalty']
            self._logger.info('DFW: {} has cumulative penalty of {}'.format(ip,obj['penalty']))

        # push our idea of timestamps to central, get back everyone's actual
        #self._logger.debug('recents for {}: {}'.format(ip, obj['recents']))

        # if not already blocked, see if the assmonkey has shit too many times within the grace period

        # update our filter meta data
        exceeded_count = obj['recents'] > self.grace_count
        exceeded_score = obj['penalty'] > self.grace_score

        self._logger.info('DFW: grace count={} of {}/{} score={} of {}/{}'.format(obj['recents'], self.grace_count, exceeded_count,
            obj['penalty'], self.grace_score, exceeded_score))

        if exceeded_count or exceeded_score:
            if exceeded_count:
                self._logger.info('DFW: applying ban hammer [add to firewall, exceeded permitted events within grace period]', console=True)
                reasons.append('exceeded within grace period; count={} of {}'.format(obj['recents'], self.grace_count))
            if exceeded_score:
                self._logger.info('DFW: applying ban hammer [add to firewall, exceeded permitted score within grace period]', console=True)
                reasons.append('exceeded within grace period; score={} of {}'.format(obj['penalty'], self.grace_score))

            if obj['blocked_at']:
                self._logger.info('DFW: double tap? last block update was at {}, updating block time'.format(obj['blocked_at']), console=True)
                obj['blocked_at'] = now

            # duplicates will now be self eliminating
            reasons = [x.strip() for x in (obj['reasons'] + reasons) if x]
            reasons = [x for x in reasons if x]
            reasons = sorted(set(reasons))
            reason = '\n'.join(reasons)

            # our periodic handler callback will instantiate the actual block
            self._push_block( [(local_port, ip, now, True, reason)] )


    @property
    def grace_score(self):
        # update cached value, this catches up from lost notifications
        _ = 'grace_score' in self.cache and self.cache['grace_score'] > time.time() - self.cache_delta or False
        if not _:
            try:
                with self.conn.cursor() as c:
                    c.execute('''SELECT grace_score FROM filter_meta WHERE filter_name=%(filter_name)s''', {'filter_name':self.filter_name})
                    self._grace_score = c.fetchone()[0]
                    self.cache['grace_score'] = time.time()
            except Exception as e:
                self._logger.info('Error fetching metadata: {}'.format(e), console=True)
        return self._grace_score


    def forgive_when(self, ip):
        if ip.startswith('IPv6:'):
            ip = ip[5:]

        _ = self._get_blocked(ip)
        if _:
            return _[0] + self.dunce_time


class web_interface(threading.Thread):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._shutdown = False

    def shutdown(self):
        self._shutdown = True

    def run(self):
        while not self._shutdown:
            time.sleep(0.5)


def _get_log_level(config, section):
    log_level = _cg_None(config, section, 'log level') or 'info'
    if not log_level.upper() in ('CRITICAL','ERROR','WARNING','INFO','DEBUG'):
        logging.getLogger('DFW').warning('Unrecognized log level: {}'.format(log_level))
    return getattr(logging, log_level.upper())


def _cg_None(config, section, key):
    return  config.get(section, key, fallback=None) or \
            config.get('default', key, fallback=None) or \
            None


if __name__ == '__main__':
    # this is only wanted when run as a listening stand-alone, submission
    # clients will make an instance per filter

    # hmm, make this configurable in the future?
    os.environ['TZ'] = 'UTC'

    logger = logging.getLogger('DFW')
    # if no handlers exist, a basicConfig should be setup
    if True:
        logging.basicConfig(format='%(asctime)-8s %(levelname)-.1s %(name)s %(message)s', datefmt='%F %TZ')

    configfile   = '/etc/DFW/dfw.conf'
    config = ConfigParser(allow_no_value=True, interpolation=ExtendedInterpolation())

    if not config.read(configfile):
        logger.warning('Error reading required configuration file: {}'.format(configfile))

    if False:
        for s in config.sections():
            print(s)
            for k,v in config[s].items():
                print('{:<30}= {}'.format(k,v))
            print()

    log_file  = _cg_None(config, 'default', 'log file') or '/var/log/dfw'
    log_level = _get_log_level(config, 'default')
    logger.setLevel(log_level)

    fh = logging.handlers.TimedRotatingFileHandler(filename=log_file, when='midnight', backupCount=14, encoding='utf-8')
    fm = logging.Formatter(fmt='%(asctime)-8s %(levelname)-.1s %(name)s %(message)s', datefmt='%F %TZ')

    fh.setFormatter(fm)
    logger.addHandler(fh)


    # at least one filter must be named
    filters = [f[7:] for f in config if f.startswith('filter:') \
                        and len(f)>7 ]

    if not filters:
        raise KeyError('at least one filter must be defined')

    # set up a thread for each filter
    managers = {}
    for filter in filters:
        # filters are "enabled" by default, if the keyword "disabled" appears, skip it
        if 'disabled' in config['filter:'+filter]:
            logger.info('filter "{}" is marked disabled, skipping'.format(filter))
            continue

        dburi           = _cg_None(config, 'filter:'+filter, 'db uri')
        log_level       = _cg_None(config, 'filter:'+filter, 'log level')
        use_nftables    = _cg_None(config, 'filter:'+filter, 'use nftables')
        node_address    = _cg_None(config, 'filter:'+filter, 'node address')
        local_whitelist = _cg_None(config, 'filter:'+filter, 'local whitelist') or ''


        local_whitelist = [netaddr.IPNetwork(x) for x in local_whitelist.replace(',','').split() if x]

        errs = []
        if not dburi:
            errs.append('db uri')
        if not node_address:
            errs.append('node address')

        if errs:
            logger.error('the following config parameters are required for filter: {}; {}'.format(filter,errs))
            continue

        _log_level = _get_log_level(config, 'default')
        _logger = logging.getLogger(filter)
        _logger.setLevel(_log_level)

        _log_file  = _cg_None(config, 'default', 'log file') or '/var/log/dfw'

        _fh = logging.handlers.TimedRotatingFileHandler(filename=log_file+':'+filter, when='midnight', backupCount=14, encoding='utf-8')
        _fm = logging.Formatter(fmt='%(asctime)-8s %(levelname)-.1s %(name)s %(message)s', datefmt='%F %TZ')

        _fh.setFormatter(_fm)
        _logger.addHandler(_fh)

        hk  = 'housekeeper' in sys.argv
        hko = 'housekeeperonly' in sys.argv

        dfw = DFW(name=filter, node_address=node_address, dburi=dburi,
                 **{'use_nftables':use_nftables, 'logger':_logger,
                  'housekeeper':hk, 'housekeeperonly':hko})

        if local_whitelist:
            dfw.ignore(local_whitelist)

        managers[filter] = {'th':dfw}
        dfw.start()

    # start a thread for the web interface
    web = web_interface(name='webUI')
    web.start()

    # do nothing
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        for filter in managers:
            t = managers[filter]['th']
            logger.info('shutting down {}'.format(t.name))
            t.shutdown()
            t.join()

        web.shutdown()
        web.join()
