#!/usr/bin/env python2
#monitor network traffic by mac, reject it when over limit
#author: jabber zhou
import os,sys
import re
import commands
import pickle
import time
import traceback
import signal

subnet = '192.168.122.0/24'
pidfile = '/var/run/netlimit.pid'

rundir=os.path.realpath(os.path.dirname(unicode(__file__, sys.getfilesystemencoding( ))))
logfile=os.path.join(rundir,'netlimit.log')
tabfile=os.path.join(rundir,'limit.tab')
ratefile=os.path.join(rundir,'rate.db')
hratefile=os.path.join(rundir,'hrate.db')
daemon = 0

def error(level,content,reason=None):
    global daemon
    if daemon:
        if reason:
            sys.stderr.write('%s netlimit[%d]%s: %s,\n%s\n'%(time.ctime(),os.getpid(),level, content, reason))
        else:
            sys.stderr.write('%s netlimit[%d]%s: %s\n'%(time.ctime(),os.getpid(),level, content))
    else:
        if reason:
            sys.stderr.write('%s: %s,\n%s\n'%(level, content, reason))
        else:
            sys.stderr.write('%s: %s\n'%(level, content))

def log(level,content,pid=None):
    if pid:
        open(logfile,'a+').write("%s netlimit[%d]%s: %s\n"%(time.ctime(), pid, level, content))
    else:
        open(logfile,'a+').write("%s %s: %s\n"%(time.ctime(), level, content))

class IptablesError(EOFError):
    pass
def iptables(rule, skip = [], warning = []):
    '''run iptables commands, return exit status and print to stderr when exit status not 0'''
    cmd = 'iptables '+' '.join(rule)
    (status, output) = commands.getstatusoutput(cmd)
    status = status/256
    if not status:
        if cmd.find('-L') < 0:
            error('info',"change iptabls rules: '%s'"%cmd)
        return output
    elif status in skip:
        return ''
    elif status in warning:
        error('warning', "run '%s' fail with exit stat %d"%(cmd, status), output)
        return ''
    else:
        error('error', "run '%s' fail with exit stat %d"%(cmd, status), output)
        raise IptablesError

def getLimit():
    mactab={}
    with open(tabfile) as tab:
        for (num, line) in enumerate(tab.readlines()):
            line = line.split('#')[0]
            line = line.strip()
            if line:
                line = re.split('\s+', line)
                if re.match('^(?:[0-9,a-f,A-F]{2}:){5}[0-9,a-f,A-F]{2}$', line[1]):
                    mac = line[1].upper()
                    if re.match('^\d+$', line[2]):
                        limit = int(line[2])
                        mactab[mac] = {'limit':limit,'name':line[0]}
                    else:
                        error('warning', "'%s' syntax wrong in line %d'"%(tabfile,num+1), "illegal limit bytes '%s'."%line[2])
                else:
                    error('warning', "'%s' syntax wrong in line %d"%(tabfile,num+1), "illegal mac address '%s'."%line[1])
    return mactab

def getArp():
    arptab={}
    with open('/proc/net/arp') as arp:
        for line in arp.readlines():
            line = line.strip()
            line = re.split('\s+', line)
            if re.match('^(?:[0-9,a-f,A-F]{2}:){5}[0-9,a-f,A-F]{2}$', line[3]):
                mac = line[3].upper()
                ip = line[0]
                arptab[mac] = ip
    return arptab

def init():
    '''create user chain to monitor traffic'''
    for chain in ('traffic-up','traffic-down'):
        #skip stat 1,iptables: Chain already exists.
        iptables(['-N', chain],[1])
    #skip stat 1 "iptables: No chain/target/match by that name."
    iptables(['-D','FORWARD','-s',subnet,'-j','traffic-up'],[1])
    iptables(['-D','FORWARD','-d',subnet,'-j','traffic-down'],[1])
    iptables(['-I','FORWARD','-s',subnet,'-j','traffic-up'])
    iptables(['-I','FORWARD','-d',subnet,'-j','traffic-down'])
    iptables(['-D','traffic-up','-j','REJECT','--reject-with','icmp-net-prohibited'],[1])
    iptables(['-A','traffic-up','-j','REJECT','--reject-with','icmp-net-prohibited'])

def uninit():
    '''del user chain to monitor traffic'''
    #skip stat 1 "iptables: No chain/target/match by that name."
    #skip stat 2,iptables v1.4.21: Couldn't load target `traffic-up':No such file or directory
    iptables(['-D','FORWARD','-s',subnet,'-j','traffic-up'],[1,2])
    iptables(['-D','FORWARD','-d',subnet,'-j','traffic-down'],[1,2])
    for chain in ('traffic-up','traffic-down'):
        #skip stat 1,iptables: No chain/target/match by that name.
        iptables(['-F', chain],[1])
        iptables(['-X', chain],[1])

def getUpChain():
    chain = 'traffic-up'
    #worning stat 3,iptables v1.4.21: can't initialize iptables table `filter': Permission denied (you must be root)
    #worning stat 1,iptables: No chain/target/match by that name.
    output = iptables(['-L',chain,'-nv','--line-numbers'],warning = [1,3])
    if not output:
        return {}
    else:
        output = output.strip().split('\n')
    upinfo = {}
    loc = re.split('\s+', output[1])
    for line in output[2:]:
        mac_find = re.findall('(?:[0-9,a-f,A-F]{2}:){5}[0-9,a-f,A-F]{2}', line)
        if mac_find:
            row = re.split('\s+', line)
            if not upinfo.has_key(mac_find[0]):
                upinfo[mac_find[0]] = {}
                for num,name in enumerate(loc):
                    upinfo[mac_find[0]][name] = row[num]
    return upinfo

def getDownChain():
    chain = 'traffic-down'
    #worning stat 3,iptables v1.4.21: can't initialize iptables table `filter': Permission denied (you must be root)
    #worning stat 1,iptables: No chain/target/match by that name.
    output = iptables(['-L',chain,'-nv','--line-numbers'],warning = [1,3])
    if not output:
        return {}
    else:
        output = output.strip().split('\n')
    downinfo = {}
    #loc = {name:num for num,name in enumerate(re.split('\s+', output[1].strip()))}
    loc = {}
    for num,name in enumerate(re.split('\s+', output[1].strip())):
        loc[name] = num
    for line in output[2:]:
        row = re.split('\s+', line)
        if re.match('^([0-9]{1,3}.){3}[0-9]{1,3}$', row[loc['destination']]):
            if not downinfo.has_key(row[loc['destination']]):
                #downinfo[row[loc['destination']]] = {name:row[loc[name]] for name in loc}
                downinfo[row[loc['destination']]] = {}
                for name in loc:
                    downinfo[row[loc['destination']]][name] = row[loc[name]]
    return downinfo

def isMonitor():
    for chain in ('traffic-up,','traffic-down'):
        upchain = iptables(['-L',chain,'-nv','--line-numbers'],[1],warning = [3])
        downchain = iptables(['-L',chain,'-nv','--line-numbers'],[1],warning = [3])
    if upchain or downchain:
        return True
    else:
        return False

def getRate():
    '''sum current rate'''
    if os.path.isfile(ratefile):
        with open(ratefile,'r') as f:
            ratetab = pickle.load(f)
    else:
        ratetab = {}
    upChain = getUpChain()
    downChain = getDownChain()
    arptab = getArp()
    for mac in upChain:
        if not ratetab.has_key(mac):
            ratetab[mac] = {'up':0,'o_up':0,'down':0,'o_down':0,'extra':0}
        if upChain.has_key(mac):
            if ratetab[mac]['o_up'] > upChain[mac]['bytes']:
                upbyte = int(upChain[mac]['bytes'])
            else:
                upbyte = int(upChain[mac]['bytes']) - ratetab[mac]['o_up']
            ratetab[mac]['up'] += upbyte
            ratetab[mac]['o_up'] = int(upChain[mac]['bytes'])
        if arptab.has_key(mac):
            if downChain.has_key(arptab[mac]):
                if ratetab[mac]['o_down'] > downChain[arptab[mac]]['bytes']:
                    downbyte = int(downChain[arptab[mac]]['bytes'])
                else:
                    downbyte = int(downChain[arptab[mac]]['bytes']) - ratetab[mac]['o_down']
                ratetab[mac]['down'] += downbyte
                ratetab[mac]['o_down'] = int(downChain[arptab[mac]]['bytes'])
    return ratetab

def sumRate():
    ratetab = getRate()
    with open(ratefile,'w') as f:
        pickle.dump(ratetab,f)
    return ratetab

def saveHRate(ratetab):
    (tm_year,tm_mon,tm_mday,tm_hour,tm_min,
    tm_sec,tm_wday,tm_yday,tm_isdst) = time.localtime()
    if os.path.isfile(hratefile):
        with open(hratefile,'r') as f:
            hratetab = pickle.load(f)
    else:
        hratetab = {}
    hratetab["%d-%d"%(tm_mon,tm_mday)] = ratetab
    with open(hratefile,'w') as f:
        pickle.dump(hratetab,f)

def printHRate(mon,mday):
    if os.path.isfile(hratefile):
        with open(hratefile,'r') as f:
            hratetab = pickle.load(f)
    else:
        hratetab = {}
    limittab = getLimit()
    if hratetab.has_key("%d-%d"%(mon,mday)):
        print("name\tmac_address     \tup\tdown\ttotal")
        ratetab = hratetab["%d-%d"%(mon,mday)]
        for mac in ratetab:
            if limittab.has_key(mac):
                name = limittab[mac]['name']
            else:
                name = 'none'
            print("%s\t%s\t%s\t%s\t%s"%(name, mac, ratetab[mac]['up'], ratetab[mac]['down'],ratetab[mac]['up']+ratetab[mac]['down']))
    else:
        print('no data in %d-%d'%(mon,mday))

def sumExtra():
    if os.path.isfile(ratefile):
        with open(ratefile,'r') as f:
            ratetab = pickle.load(f)
    else:
        ratetab = {}
    limittab = getLimit()
    saveHRate(ratetab)
    for mac in limittab:
        if ratetab.has_key(mac):
            num = limittab[mac]['limit'] - ratetab[mac]['up'] - ratetab[mac]['down']
            ratetab[mac]['extra'] += num
            ratetab[mac]['up'] = 0
            ratetab[mac]['down'] = 0
            error('info',"auto add extra %d bytes to %s[%s]"%(num,limittab[mac]['name'],mac))
    with open(ratefile,'w') as f:
        pickle.dump(ratetab,f)

def addExtra(mac,num):
    if os.path.isfile(ratefile):
        with open(ratefile,'r') as f:
            ratetab = pickle.load(f)
    else:
        ratetab = {}
    limittab = getLimit()
    if ratetab.has_key(mac) and limittab.has_key(mac):
        ratetab[mac]['extra'] += num
        with open(ratefile,'w') as f:
            pickle.dump(ratetab,f)
        log('info',"add extra %d bytes to %s[%s]"%(num,limittab[mac]['name'],mac))
    else:
        error('error',"mac address '%s' is not exist."%mac)
        return 1

def clearRate():
    with open(ratefile,'w') as f:
        pickle.dump({},f)

def upCtrl():
    chain = 'traffic-up'
    limittab = getLimit()
    upchain = getUpChain()
    ratetab = getRate()
    accept_mac = set()
    for mac in limittab:
        if ratetab.has_key(mac):
            if ratetab[mac]['up'] + ratetab[mac]['down'] < limittab[mac]['limit'] + ratetab[mac]['extra']:
                accept_mac.add(mac)
        else:
            accept_mac.add(mac)
            
    delmac = set(upchain.keys()).difference(accept_mac)
    for mac in delmac:
        iptables(['-D',chain,'-m','mac','--mac-source',mac,'-j','RETURN'])
    newmac = accept_mac.difference(set(upchain.keys()))
    for mac in newmac:
        #worning exit 3 "iptables v1.4.21: can't initialize iptables table `filter': Permission denied (you must be root)"
        iptables(['-I',chain,'-m','mac','--mac-source',mac,'-j','RETURN'],[3])

def downCtrl():
    chain = 'traffic-down'
    monitor_mac = getLimit().keys()
    downchain = getDownChain()
    arptab = getArp()
    ips = [arptab[mac] for mac in arptab if mac in monitor_mac]
    for ip in ips:
        if not downchain.has_key(ip):
            #worning exit 3 "iptables v1.4.21: can't initialize iptables table `filter': Permission denied (you must be root)"
            iptables(['-A',chain,'-d',ip,'-j','RETURN'],[3])
    for ip in downchain:
        if not ip in ips:
            iptables(['-D',chain,'-d',ip,'-j','RETURN'])

def dayCtrl():
    (tm_year,tm_mon,tm_mday,tm_hour,tm_min,
    tm_sec,tm_wday,tm_yday,tm_isdst) = time.localtime()
    days = 31
    if tm_mon == 2:
        if tm_year%4:
            days = 28
        elif not tm_year%400:
            days = 29
        elif not tm_year%100:
            days = 28
        else:
            days = 29
    elif tm_mon in (4,6,9,11):
        days = 30
    if (tm_wday + (days - tm_mday)%7)%7 in (5,6):
        return (days - (tm_wday + (days - tm_mday)%7)%7 + 4)
    else:
        return days

def printRate():
    rate = getRate()
    limit = getLimit()
    arp = getArp()
    print("name\tmac_address     \tip_address\tup\tdown\tquota")
    for mac in limit:
        if arp.has_key(mac):
            ip = arp[mac]
        else:
            ip = 'not_alive'
        if rate.has_key(mac):
            up = rate[mac]['up']
            down = rate[mac]['down']
        else:
            up = 'not_trace'
            down = 'not_trace'
        left_bytes = (limit[mac]['limit'] + rate[mac]['extra'] - up - down)
        print("%s\t%s\t%s\t%s\t%s\t%s+%s"%(limit[mac]['name'], mac, ip, up, down,limit[mac]['limit'],rate[mac]['extra']))

class FlagJob:
    '''try to do some thing when flag change'''
    def __init__(self,function,flag = None):
        self.flag = flag
        self.function = function
    def do(self,flag):
        if self.flag != flag:
            try:
                self.function()
                self.flag = flag
            except:
                error('error',traceback.print_exc())

def keepPid():
    if os.path.isfile(pidfile):
        try:
            pid = int(open(pidfile).read().strip())
        except:
            pid = None
        if pid:
            if os.getpid() != pid:
                if isDaemon(pidfile):
                    error('error',"'%s' is not match, current pid is %d, but %d in pidfile."%(pidfile,os.getpid(),pid))
                    error('error',"daemon is already running, this process stop.")
                    sys.exit(5)
    try:
        open(pidfile,'w').write(str(os.getpid())+'\n')
    except:
        error('error',traceback.print_exc())
        error('error',"can not write %s, process stop"%pidfile)
        sys.exit(4)

def isDaemon():
    if os.path.isfile(pidfile):
        try:
            pid = int(open(pidfile).read().strip())
        except:
            pid = None
        if pid:
            if os.path.isdir('/proc/%d'%pid):
                return True
    return False

def stopDaemon():
    if isDaemon():
        print 'stopping...'
        pid = int(open(pidfile).read().strip())
        log('info',"daemon stoping...",pid)
        try:
            os.kill(pid,15)
            os.remove(pidfile)
        except:
            pass
    else:
        error('warning',"daemon not running.")
    n = 0
    while isDaemon():
        n += 1
        time.sleep()
        if n > 10:
            error('error',"stop fail,process %d is still alive."%pid)
            sys.exit(7)
    if os.path.isfile(pidfile):
        os.remove(pidfile)
    if isMonitor():
        sumRate()
        log('info',"current rate has been store")
    uninit()
    print 'stop success!'

def startDaemon():
    if isDaemon():
        print("netlimit is already running.")
        sys.exit(0)

    pid = os.fork()
    if pid:
        def onSigChld(num,inter):
            print('start fail!')
            sys.exit(1)
        signal.signal(signal.SIGCHLD, onSigChld)
        print('starting...')
        n = 0
        while not isDaemon():
            n += 1
            if n > 100:
                print('start time out!')
                sys.exit(1)
            time.sleep(0.1)
        print("start success!")
        sys.exit(0)
    os.setsid()
    devnull = os.open('/dev/null',os.O_RDWR)
    logop = open(logfile,'a',1)
    os.dup2(devnull,0)
    os.dup2(logop.fileno(),1)
    os.dup2(logop.fileno(),2)
    os.close(devnull)
    del devnull,logop
    global daemon
    daemon = 1

    (tm_year,tm_mon,tm_mday,tm_hour,tm_min,
    tm_sec,tm_wday,tm_yday,tm_isdst) = time.localtime()
    clear = FlagJob(clearRate,tm_mon)
    sum_extra = FlagJob(sumExtra,tm_mday)
    store = FlagJob(sumRate,tm_min)
    up_ctrl = FlagJob(upCtrl,tm_sec)
    down_ctrl = FlagJob(downCtrl,tm_sec)
    init()
    error('info',"netlimit has been started.")
    while True:
        (tm_year,tm_mon,tm_mday,tm_hour,tm_min,
        tm_sec,tm_wday,tm_yday,tm_isdst) = time.localtime()
        store.do(tm_min)
        clear.do(tm_mon)
        sum_extra.do(tm_mday)
        up_ctrl.do(tm_sec)
        down_ctrl.do(tm_sec)
        keepPid()
        time.sleep(1)

def printHelp():
    print('''usage:
    start       start daemon
    stop        stop daemon
    restart     stop and start daemon
    status      show status and rate
''')

if len(sys.argv) > 1:
    if sys.argv[1] == 'start':
        startDaemon()
    elif sys.argv[1] == 'stop':
        stopDaemon()
    elif sys.argv[1] == 'restart':
        stopDaemon()
        startDaemon()
    elif sys.argv[1] == 'status':
        printRate()
    elif sys.argv[1] == 'hrate':
        if len(sys.argv) == 4:
            try:
                mon = int(sys.argv[2])
                mday = int(sys.argv[3])
            except:
                print("hrate need two number as month and mday")
                sys.exit(1)
            printHRate(mon,mday)
        else:
            print("hrate need two number as month and mday")
            sys.exit(1)
    elif sys.argv[1] == 'add':
        if len(sys.argv) == 4:
            if getLimit().has_key(sys.argv[2]):
                try:
                    quota = int(sys.argv[3])
                except:
                    print("'%s' is not a integer."%sys.argv[3])
                    sys.exit(2)
                addExtra(sys.argv[2],quota)
            else:
                print("'%s'is not a mac address exist in limit.tab"%sys.argv[2])
        else:
            print("'add' need a mac address and a num of bytes")
            sys.exit(1)
    else:
        printHelp()
else:
    printHelp()
