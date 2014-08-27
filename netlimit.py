#!/usr/bin/env python2
#monitor network traffic by mac, reject it when over limit
#author: jabber zhou
import os,sys
import re
#import subprocess
import commands
import pickle
import time
import traceback

subnet = '192.168.122.0/24'

rundir=os.path.realpath(os.path.dirname(unicode(__file__, sys.getfilesystemencoding( ))))
tabfile=os.path.join(rundir,'limit.tab')
ratefile=os.path.join(rundir,'rate.db')

def error(level,content,reason=None):
    if reason:
        sys.stderr.write('%s: %s,\n%s\n'%(level, content, reason))
    else:
        sys.stderr.write('%s: %s\n'%(level, content))

class IptablesError(EOFError):
    pass
def iptables(rule, skip = [], warning = []):
    '''run iptables commands, return exit status and print to stderr when exit status not 0'''
    cmd = 'iptables '+' '.join(rule)
    (status, output) = commands.getstatusoutput(cmd)
    status = status/256
    if not status:
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

def sumExtra():
    if os.path.isfile(ratefile):
        with open(ratefile,'r') as f:
            ratetab = pickle.load(f)
    else:
        ratetab = {}
    limittab = getLimit()
    for mac in limittab:
        if ratetab.has_key(mac):
            ratetab[mac]['extra'] += limittab[mac]['limit'] - ratetab[mac]['up'] - ratetab[mac]['down']
            ratetab[mac]['up'] = 0
            ratetab[mac]['down'] = 0
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
    else:
        error('error',"mac address '%s' is not exist."%mac)
        return 1
    with open(ratefile,'w') as f:
        pickle.dump(ratetab,f)

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
    print "name\tmac_address     \tip_address\tup\tdown\tquota"
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
        print "%s\t%s\t%s\t%s\t%s\t%s+%s"%(limit[mac]['name'], mac, ip, up, down,limit[mac]['limit'],rate[mac]['extra'])

def printHelp():
    print '''usage:
    start       start daemon
    stop        stop daemon
    status      show status and rate
'''

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

if len(sys.argv) > 1:
    if sys.argv[1] == 'start':
        (tm_year,tm_mon,tm_mday,tm_hour,tm_min,
        tm_sec,tm_wday,tm_yday,tm_isdst) = time.localtime()
        clear = FlagJob(clearRate,tm_mon)
        sum_extra = FlagJob(sumExtra,tm_mday)
        store = FlagJob(sumRate,tm_min)
        up_ctrl = FlagJob(upCtrl,tm_sec)
        down_ctrl = FlagJob(downCtrl,tm_sec)
        init()
        while True:
            (tm_year,tm_mon,tm_mday,tm_hour,tm_min,
            tm_sec,tm_wday,tm_yday,tm_isdst) = time.localtime()
            store.do(tm_min)
            clear.do(tm_mon)
            sum_extra.do(tm_mday)
            up_ctrl.do(tm_sec)
            down_ctrl.do(tm_sec)
            time.sleep(1)
    elif sys.argv[1] == 'stop':
        sumRate()
        uninit()
    elif sys.argv[1] == 'status':
        printRate()
    elif sys.argv[1] == 'add':
        if len(sys.argv) == 4:
            if getLimit().has_key(sys.argv[2]):
                try:
                    quota = int(sys.argv[3])
                except:
                    print "'%s' is not a integer."%sys.argv[3]
                    sys.exit(2)
                addExtra(sys.argv[2],quota)
        else:
            print "'%s' in not in limit.tab."
            sys.exit(1)
    else:
        printHelp()
else:
    printHelp()
