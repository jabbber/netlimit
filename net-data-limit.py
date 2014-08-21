#!/usr/bin/env python2
#monitor network traffic by mac, reject it when over limit
#author: jabber zhou
import os,sys
import re
import subprocess
import pickle
import time

subnet = '192.168.122.0/24'

rundir=os.path.realpath(os.path.dirname(unicode(__file__, sys.getfilesystemencoding( ))))
tabfile=os.path.join(rundir,'limit.tab')
ratefile=os.path.join(rundir,'rate.db')

def error(level,content,reason=None):
    if reason:
        sys.stderr.write('%s: %s,\n%s\n'%(level, content, reason))
    else:
        sys.stderr.write('%s: %s\n'%(level, content))

def iptables(command):
    '''run iptables commands, return exit status and print to stderr when exit status not 0'''
    try:
        out = subprocess.check_call(['iptables']+command)
    except subprocess.CalledProcessError, err:
        error('warning',"run '%s' error with stat %d"%(' '.join(err.cmd),err.returncode))
        return err.returncode
    return 0

def getLimit():
    mactab={}
    with open(tabfile) as tab:
        for (num, line) in enumerate(tab.readlines()):
            line = line.split('#')[0]
            line = line.strip()
            if line:
                line = re.split('\s+', line)
                if re.match('^([0-9,a-f,A-F]{2}:){5}[0-9,a-f,A-F]{2}$', line[0]):
                    mac = line[0].upper()
                    if re.match('^\d+$', line[1]):
                        limit = int(line[1])
                        mactab[mac] = limit
                    else:
                        error('warning', "'%s' syntax wrong in line %d'"%(tabfile,num+1), "illegal limit bytes '%s'."%line[1])
                else:
                    error('warning', "'%s' syntax wrong in line %d"%(tabfile,num+1), "illegal mac address '%s'."%line[0])
    return mactab

def getArp():
    arptab={}
    with open('/proc/net/arp') as arp:
        for line in arp.readlines():
            line = line.strip()
            line = re.split('\s+', line)
            if re.match('^([0-9,a-f,A-F]{2}:){5}[0-9,a-f,A-F]{2}$', line[3]):
                mac = line[3].upper()
                ip = line[0]
                arptab[mac] = ip
    return arptab

def init():
    '''create user chain to monitor traffic'''
    rules = []
    for chain in ('traffic-up','traffic-down'):
        rules.append(['-N', chain])
        rules.append(['-F', chain])
    rules.append(['-D','FORWARD','-s',subnet,'-j','traffic-up'])
    rules.append(['-D','FORWARD','-d',subnet,'-j','traffic-down'])
    rules.append(['-I','FORWARD','-s',subnet,'-j','traffic-up'])
    rules.append(['-I','FORWARD','-d',subnet,'-j','traffic-down'])
    rules.append(['-A','traffic-up','-j','REJECT','--reject-with','icmp-net-prohibited'])
    for rule in rules:
        try:
            subprocess.check_output(['iptables']+rule, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, err:
            if err.returncode != 1:
                error('error', "run '%s' fail"%' '.join(err.cmd), err.output)
                sys.exit(err.returncode)

def getUpChain():
    chain = 'traffic-up'
    output = subprocess.check_output(['iptables','-L',chain,'-nv','--line-numbers']).strip().split('\n')
    loc = re.split('\s+', output[1])
    upinfo = {}
    for line in output[2:]:
        row = re.split('\s+', line)
        if re.match('^([0-9,a-f,A-F]{2}:){5}[0-9,a-f,A-F]{2}$', row[-1]):
            if not upinfo.has_key(row[-1]):
                upinfo[row[-1]] = {name:row[num] for num,name in enumerate(loc)}
    return upinfo

def getDownChain():
    chain = 'traffic-down'
    output = subprocess.check_output(['iptables','-L',chain,'-nv','--line-numbers']).strip().split('\n')
    loc = {name:num for num,name in enumerate(re.split('\s+', output[1].strip()))}
    downinfo = {}
    for line in output[2:]:
        row = re.split('\s+', line)
        if re.match('^([0-9]{1,3}.){3}[0-9]{1,3}$', row[loc['destination']]):
            if not downinfo.has_key(row[loc['destination']]):
                downinfo[row[loc['destination']]] = {name:row[loc[name]] for name in loc}
    return downinfo

def getRate():
    if os.path.isfile(ratefile):
        with open(ratefile,'r') as f:
            ratetab = pickle.load(f)
    else:
        ratetab = {}
    upChain = getUpChain()
    downChain = getDownChain()
    arptab = getArp()
    for mac in getLimit():
        if not ratetab.has_key(mac):
            ratetab[mac] = {'up':0,'o_up':0,'down':0,'o_down':0}
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
    with open(ratefile,'w') as f:
        pickle.dump(ratetab,f)
    return ratetab

def upCtrl():
    chain = 'traffic-up'
    rules = []
    limittab = getLimit()
    upchain = getUpChain()
    ratetab = getRate()
    accept_mac = set()
    for mac in limittab:
        if ratetab[mac]['up'] + ratetab[mac]['down'] < limittab[mac]:
            accept_mac.add(mac)
    delmac = set(upchain.keys()).difference(accept_mac)
    for mac in delmac:
        rules.append(['-D',chain,'-m','mac','--mac-source',mac,'-j','RETURN'])
    newmac = accept_mac.difference(set(upchain.keys()))
    for mac in newmac:
        rules.append(['-I',chain,'-m','mac','--mac-source',mac,'-j','RETURN'])
    for rule in rules:
        try:
            subprocess.check_output(['iptables']+rule, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, err:
            error('error', "run '%s' fail"%' '.join(err.cmd), err.output)

def downCtrl():
    chain = 'traffic-down'
    rules = []
    monitor_mac = getLimit().keys()
    downchain = getDownChain()
    arptab = getArp()
    ips = [arptab[mac] for mac in arptab if mac in monitor_mac]
    for ip in ips:
        if not downchain.has_key(ip):
            rules.append(['-A',chain,'-d',ip,'-j','RETURN'])
    for rule in rules:
        try:
            subprocess.check_output(['iptables']+rule, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, err:
            error('error', "run '%s' fail"%' '.join(err.cmd), err.output)

init()
while True:
    upCtrl()
    downCtrl()
    print getRate()
    time.sleep(1)

