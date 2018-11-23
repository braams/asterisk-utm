#!/usr/local/bin/python

import socket, sys
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import asterisk.agi

raddict = Dictionary("/usr/share/freeradius/dictionary", "/usr/share/freeradius/dictionary.cisco")

server = "192.168.0.1"
nas = "192.168.0.2"
secret = "secret"
agi = asterisk.agi.AGI()


def auth(user, password, src, dst):
    agi.verbose("user %s,password %s,src %s, dst %s" % (user, password, src, dst))
    srv = Client(server=server, authport=1812, secret=secret, dict=raddict)
    req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest)
    req["NAS-IP-Address"] = nas
    req["User-Name"] = user
    req["User-Password"] = req.PwCrypt(password)
    req["Calling-Station-Id"] = src
    req["Called-Station-Id"] = dst

    maxdur = 0
    try:
        reply = srv.SendPacket(req)
    except pyrad.client.Timeout:
        agi.verbose("RADIUS server does not reply")
        # sys.exit(1)
        return 0
    except socket.error, error:
        agi.verbose("Network error: " + error[1])
        # sys.exit(1)
        return 0
    if reply.code == pyrad.packet.AccessAccept:
        agi.verbose("Access accepted")
        maxdur = int(reply[(9, 102)][0].split("=")[1]) * 1000
        agi.verbose("Max duration: %d" % maxdur)
    else:
        agi.verbose("Access denied")
    return maxdur


def start(user, id, src, dst):
    srv = Client(server=server, acctport=1813, secret=secret, dict=raddict)
    req = srv.CreateAcctPacket()
    req["Acct-Status-Type"] = "Start"
    req["NAS-IP-Address"] = nas
    req["User-Name"] = user
    req["Calling-Station-Id"] = src
    req["Called-Station-Id"] = dst
    req["Acct-Session-Id"] = id
    try:
        reply = srv.SendPacket(req)
    except pyrad.client.Timeout:
        agi.verbose("RADIUS server does not reply")
        sys.exit(1)
    except socket.error, error:
        agi.verbose("Network error: " + error[1])
        sys.exit(1)


def stop(user, id, src, dst):
    srv = Client(server=server, acctport=1813, secret=secret, dict=raddict)
    req = srv.CreateAcctPacket()
    req["Acct-Status-Type"] = "Stop"
    req["NAS-IP-Address"] = nas
    req["User-Name"] = user
    req["Calling-Station-Id"] = src
    req["Called-Station-Id"] = dst
    req["Acct-Session-Id"] = id
    try:
        reply = srv.SendPacket(req)
    except pyrad.client.Timeout:
        agi.verbose("RADIUS server does not reply")
        sys.exit(1)
    except socket.error, error:
        agi.verbose("Network error: " + error[1])
        sys.exit(1)


agi.verbose("begin")
if sys.argv[1] == "auth":
    if len(sys.argv[2]) > 1 and len(sys.argv[3]) > 1 and len(sys.argv[4]) > 1 and len(sys.argv[5]) > 1:
        agi.verbose("auth")
        maxdur = auth(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        agi.set_variable('maxdur', str(maxdur))
    else:
        agi.verbose("auth: bad params")
elif sys.argv[1] == "start":
    if len(sys.argv[2]) > 1 and len(sys.argv[3]) > 1 and len(sys.argv[4]) and len(sys.argv[5]) > 1:
        agi.verbose("start")
        start(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        agi.verbose("start: bad params")
elif sys.argv[1] == "stop":
    if len(sys.argv[2]) > 1 and len(sys.argv[3]) > 1 and len(sys.argv[4]) and len(sys.argv[5]) > 1:
        agi.verbose("stop")
        stop(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        agi.verbose("stop: bad params")
else:
    agi.verbose("bad action")

agi.verbose("end")
