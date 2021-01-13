#Hl7 message fuzzer
#twitter: 0xRaindrop

import argparse
import socket
import queue
from os import listdir, urandom
from random import randrange, choice
from sqlalchemy import create_engine, Table, Column, String, MetaData
from time import time_ns,sleep
import numpy
import re
import threading
import _thread

class hl7fuzz():
    def __init__(self, cmdargs):
        self.bq = queue.Queue()
        self.fq = queue.Queue()
        self.cmdargs = cmdargs
        self.KillT = 0
        self.header = b'\x0b'
        self.tail = b'\x1c\x0d'
        self.badstrings = []
        with open('payloads/badstrings.txt','rb') as bads:
            for i,j in enumerate(bads.readlines()):
                if j[0] != 35:
                    self.badstrings.append(j.replace(b'\r\n',b''))
        self.badstrings = list(set(self.badstrings))
        self.badstrings.pop(0)
        self.sock = socket.socket()
        if self.cmdargs.server and self.cmdargs.serverport:
            self.hl7server()
        elif self.cmdargs.ip and self.cmdargs.port and self.cmdargs.server == 0:
            self.grab()
        else:
            print("[INFO] No HL7 remote server IP and port were set.. Exiting...!")

    def dbSRhl7(self):
        self.dbname = f"hl7sessionfuzz-{time_ns()}.db" if not self.cmdargs.server else f"hl7sessionfuzz-server-{time_ns()}.db"
        self.engine = create_engine(f'sqlite:///DB/{self.dbname}', echo=False)
        self.metadata = MetaData()
        fuzzsession = Table(
            'fuzzhl7', self.metadata,
            Column('sent', String),
            Column('recv', String), )
        self.metadata.create_all(self.engine)
        return self.engine, fuzzsession

    def grab(self):
        print("[-] Queuing baseline messages.")
        for message in listdir(self.cmdargs.folder):
            with open(f"{self.cmdargs.folder}/{message}", 'rb') as msg:
                self.bq.put(b''.join(msg.readlines()))
        print("\t-Done!")
        self.fuzz()

    def fuzz(self):
        print("[-] Connecting to server...")
        self.sender = threading.Thread(target=self.transmit)
        self.sender.start()
        print("[-] Creating & sending samples...")
        if self.cmdargs.target is not None:
            while not self.bq.empty():
                msg = self.bq.get()
                self.fmtstr = [b"%n" * randrange(1, self.cmdargs.max), b"%c" * randrange(1, self.cmdargs.max),
                               b"%s" * randrange(1, self.cmdargs.max), b"%p" * randrange(1, self.cmdargs.max),
                               b"%d" * randrange(1, self.cmdargs.max)]
                self.sqli = [i for i in open('payloads/sqli.txt', 'rb').readlines()]
                self.xss = [i for i in open('payloads/xss.txt', 'rb').readlines()]
                self.elements = [b'^' * randrange(1, self.cmdargs.max), b'\\' * randrange(1, self.cmdargs.max),
                                 b'&' * randrange(1, self.cmdargs.max), b'~' * randrange(1, self.cmdargs.max)]
                self.strats = [b"A" * randrange(1, self.cmdargs.max), urandom(randrange(1, self.cmdargs.max)),
                               choice(self.elements), choice(self.sqli), choice(self.xss),
                               choice(self.fmtstr), choice(self.badstrings)]
                for i in range(self.cmdargs.samples):
                    try:
                        msg1 = re.sub(self.cmdargs.target.encode() ,choice(self.strats),msg)
                    except:
                        msg1 = re.sub(self.cmdargs.target.encode(), b"\xcc"*10, msg)
                    self.fq.put(self.header + msg1 + self.tail)
        else:
            try:
                line, fld = self.cmdargs.change.split(',')
            except:
                line, fld = (-1,-1)
            while not self.bq.empty():
                x = self.bq.get()
                for q in range(self.cmdargs.samples):
                    msg = []
                    arr = numpy.array(x.split(b'\n'))
                    for i, j in enumerate(arr):
                        arr2 = j.split(b"|")
                        for k, l in enumerate(arr2):
                            try:
                                if self.cmdargs.allparts == 0 and i == 0:
                                    pass
                                else:
                                    arr2[randrange(1, len(arr2))] = choice(self.strats)
                                    if int(line) > -1:
                                        arr2[int(fld)] = randrange(11234532, 9999999999).to_bytes(10,'big')
                                    break
                            except:
                                pass
                        msg.append(b'|'.join(arr2))
                    if self.cmdargs.clientmode == 0:
                        self.fq.put(self.header + b''.join(msg) + self.tail)
                    else:
                        self.fq.put(b''.join(msg))
        while True:
            try:
                sleep(10)
                if self.sender.is_alive() == False:
                    print("[-]Fuzz session completed.\n\t-Sockets closed...\n\t-Exiting!")
                    self.sender.join()
                    exit()
            except KeyboardInterrupt:
                self.KillT = 1
                print("[-]Fuzz session completed.\n\t-Sockets closed...\n\t-Exiting!")
                self.sender.join()
                exit()

    def transmit(self):
        self.sock.connect((self.cmdargs.ip, self.cmdargs.port))
        print(f"[-]Connected to: {self.cmdargs.ip}:{self.cmdargs.port}")
        dbobj, _table = self.dbSRhl7()
        dbconnect = dbobj.connect()
        while True:
            if self.KillT == 1:
                break
            if self.fq.empty():
                break
            send_hl7 = self.fq.get()
            try:
                self.sock.send(send_hl7)
                recv_reply = self.sock.recv(5000)
            except Exception as e:
                self.sock.close()
                self.transmit()
                print(e)
                continue
            if self.cmdargs.noisey:
                print(f"{'-' * 40}Q-size[{self.fq.qsize()}]\nSent:\n{send_hl7}\n++++++++++++++++++++++\nRecevied:\n{recv_reply}")
            else:
                print(f"{'-' * 40}Q-size[{self.fq.qsize()}]\nRecevied:\n{recv_reply}")
            try:
                _insert = _table.insert().values(sent=send_hl7, recv=recv_reply)
                dbconnect.execute(_insert.execution_options(autocommit=True))
            except Exception as e:
                print("failed to insert into DB")

            sleep(self.cmdargs.delay)
        dbconnect.close()
        self.sock.close()
        print("Finishing up, Exiting in 10 seconds...")
        return

    def new_hl7_client(self,clientS, addr):
        dbobj, _table = self.dbSRhl7()
        dbconnect = dbobj.connect()
        while True:
            self.fmtstr = [b"%n" * randrange(1, self.cmdargs.max), b"%c" * randrange(1, self.cmdargs.max),
                           b"%s" * randrange(1, self.cmdargs.max), b"%p" * randrange(1, self.cmdargs.max),
                           b"%d" * randrange(1, self.cmdargs.max)]
            self.sqli = [i for i in open('payloads/sqli.txt', 'rb').readlines()]
            self.xss = [i for i in open('payloads/xss.txt', 'rb').readlines()]
            self.elements = [b'^' * randrange(1, self.cmdargs.max), b'\\' * randrange(1, self.cmdargs.max),
                             b'&' * randrange(1, self.cmdargs.max), b'~' * randrange(1, self.cmdargs.max)]
            self.strats = [b"A" * randrange(1, self.cmdargs.max), urandom(randrange(1, self.cmdargs.max)),
                           choice(self.elements), choice(self.sqli), choice(self.xss),
                           choice(self.fmtstr), choice(self.badstrings)]
            try:
                try:
                    msg = clientS.recv(1024)
                    print(addr, ' >> ', msg)
                except:
                    break
                if not msg:
                    break
                send_hl7 = self.header+choice(self.strats)+self.tail if self.cmdargs.servermode == 0 else b"\x01"+choice(self.strats)
                print(f"\n\n{send_hl7}\n\n---------------------------")
                clientS.send(send_hl7)
                try:
                    _insert = _table.insert().values(sent=send_hl7, recv=msg)
                    dbconnect.execute(_insert.execution_options(autocommit=True))
                except Exception as e:
                    print("failed to insert into DB")
            except KeyboardInterrupt:
                break
        clientS.close()

    def hl7server(self):
        s = socket.socket()
        s.bind(('',self.cmdargs.serverport))
        s.listen(5)
        while True:
            try:
                c, addr = s.accept()
                _thread.start_new_thread(self.new_hl7_client, (c, addr))
            except KeyboardInterrupt:
                break
        s.close()
        exit()

if __name__ == '__main__':
    cmdopts = argparse.ArgumentParser(description='An extremely dumb HL7 message fuzzer.')
    cmdopts.add_argument("-f", "--folder", help="Folder containing a hl7 messages as text files.", default="messages")
    cmdopts.add_argument("-d", "--ip", help="Destination Ip address.", required=False)
    cmdopts.add_argument("-p", "--port", help="Destination port.", required=False, type=int)
    cmdopts.add_argument("-s", "--samples", help="Number of samples to generate.", required=False, type=int, default=3000)
    cmdopts.add_argument("-c", "--change", help="Fields to always change.", required=False)
    cmdopts.add_argument("-m", "--max",  type=int, help="Max length of fuzz generated string.", required=False, default=10)
    cmdopts.add_argument("-t", "--target", help="Will change from random fuzz payload insertion into messages to defined areas that you selected from a message which are defined by a delimiter of your choice.", required=False)
    cmdopts.add_argument("-a", "--allparts", help="This will allow you to parse the first segment of an HL7 message instead of skipping the first segment.", required=False, type=int ,default=0)
    cmdopts.add_argument("-v", "--noisey",help="to show both sent and received messages set this to 1",required=False, type=int, default=0)
    cmdopts.add_argument("-x", "--delay", help="delay interval between sending packets. Set this to 0 for DoS attack/stress testing.", required=False,type=int, default=1)
    cmdopts.add_argument("-b","--server",help="Setup a server to respond with malicious HL7 messages.",required=False , default=0)
    cmdopts.add_argument("-bp", "--serverport", help="Setup the server port respond with malicious HL7 messages.",required=False, type=int)
    cmdopts.add_argument("-bm", "--servermode", help="Setup the server to respond with malicious (generic or HL7) messages.", required=False, type=int)
    cmdopts.add_argument("-cm", "--clientmode", help="Setup the client to respond with malicious (generic or HL7) messages.", required=False, type=int)
    cmdargs = cmdopts.parse_args()
    hl7f = hl7fuzz(cmdargs)
