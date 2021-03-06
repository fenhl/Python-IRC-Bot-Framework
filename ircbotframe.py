import ipaddress
import re
import socket
import ssl
import threading
import time
import sched
import queue


class ircOutputBuffer:
    # This class provides buffered and unbuffered sending to a socket
    def __init__(self, irc):
        self.irc = irc
        self.queue = queue.Queue()

    def sendBuffered(self, string):
        # Sends the given string after the rest of the messages in the buffer.
        self.queue.put_nowait(string)
        return True

    def sendFromQueue(self):
        # Send the oldest message in the buffer if there is one
        try:
            string = self.queue.get_nowait()
            result = self.sendImmediately(string)
            self.queue.task_done()
            return result
        except queue.Empty:
            return True

    def sendImmediately(self, string):
        # Sends the given string without buffering.
        try:
            self.irc.send((string + "\r\n").encode("utf-8"))
            return True
        except socket.error as msg:
            print("Output error", msg)
            print("Was sending \"" + string + "\"")
            return False


class ircInputBuffer:
    # Keeps a record of the last line fragment received by the socket which is usually not a complete line.
    # It is prepended onto the next block of data to make a complete line.
    def __init__(self, irc):
        self.buffer = ""
        self.irc = irc
        self.lines = []

    def __recv(self):
        # Receives new data from the socket and splits it into lines.
        try:
            data = self.buffer + self.irc.recv(4096).decode("utf-8")
        except UnicodeDecodeError:
            data = ''
        self.lines += data.split("\r\n")
        # Last (incomplete) line is kept for buffer purposes.
        self.buffer = self.lines[-1]
        self.lines = self.lines[:-1]

    def getLine(self):
        # Returns the next line of IRC received by the socket or None.
        # This should already be in the standard string format.
        # If no lines are buffered, this blocks until a line is received
        # or we reach the socket timeout. When the timeout is
        # reached, the function returns None.

        while len(self.lines) == 0:
            try:
                self.__recv()
            except socket.timeout:
                return None

        line = self.lines[0]
        self.lines = self.lines[1:]
        return line


class ircBot(threading.Thread):
    def __init__(self, network, port, name, description, password=None, ssl=False, ip_ver=None):
        threading.Thread.__init__(self)
        self.keepGoing = True
        self.name = name
        self.desc = description
        self.password = password
        self.network = network
        self.port = port
        self.ssl = ssl
        self.identifyNickCommands = []
        self.identifyLock = False
        self.binds = {}
        self.debug = False
        self.default_log_length = 200
        self.log_own_messages = True
        self.channel_data = {}
        self.irc = None
        self.outBuf = None
        self.inBuf = None
        self.connected = False
        self.connect_timeout = 30
        self.reconnect_interval = 30
        self.ping_timeout = 10
        self.ping_interval = 60

        self.bind("PONG", self.__handlePong)
        self.__unansweredPing = False
        self.__sched = sched.scheduler()

        if ip_ver == 4:
            self.socket_family = socket.AF_INET
        elif ip_ver == 6:
            self.socket_family = socket.AF_INET6
        elif ip_ver is None:
            try:
                address = ipaddress.ip_address(network)
            except:
                for family, _, _, _, _ in socket.getaddrinfo(network, port, proto=socket.IPPROTO_TCP):
                    if family == socket.AF_INET6:
                        self.socket_family = socket.AF_INET6
                        break
                else:
                    self.socket_family = socket.AF_INET
            else:
                self.socket_family = {
                    4: socket.AF_INET,
                    6: socket.AF_INET6
                }[address.version]
        else:
            raise ValueError('Invalid IP version: {!r}'.format(ip_ver))

    # PRIVATE FUNCTIONS
    def __identAccept(self, nick):
        """ Executes all the callbacks that have been approved for this nick
    	"""
        i = 0
        while i < len(self.identifyNickCommands):
            (nickName, accept, acceptParams, reject, rejectParams) = self.identifyNickCommands[i]
            if nick == nickName:
                accept(*acceptParams)
                self.identifyNickCommands.pop(i)
            else:
                i += 1

    def __identReject(self, nick):
        # Calls the given "denied" callback for all functions called by that nick.
        i = 0
        while i < len(self.identifyNickCommands):
            (nickName, accept, acceptParams, reject, rejectParams) = self.identifyNickCommands[i]
            if nick == nickName:
                reject(*rejectParams)
                self.identifyNickCommands.pop(i)
            else:
                i += 1

    def __callBind(self, msgtype, sender, headers, message):
        # Calls the function associated with the given msgtype.
        callback = self.binds.get(msgtype)
        if callback:
            callback(sender, headers, message)

    def __processLine(self, line):
        # If a message comes from another user, it will have an @ symbol
        if "@" in line:
            # Location of the @ symbol in the line (proceeds sender's domain)
            at = line.find("@")
            # Location of the first gap, this immediately follows the sender's domain
            gap = line[at:].find(" ") + at + 1
            lastColon = line[gap+1:].find(":") + 2 + gap
        else:
            lastColon = line[1:].find(":") + 1

        # Does most of the parsing of the line received from the IRC network.
        # if there is no message to the line. ie. only one colon at the start of line
        if ":" not in line[1:]:
            headers = line[1:].strip().split(" ")
            message = ""
        else:
            # Split everything up to the lastColon (ie. the headers)
            headers = line[1:lastColon-1].strip().split(" ")
            message = line[lastColon:]

        sender = headers[0]
        if len(headers) < 2:
            self.__debugPrint("Unhelpful number of messages in message: \"" + line + "\"")
        else:
            if "!" in sender:
                cut = headers[0].find('!')
                if cut != -1:
                    sender = sender[:cut]
                msgtype = headers[1]
                if msgtype == 'PRIVMSG':
                    if message.startswith('\001ACTION ') and message.endswith('\001'):
                        msgtype = 'ACTION'
                        message = message[8:-1]
                    if headers[2].startswith('#'):
                        self.log(headers[2], msgtype, sender, headers[2:], message) # log PRIVMSG and ACTION only for now
            else:
                msgtype = headers[1]
                self.__debugPrint('[' + msgtype + '] ' + message)
                if msgtype == '376':
                    self.connected = True
                if msgtype in ['307', '330'] and len(headers) >= 4:
                    self.__identAccept(headers[3])
                if msgtype == '318' and len(headers) >= 4:
                    self.__identReject(headers[3])
                    #identifies the next user in the nick commands list
                    if len(self.identifyNickCommands) == 0:
                        self.identifyLock = False
                    else:
                        self.outBuf.sendBuffered("WHOIS " + self.identifyNickCommands[0][0])
            self.__callBind(msgtype, sender, headers[2:], message)

    def __debugPrint(self, s):
        if self.debug:
            print(s)

    def __periodicSend(self):
        if not self.irc:
            return

        if not self.outBuf.sendFromQueue():
            self.close()
            return

        # Delays consecutive messages by at least 1 second.
        # This prevents the bot spamming the IRC server.
        self.__sched.enter(1, priority=10, action=self.__periodicSend)

    def __periodicRecv(self):
        if not self.irc:
            return

        try:
            line = self.inBuf.getLine()
        except socket.error as msg:
            self.__debugPrint("Input error", msg)
            self.close()
            return

        if line is not None:
            if line.startswith("PING"):
                if not self.outBuf.sendImmediately("PONG " + line.split()[1]):
                    self.close()
                    return
            else:
                self.__processLine(line)

        # next recv should be directly but with verly low priority
        self.__sched.enter(0.01, priority=1, action=self.__periodicRecv)

    def __periodicPing(self):
        self.ping()
        self.__sched.enter(self.ping_interval, 1, self.__periodicPing)

    def __handlePong(self, sender, headers, message):
        self.__unansweredPing = False

    def __handlePingTimeout(self):
        if self.__unansweredPing:
            self.__debugPrint("Ping timeout reached. Killing the connection.")
            self.close()

    def ping(self):
        if self.__unansweredPing:
            return

        self.outBuf.sendImmediately('PING %s' % self.network)
        self.__unansweredPing = True
        self.__sched.enter(self.ping_timeout, 1, self.__handlePingTimeout)

    def log(self, channel, msgtype, sender, headers, message):
        if channel in self.channel_data:
            self.channel_data[channel]['log'].append((msgtype, sender, headers, message))
            if len(self.channel_data[channel]['log']) > self.channel_data[channel]['log_length']:
                self.channel_data[channel]['log'] = self.channel_data[channel]['log'][-self.channel_data[channel]['log_length']:] # trim log to log length if necessary

    # PUBLIC FUNCTIONS
    def ban(self, banMask, channel, reason):
        # only bans, no kick.
        self.__debugPrint("Banning " + banMask + "...")
        self.send("MODE +b " + channel + " " + banMask)
        # TODO get nick
        #self.kick(nick, channel, reason)

    def bind(self, msgtype, callback):
        self.binds[msgtype] = callback

    def __handleConnectingTimeout(self):
        if not self.connected:
            self.close()

    def connect(self):
        self.__debugPrint("Connecting...")
        self.irc = socket.socket(self.socket_family, socket.SOCK_STREAM)
        self.irc.settimeout(self.connect_timeout)

        if self.ssl:
            self.irc = ssl.wrap_socket(self.irc)

        try:
            self.irc.connect((self.network, self.port))
        except socket.error as msg:
            self.__debugPrint("Connection failed: %s" % msg)
            self.close()
            return False

        self.irc.settimeout(1.0)

        self.inBuf = ircInputBuffer(self.irc)
        self.outBuf = ircOutputBuffer(self.irc)

        if self.password is not None:
            self.outBuf.sendBuffered("PASS " + self.password)

        self.outBuf.sendBuffered("NICK " + self.name)
        self.outBuf.sendBuffered("USER " + self.name + " 0 * :" + self.desc)

        self.connected = False

        self.__periodicSend()
        self.__periodicRecv()
        self.__sched.enter(self.connect_timeout, priority=20, action=self.__handleConnectingTimeout)

        while True:
            if self.connected:
                self.__debugPrint("Connection was successful!")
                return True

            if self.irc is None:
                return False

            self.__sched.run(blocking=False)

    def debugging(self, state):
        self.debug = state

    def close(self):
        self.outBuf = None
        self.inBuf = None
        self.irc.close()
        self.irc = None
        self.connected = False

    def disconnect(self, qMessage):
        self.__debugPrint("Disconnecting...")
        # TODO make the following block until the message is sent
        self.send("QUIT :" + qMessage)
        self.close()

    def identify(self, nick, approvedFunc, approvedParams, deniedFunc, deniedParams):
        self.__debugPrint("Verifying " + nick + "...")
        self.identifyNickCommands += [(nick, approvedFunc, approvedParams, deniedFunc, deniedParams)]
        # TODO this doesn't seem right
        if not self.identifyLock:
            self.send("WHOIS " + nick)
            self.identifyLock = True

    def joinchan(self, channel):
        self.__debugPrint("Joining " + channel + "...")
        self.channel_data[channel] = {
            'log': [],
            'log_length': self.default_log_length
        }
        self.send("JOIN " + channel)

    def kick(self, nick, channel, reason):
        self.__debugPrint("Kicking " + nick + "...")
        self.send("KICK " + channel + " " + nick + " :" + reason)

    def reconnect(self, gracefully=True):
        if gracefully:
            self.disconnect("Reconnecting")
        else:
            self.close()

        self.__debugPrint("Pausing before reconnecting...")
        time.sleep(self.reconnect_interval)
        self.connect()

    def run(self):
        self.__debugPrint("Bot is now running.")
        self.connect()

        self.__periodicPing()

        while self.keepGoing:
            if self.irc is None:
                self.__debugPrint("Pausing before reconnecting...")
                time.sleep(self.reconnect_interval)
                self.connect()
                continue

            self.__sched.run(blocking=False)

        self.disconnect()

    def say(self, recipient, message):
        if self.log_own_messages:
            self.log(recipient, 'PRIVMSG', self.name, [recipient], message)
        self.send("PRIVMSG " + recipient + " :" + message)

    def send(self, string):
        if not self.connected:
            self.__debugPrint("WARNING: you are trying to send without being connected - \"", string, "\"")
            return

        self.outBuf.sendBuffered(string)

    def stop(self):
        self.keepGoing = False

    def topic(self, channel, message):
        self.send('TOPIC ' + channel + ' :' + message)

    def unban(self, banMask, channel):
        self.__debugPrint('Unbanning ' + banMask + '...')
        self.send('MODE -b ' + channel + ' ' + banMask)
