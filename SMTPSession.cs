using System;
using System.Diagnostics;
using System.Threading;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace FakeSMTP
{
    class SMTPsession
    {
        #region "privatedata"
        // chars allowed in HELO/EHLO string
        const string        HELO_CHARS      = "[]0123456789.-abcdefghijklmnopqrstuvwxyz_";

        // for verbose logging
        const string        DIR_TX = "SND";
        const string        DIR_RX = "RCV";

        // misc SMTP messages
        const string        BANNER_STR      = "220 {0} MailRecv 0.1.2-b4; {1}";
        const string        TEMPFAIL_MSG    = "421 Service temporarily unavailable, closing transmission channel.";
        const string        DNSBL_MSG       = "442 Connection from {0} temporarily refused, host listed by {1}";
        const string        TIMEOUT_MSG     = "442 Connection timed out.";
        const string        ETALKER_MSG     = "554 Misbehaved SMTP session (EarlyTalker)";

        // SMTP command strings
        string[] cmdList = { "\r\n",
                             "HELO",
                             "EHLO",
                             "MAIL FROM:",
                             "RCPT TO:",
                             "DATA",
                             "RSET",
                             "QUIT",
                             "VRFY",
                             "EXPN",
                             "HELP",
                             "NOOP"
                        };


        // command ID mapping codes (must match the list above)
        enum cmdID
        {
            invalid,
            helo,
            ehlo,
            mailFrom,
            rcptTo,
            data,
            rset,
            quit,
            vrfy,
            expn,
            help,
            noop
        }

        // network/system
        private bool                _initOk = false;                    // true = initialized
        private string              _hostName = null;                   // local host name for banner
        private TcpClient           _client;                            // remote client
        private NetworkStream       _stream;                            // network stream for I/O
        private StreamReader        _reader;                            // network reader
        private StreamWriter        _writer;                            // network writer
        private long                _sessCount = 0;                     // current session count
        private string              _sessionID = null;                  // ID for this session
        private long                _lastMsgID = -1;                    // last logged message #
        private bool                _timedOut = false;                  // true = the connection timed out

        // local domains/mailboxes
        private List<string> _mailDomains = new List<string>();         // list of locally handled domains
        private List<string> _mailBoxes = new List<string>();           // list of locally handled mailboxes

        // session
        private DateTime            _startDate = DateTime.UtcNow;       // session start datetime
        private string              _clientIP = null;                   // remote IP
        private string              _dnsListType = null;                // type of listing
        private string              _dnsListName = null;                // name of DNS list flagging the IP
        private string              _dnsListValue = null;               // value returned by the DNS list
        private cmdID               _lastCmd = cmdID.invalid;           // last cmd issued
        private string              _heloStr = null;                    // HELO/EHLO string
        private string              _mailFrom = null;                   // MAIL FROM address
        private List<string>        _rcptTo = new List<string>();       // RCPT TO list
        private long                _msgCount = 0;                      // # of messages for this session
        private string              _msgFile = null;                    // message file storage
        private bool                _earlyTalker = false;               // true the client is a "early talker"
        private int                 _noopCount = 0;                     // # of NOOP issued
        private int                 _errCount = 0;                      // # of errors
        private int                 _vrfyCount = 0;                     // # of VRFY/EXPN

        // workareas
        private string              _mailBox = null;                    // mailbox part of a mail address
        private string              _mailDom = null;                    // domain part of a mail address
        #endregion

        #region "instance"
        // init
        public SMTPsession(TcpClient client)
        {
            try
            {
                this._sessCount = AppGlobals.addSession();
                this._sessionID = AppGlobals.sessionID();
                this._hostName = AppGlobals.hostName;

                if (null != AppGlobals.LocalDomains)
                    this._mailDomains = AppGlobals.LocalDomains;
                if (null != AppGlobals.LocalMailBoxes)
                    this._mailBoxes = AppGlobals.LocalMailBoxes;

                this._client = client;
                this._clientIP = this._client.Client.RemoteEndPoint.ToString();
                int i = this._clientIP.IndexOf(':');
                if (-1 != i) this._clientIP = this._clientIP.Substring(0, i);
                this._client.ReceiveTimeout = AppGlobals.receiveTimeout;

                this._stream = this._client.GetStream();
                this._reader = new StreamReader(this._stream);
                this._writer = new StreamWriter(this._stream);
                this._writer.NewLine = "\r\n";
                this._writer.AutoFlush = true;

                AppGlobals.writeConsole("client {0} connected, sess={1}, ID={2}.", this._clientIP, this._sessCount, this._sessionID);
                this._initOk = true;
            }
            catch (Exception ex)
            {
                AppGlobals.writeConsole("SMTPsession::Exception: " + ex.Message);
                closeSession();
            }
        }
        #endregion

        #region "methods"
        public void handleSession()
        {
            string cmdLine = "?";
            string response = cmd_ok(null);
            cmdID  currCmd = cmdID.invalid;
            bool   connOk = true;

            if (false == this._initOk)
            {
                closeSession();
                return;
            }

            // sessions limit reached, reject session
            if (this._sessCount > AppGlobals.maxSessions)
            {
                if (connOk) sendLine(TEMPFAIL_MSG);
                closeSession();
                return;
            }

            // if the remote IP isn't a private one
            if (!isPrivateIP(this._clientIP))
            {
                // checks the incoming IP against whitelists, if listed skip blacklist checks
                bool isDnsListed = isListed(this._clientIP, AppGlobals.whiteLists, "white");
                if (!isDnsListed)
                {
                    // check the IP against blacklists
                    isDnsListed = isListed(this._clientIP, AppGlobals.blackLists, "black");
                    if ((isDnsListed) && (!AppGlobals.storeData))
                    {
                        // if blacklisted and NOT storing messages
                        sendLine(string.Format(DNSBL_MSG, this._clientIP, this._dnsListName));
                        closeSession();
                        return;
                    }
                }
            }

            // add a short delay before banner and check for early talker
            // see http://wiki.asrg.sp.am/wiki/Early_talker_detection
            sleepDown(AppGlobals.bannerDelay);
            this._earlyTalker = isEarlyTalker();
            if (this._earlyTalker)
            {
                sendLine(ETALKER_MSG);
                closeSession();
                return;
            }

            // all ok, send out our banner            
            connOk = sendLine(cmd_banner(null));
            while ((null != cmdLine) && (true == connOk))
            {
                if (this._lastCmd == cmdID.data)
                {
                    string mailMsg = recvData();
                    if (this._timedOut)
                    {
                        // got a receive timeout during the DATA phase
                        if (connOk) sendLine(TIMEOUT_MSG);
                        closeSession();
                        return;
                    }
                    response = cmd_dot(null);
                    if (String.IsNullOrEmpty(mailMsg))
                        response = "422 Recipient mailbox exceeded quota limit.";
                    else
                    {
                        storeMailMsg(mailMsg);
                        if (AppGlobals.doTempFail) 
                        {
                            // emit a tempfail AFTER storing the mail DATA
                            if (connOk) sendLine(TEMPFAIL_MSG);
                            closeSession();
                            return;
                        }
                    }
                    resetSession();
                }
                else
                {
                    // read an SMTP command line and deal with the command
                    cmdLine = recvLine();
                    if (null != cmdLine)
                    {
                        logCmdAndResp(DIR_RX, cmdLine);
                        currCmd = getCommandID(cmdLine);
                        switch (currCmd)
                        {
                            case cmdID.helo:            // HELO
                                response = cmd_helo(cmdLine);
                                break;
                            case cmdID.ehlo:            // EHLO
                                response = cmd_helo(cmdLine);
                                break;
                            case cmdID.mailFrom:        // MAIL FROM:
                                response = cmd_mail(cmdLine);
                                break;
                            case cmdID.rcptTo:          // RCPT TO:
                                response = cmd_rcpt(cmdLine);
                                break;
                            case cmdID.data:            // DATA
                                if ((AppGlobals.doTempFail) && (!AppGlobals.storeData))
                                {
                                    // emit a tempfail upon receiving the DATA command
                                    response = TEMPFAIL_MSG;
                                    cmdLine = null;
                                    this._lastCmd = currCmd = cmdID.quit;
                                }
                                else
                                    response = cmd_data(cmdLine);
                                break;
                            case cmdID.rset:            // RSET
                                response = cmd_rset(cmdLine);
                                break;
                            case cmdID.quit:            // QUIT
                                response = cmd_quit(cmdLine);
                                cmdLine = null; // force closing
                                break;
                            case cmdID.vrfy:            // VRFY
                                response = cmd_vrfy(cmdLine);
                                break;
                            case cmdID.expn:            // EXPN
                                response = cmd_vrfy(cmdLine);
                                break;
                            case cmdID.help:            // HELP
                                response = cmd_help(cmdLine);
                                break;
                            case cmdID.noop:            // NOOP
                                response = cmd_noop(cmdLine);
                                break;
                            default:                    // unkown/unsupported
                                response = cmd_unknown(cmdLine);
                                break;
                        }
                    }
                    else
                    {
                        // the read timed out (or we got an error), emit a message and drop the connection
                        response = TIMEOUT_MSG;
                        currCmd = cmdID.quit;
                    }
                }

                // send response
                if ((this._errCount > 0) && (cmdID.quit != currCmd))
                {
                    // tarpit a bad client, time increases with error count
                    sleepDown(AppGlobals.errorDelay * this._errCount);
                }
                else
                {
                    // add a short delay
                    sleepDown(25);
                }

                // checks for early talkers
                this._earlyTalker = isEarlyTalker();

                // send out the response
                connOk = sendLine(response);

                // check/enforce hard limits (errors, vrfy ...)
                if ((cmdID.quit != currCmd) && (connOk))
                {
                    string errMsg = null;
                    if (this._msgCount > AppGlobals.maxMessages)
                    {
                        // above max # of message in a single session
                        errMsg = "451 Session messages count exceeded";
                    } 
                    else if (this._errCount > AppGlobals.maxSmtpErr)
                    {
                        // too many errors
                        errMsg = "550 Max errors exceeded";
                    }
                    else if (this._vrfyCount > AppGlobals.maxSmtpVrfy)
                    {
                        // tried to VRFY/EXPN too many addresses
                        errMsg = "451 Max recipient verification exceeded";
                    }
                    else if (this._noopCount > AppGlobals.maxSmtpNoop)
                    {
                        // entered too many NOOP commands
                        errMsg = "451 Max NOOP count exceeded";
                    }
                    else if (this._rcptTo.Count > AppGlobals.maxSmtpRcpt)
                    {
                        // too many recipients for a single message
                        errMsg = "452 Too many recipients";
                    }
                    else if (this._earlyTalker)
                    {
                        // early talker
                        errMsg = ETALKER_MSG;
                    }
                    if (null != errMsg)
                    {
                        if (connOk) connOk = sendLine(errMsg);
                        cmdLine = null; // force closing
                    }
                }

                // check if connection Ok
                if (connOk) connOk = this._client.Connected;
            } // while null...

            // close/reset this session
            closeSession();
        }
        #endregion

        #region "privatecode"
        // retrieves the command ID from command line args
        private cmdID getCommandID(string cmdLine)
        {
            cmdID id = cmdID.invalid;
            string tmpBuff = cmdLine.ToUpperInvariant();

            for (int i = 0; i < this.cmdList.Length; i++)
            {
                if (tmpBuff.StartsWith(this.cmdList[i]))
                {
                    id = (cmdID)i;
                    break;
                }
            }
            return id;
        }

        // resets the internal session values
        private void resetSession()
        {
            logSession(); // logs the session/message to file (if data available) 
            this._mailFrom = null;
            this._rcptTo = new List<string>();
            this._msgFile = null;
            this._noopCount = 0;
            this._errCount = 0;
            this._vrfyCount = 0;
        }
        
        // closes the socket, terminates the session
        private void closeSession()
        {
            if (null != this._client)
            {
                if (this._client.Connected)
                    sleepDown(25);
                try { this._client.Close(); this._client = null;  }
                catch { }
                if (!string.IsNullOrEmpty(this._clientIP))
                    AppGlobals.writeConsole("client {0} disconnected, sess={1}, ID={2}.", this._clientIP, this._sessCount, this._sessionID);
            }
            this._initOk = false;
            long sesscount = AppGlobals.removeSession();
            resetSession();
        }

        // banner string (not a real command)
        private string cmd_banner(string cmdLine)
        {
            string banner = String.Format(BANNER_STR, this._hostName, DateTime.UtcNow.ToString("R"));
            return banner;
        }

        // HELO/EHLO
        private string cmd_helo(string cmdLine)
        {
            cmdID id = getCommandID(cmdLine);
            List<string> parts = parseCmdLine(id, cmdLine);
            if (2 != parts.Count)
            {
                this._errCount++;
                return String.Format("501 {0} needs argument", parts[0]);
            }
            if (!string.IsNullOrEmpty(this._heloStr))
            {
                this._errCount++;
                return string.Format("503 you already sent {0} ...", parts[0]);
            }
            if (!checkHelo(parts[1]))
            {
                this._errCount++;
                return String.Format("501 Invalid {0}", parts[0]);
            }
            if (parts[1].ToLower().Equals("localhost") || 
                parts[1].ToLower().Equals(AppGlobals.hostName) ||
                parts[1].StartsWith("[127.") ||
                parts[1].Equals("[" + AppGlobals.listenAddress + "]")
               )
            {
                this._errCount++;
                return String.Format("501 spoofed {0}", parts[0]);
            }

            this._heloStr = parts[1];
            this._lastCmd = id;
            if (id == cmdID.helo)
                return String.Format("250 Hello {0} ([{1}]), nice to meet you.", parts[1], this._clientIP);
            return String.Format("250 Hello {0} ([{1}]), nice to meet you.\r\n250-HELP\r\n250-VRFY\r\n250-EXPN\r\n250 NOOP", parts[1], this._clientIP);
        }

        // MAIL FROM:
        private string cmd_mail(string cmdLine)
        {
            if (string.IsNullOrEmpty(this._heloStr))
            {
                this._errCount++;
                return "503 HELO/EHLO Command not issued";
            }
            if (!string.IsNullOrEmpty(this._mailFrom))
            {
                this._errCount++;
                return "503 Nested MAIL command";
            }
            List<string> parts = parseCmdLine(cmdID.mailFrom, cmdLine);
            if (2 != parts.Count)
            {
                this._errCount++;
                return String.Format("501 {0} needs argument", parts[0]);
            }
            if (!checkMailAddr(parts[1]))
            {
                this._errCount++;
                return String.Format("553 Invalid address {0}", parts[1]);
            }
            this._mailFrom = parts[1];
            this._lastCmd = cmdID.mailFrom;
            return string.Format("250 {0}... Sender ok", parts[1]);
        }

        // RCPT TO:
        private string cmd_rcpt(string cmdLine)
        {
            if (string.IsNullOrEmpty(this._mailFrom))
            {
                this._errCount++;
                return "503 Need MAIL before RCPT";
            }
            List<string> parts = parseCmdLine(cmdID.rcptTo, cmdLine);
            if (2 != parts.Count)
            {
                this._errCount++;
                return String.Format("501 {0} needs argument", parts[0]);
            }
            if (!checkMailAddr(parts[1]))
            {
                this._errCount++;
                return String.Format("553 Invalid address {0}", parts[1]);
            }

            if (!isLocalDomain(this._mailDom))
            {
                // relaying not allowed...
                this._errCount++;
                return "530 Relaying not allowed for policy reasons";
            }
            else if (!isLocalBox(this._mailBox, this._mailDom))
            {
                // unkown/invalid recipient
                this._errCount++;
                return String.Format("553 Unknown email address {0}", parts[1]);
            }

            this._rcptTo.Add(parts[1]);
            this._lastCmd = cmdID.rcptTo;
            return string.Format("250 {0}... Recipient ok", parts[1]);
        }

        // DATA
        private string cmd_data(string cmdLine)
        {
            if (this._rcptTo.Count < 1)
            {
                this._errCount++;
                return "471 Bad or missing RCPT command";
            }
            this._lastCmd = cmdID.data;
            return "354 Start mail input; end with <CRLF>.<CRLF>";
        }

        // end of DATA (dot)
        private string cmd_dot(string cmdLine)
        {
            this._lastCmd = cmdID.noop;
            return "250 Queued mail for delivery";
        }

        // RSET
        private string cmd_rset(string cmdLine)
        {
            resetSession();
            this._lastCmd = cmdID.rset;
            return "250 Reset Ok";
        }

        // QUIT
        private string cmd_quit(string cmdLine)
        {
            this._lastCmd = cmdID.quit;
            return "221 Closing connection.";
        }

        // VRFY/EXPN
        private string cmd_vrfy(string cmdLine)
        {
            cmdID id = getCommandID(cmdLine);
            this._vrfyCount++;
            List<string> parts = parseCmdLine(id, cmdLine);
            if (2 != parts.Count)
            {
                this._errCount++;
                return String.Format("501 {0} needs argument", parts[0]);
            }
            if (!checkMailAddr(parts[1]))
            {
                this._errCount++;
                return String.Format("553 Invalid address {0}", parts[1]);
            }
            this._lastCmd = id;
            if (id == cmdID.vrfy)
                return "252 Cannot VRFY user; try RCPT to attempt delivery (or try finger)";
            return String.Format("250 {0}", parts[1]);
        }

        // NOOP
        private string cmd_noop(string cmdLine)
        {
            this._noopCount++;
            List<string> parts = parseCmdLine(cmdID.noop, cmdLine);
            if (parts.Count > 1)
            {
                // NOOP may have args...
                return string.Format("250 ({0}) OK", parts[1]);
            }
            return "250 OK";
        }

        // HELP
        private string cmd_help(string cmdLine)
        {
            // dynamically build the help string for our commands list
            string cmd = null;
            int pos = -1;
            string buff = "211";
            for (int i = 1; i < cmdList.Length; i++)
            {
                cmd = cmdList[i];
                pos = cmd.IndexOf(' ');
                if (-1 != pos) cmd = cmd.Substring(0, pos);
                buff = buff + " " + cmd;
            }
            return buff;
        }

        // misc command, fake support
        private string cmd_ok(string cmdLine)
        {
            if (!string.IsNullOrEmpty(cmdLine))
            {
                List<string> parts = parseCmdLine(cmdID.noop, cmdLine);
                if (parts.Count > 1)
                {
                    return string.Format("250 {0} OK", parts[0]);
                }
            }
            return "250 Ok";
        }

        // unknown/unsupported
        private string cmd_unknown(string cmdLine)
        {
            this._errCount++;
            this._lastCmd = cmdID.invalid;
            if (string.IsNullOrEmpty(cmdLine))
                return "500 Command unrecognized";
            else
                return string.Format("500 Command unrecognized ({0})", cmdLine);
        }

        // coarse checks on the HELO string (todo: replace with regexp)
        private bool checkHelo(string heloStr)
        {
            // can't be empty
            if (String.IsNullOrEmpty(heloStr)) return false;

            // can't start with a dot or hypen
            char[] heloChars = heloStr.ToLowerInvariant().ToCharArray();
            if ((heloChars[0] == '.') || (heloChars[0] == '-')) return false;

            // must contain at least a dot
            if (!heloStr.Contains('.')) return false;

            // can only contain valid chars
            for (int i = 0; i < heloChars.Length; i++)
                if (!HELO_CHARS.Contains(heloChars[i])) return false;

            // if starts with "[" the bracket must match and the
            // enclosed string must be a valid IP address (and
            // match the connecting IP address)
            if ('[' == heloChars[0])
            {
                if (']' != heloChars[heloChars.Length - 1]) return false;
                string ipAddr = heloStr.Replace('[', ' ');
                ipAddr = ipAddr.Replace(']', ' ').Trim();
                IPAddress ip;
                //if (!ipAddr.Equals(this._clientIP)) return false;
                if (!IPAddress.TryParse(ipAddr, out ip)) return false;
                //if (isPrivateIP(ipAddr)) return false;
            }
            else
            {
                // run a check on the domain
                bool result = checkMailAddr("postmaster@" + heloStr);
                if (false == result) return false;
            }

            return true;
        }

        // coarse checks on the email address (todo: replace with regexp)
        private bool checkMailAddr(string mailAddr)
        {
            // init
            this._mailBox = this._mailDom = null;
            string email = cleanupString(mailAddr).ToLowerInvariant();

            // shouldn't be empy and must contain at least a @ and a dot
            if (string.IsNullOrEmpty(email)) return false;
            if (!email.Contains('@')) return false;
            if (!email.Contains('.')) return false;

            // if starting with a "<" must end with a ">"
            char[] chars = email.ToCharArray();
            if ('<' == chars[0])
            {
                if ('>' != chars[email.Length - 1]) return false;
                email = email.Replace('<', ' ');
                email = email.Replace('>', ' ');
                email = cleanupString(email);
                if (email.Length < 1) return false;
            }

            // can't contain a space
            if (email.Contains(' ')) return false;

            // the "@" must be unique
            string[] parts = email.Split('@');
            if (2 != parts.Length) return false;

            // cleanup and check parts
            for (int p = 0; p < parts.Length; p++)
            {
                parts[p] = cleanupString(parts[p]);
                if (string.IsNullOrEmpty(parts[p])) return false;
            }

            // formally checks domain (and TLD)
            if (!parts[1].Contains('.')) return false;
            if (parts[1].StartsWith(".")) return false;
            if (parts[1].EndsWith(".")) return false;
            string[] domain = parts[1].Split('.');
            if (domain.Length < 2) return false;
            for (int p = 0; p < domain.Length; p++)
            {
                if (string.IsNullOrEmpty(domain[p])) return false;
                if (domain[p].StartsWith("-")) return false;
            }
            string TLD = domain[domain.Length - 1];
            if (TLD.Length < 2) return false;

            // store mailbox and domain
            this._mailBox = parts[0];
            this._mailDom = parts[1];

            return true;
        }

        // checks if a domain is local
        private bool isLocalDomain(string maildomain)
        {
            // if no domain, treat as "all domains are ok"
            if (this._mailDomains.Count < 1) return true;
            for (int d = 0; d < this._mailDomains.Count; d++)
            {
                if (maildomain.Equals(this._mailDomains[d], StringComparison.InvariantCultureIgnoreCase))
                    return true;
            }
            return false;
        }
        
        // checks if a mailbox is local / exists
        private bool isLocalBox(string mailbox, string maildomain)
        {
            // check if domain is local
            // if (!isLocalDomain(maildomain)) return false;

            // if no mailbox, treat as "all mailboxes are ok"
            if (this._mailBoxes.Count < 1) return true;

            // check if the mailbox exists
            string tmpAddr = mailbox + "@" + maildomain;
            for (int b = 0; b < this._mailBoxes.Count; b++)
            {
                if (tmpAddr.Equals(this._mailBoxes[b], StringComparison.InvariantCultureIgnoreCase))
                    return true;
            }
            return false;
        }

        // sends a line to remote
        private bool sendLine(string line)
        {
            try
            {
                logCmdAndResp(DIR_TX, line);
                this._writer.WriteLine(line);
                return true;
            }
            catch //(Exception ex)
            {
                //AppGlobals.writeConsole("sendLine(id={0},ip={1}): {2}", this._sessionID, this._clientIP, ex.Message);
                return false;
            }
        }

        // checks the receive buffer (used for early talkers)
        private bool recvPeek()
        {
            bool result;

            try { result = this._client.GetStream().DataAvailable; }
            catch { result = false; }
            return result;
        }


        // receives a line from remote
        private string recvLine()
        {
            string line = null;

            try
            {
                if (this._client.Connected)
                    line = this._reader.ReadLine();
            }
            catch //(Exception ex)
            {
                //AppGlobals.writeConsole("recvLine(id={0},ip={1}): {2}", this._sessionID, this._clientIP, ex.Message);
                this._timedOut = true;
                this._errCount++;
                line = null;
            }
            return line;
        }

        // receive a full data buffer from remote
        private string recvData()
        {
            try
            {
                StringBuilder buff = new StringBuilder();
                string line = "?";
                bool aboveMaxSize = false;

                while (null != line)
                {
                    line = recvLine();
                    if (null != line)
                    {
                        if (AppGlobals.storeData)
                        {
                            if (!aboveMaxSize)
                            {
                                if (buff.Length < AppGlobals.maxDataSize)
                                    buff.AppendLine(line);
                                else
                                    aboveMaxSize = true;
                            }
                        }
                        if (line.Equals(".", StringComparison.InvariantCultureIgnoreCase))
                            line = null;
                    } 
                }
                if (aboveMaxSize) return null;
                if (!AppGlobals.storeData) buff.AppendLine(".");
                return buff.ToString();
            }
            catch //(Exception ex)
            {
                //AppGlobals.writeConsole("recvData(id={0},ip={1}): {2}", this._sessionID, this._clientIP, ex.Message);
                return null;
            }
        }

        // splits an SMTP command into command and argument(s)
        private List<string> parseCmdLine(cmdID id, string cmdLine)
        {
            List<string> parts = new List<string>();
            if (string.IsNullOrEmpty(cmdLine)) return parts;
            try
            {
                string cmdStr = cmdList[(int)id];
                string curCmd = cleanupString(cmdLine);

                int pos = -1;
                if (cmdStr.Contains(':'))
                    pos = cmdLine.IndexOf(':');
                else
                    pos = cmdLine.IndexOf(' ');
                if (-1 != pos)
                {
                    string cmd = cleanupString(cmdLine.Substring(0, pos));
                    string arg = cleanupString(cmdLine.Substring(pos + 1));
                    parts.Add(cmd.ToUpper());
                    parts.Add(arg);
                }
                else
                    parts.Add(cleanupString(cmdLine).ToUpper());
            }
            catch
            {
                parts = new List<string>();
            }
            
            return parts;
        }

        // cleans a string
        private string cleanupString(string inputStr)
        {
            // setup...
            if (string.IsNullOrEmpty(inputStr)) return null;
            string strBuff = inputStr.Trim();
            char[] chars = strBuff.ToCharArray();
            char chr;

            // turn control chars into spaces
            for (int c = 0; c < chars.Length; c++)
            {
                chr = chars[c];
                if ((char.IsWhiteSpace(chr) || char.IsControl(chr)) && (!chr.Equals(' ')))
                {
                    chars[c] = ' '; // turn controls/tabs/... into spaces
                }
            }
            
            // trim, remove double spaces, trim again
            string result = new string(chars).Trim();
            while (result.Contains("  "))
                result.Replace("  ", " ");
            return result.Trim();
        }

        // check for early talkers, that is clients which won't wait
        // for the response and keep sending in commands/stuff, those
        // are usually spambots or the like, so let's deal with them
        private bool isEarlyTalker()
        {
            if (!AppGlobals.earlyTalkers) return false;
            bool tooEarly = false;
            if (recvPeek())
            {
                this._errCount++;
                tooEarly = true;
            }
            return tooEarly;
        }

        // "sleeps" for the given time
        private void sleepDown(int milliSeconds)
        {
            Thread.Sleep(milliSeconds);
        }

        // checks an IPv4 against DNS lists
        // todo: add parallel lookups to speed things up, stop
        //       the lookups upon the first positive hit
        private bool isListed(string IP, string[] lists, string listType)
        {
            if ((null == lists) || (lists.Length < 1)) return false;
            string queryString = null;
            for (int i = 0; i < lists.Length; i++)
            {
                queryString = buildDnsListQuery(IP, lists[i]);
                string result = queryDNS(queryString);
                if (!string.IsNullOrEmpty(result))
                {
                    this._dnsListType = listType;
                    this._dnsListName = lists[i];
                    this._dnsListValue = result;
                    return true;
                }
            }
            return false;
        }

        // true = the IP falls into a private/reserved range
        // see RFC-1918, RFC-3330, RFC-3927 for details
        private bool isPrivateIP(string IP)
        {
            // 127/8, 10/8, 192.168/16, 169.254/16, 192.0.2/24
            if (IP.StartsWith("127.") ||
                IP.StartsWith("10.") ||
                IP.StartsWith("192.168.") ||
                IP.StartsWith("169.254.") ||
                IP.StartsWith("192.0.2.")
                ) return true;
            
            // 172.16/12
            string[] octets = IP.Split(".".ToCharArray(), 4);
            if (octets[0].Equals("172"))
            {
                int octet = int.Parse(octets[1]);
                if ((octet > 15) && (octet < 32)) return true;
            }

            return false;
        }

        // reverse an IPv4 and appends the domain name
        private string buildDnsListQuery(string IP, string domain)
        {
            string[] octets = IP.Split(".".ToCharArray(), 4);

            return this.joinParts(octets[3], octets[2], octets[1], octets[0], domain);
        }

        // joins the given parms using dots as separators
        private string joinParts(params string[] args)
        {
            StringBuilder ret = new StringBuilder();
            foreach (String s in args)
                ret.AppendFormat("{0}.", s);

            return ret.ToString().Substring(0, ret.ToString().Length - 1);
        }

        // runs a DNS query
        private string queryDNS(string query)
        {
            IPHostEntry entry = null;
            string result = null;

            
            try
            {
                entry = Dns.GetHostEntry(query);
                if (null != entry)
                {
                    List<string> buff = new List<string>();
                    for (int i = 0; i < entry.AddressList.Length; i++)
                        buff.Add(entry.AddressList[i].ToString());
                    result = string.Join("+", buff);
                }
            }
            catch
            {
                //
            }
            return result;
        }

        // stores a mail message to file, notice that the code doesn't even
        // try to deal with message headers and mime parts nor to check if
        // they're correct, this isn't the purpose for this code, but willing
        // to add such parsing/checks, you may either add them here or after
        // receiving the "." command at end of the DATA stage
        private void storeMailMsg(string msgData)
        {
            // bump the message counter
            this._msgCount++;
            if (!AppGlobals.storeData) return;

            try
            {
                // build the pathname of the file used to store this email
                string filePath = AppGlobals.storePath;
                string fileName = "mailmsg-" + Path.GetRandomFileName().Replace('.','-') + ".txt";

                // record the file name
                this._msgFile = fileName;

                // open the file for writing
                StreamWriter fp = new StreamWriter(filePath + fileName, true);
                
                // add the envelope infos as headers
                fp.WriteLine("X-FakeSMTP-HostName: {0}", AppGlobals.hostName);
                fp.WriteLine("X-FakeSMTP-Sessions: count={0}, id={1}", this._sessCount, this._sessionID);
                fp.WriteLine("X-FakeSMTP-MsgCount: {0}", this._msgCount);
                fp.WriteLine("X-FakeSMTP-SessDate: {0}", this._startDate.ToString("u"));
                fp.WriteLine("X-FakeSMTP-ClientIP: {0}", this._clientIP);
                if (null != this._dnsListType)
                    fp.WriteLine("X-FakeSMTP-DnsList: type={0}, list={1}, result={2}", this._dnsListType, this._dnsListName, this._dnsListValue);
                else
                    fp.WriteLine("X-FakeSMTP-DnsList: type={0}, list={1}, result={2}", "notlisted", "none", "0.0.0.0");
                fp.WriteLine("X-FakeSMTP-Helo: {0}", this._heloStr);
                fp.WriteLine("X-FakeSMTP-MailFrom: {0}", this._mailFrom);
                fp.WriteLine("X-FakeSMTP-RcptCount: {0}", this._rcptTo.Count.ToString());
                for (int i = 0; i < this._rcptTo.Count; i++)
                    fp.WriteLine("X-FakeSMTP-RcptTo-{0}: {1}", i + 1, this._rcptTo[i]);
                fp.WriteLine("X-FakeSMTP-Counters: noop={0}, vrfy={1}, err={2}", this._noopCount, this._vrfyCount, this._errCount);

                // write the message data
                fp.WriteLine(msgData);

                // all done, flush and close
                fp.Flush();
                fp.Close();
            }
            catch (Exception ex)
            {
                this._msgFile = "write_error";
                Debug.WriteLine("storeMailMsg::Error: " + ex.Message);
            }
        }

        // if enabled, logs commands and replies
        private void logCmdAndResp(string direction, string line)
        {
            if (AppGlobals.logVerbose)
                AppGlobals.logMessage("{0}:{1} {2}: {3}", this._clientIP, this._sessionID, direction, line);
        }

        // logs session infos to logfile (at each mail); if you want to change
        // the log record format, this is the place to do it, just change the
        // "cols.Add" to include the columns you want and there you'll go :-)
        private void logSession()
        {
            // check if already logged
            if (this._lastMsgID == this._msgCount) return;
            this._lastMsgID = this._msgCount;

            // check if we got some data
            if (string.IsNullOrEmpty(this._heloStr)) this._heloStr = "-no-helo-";
            if (string.IsNullOrEmpty(this._mailFrom)) this._mailFrom = "-no-from-";
            // if (0 == this._rcptTo.Count) return;

            // build the log array
            List<string> cols = new List<string>();

            // current date/time
            cols.Add(DateTime.UtcNow.ToString("u"));

            // start date, session ID, client IP, helo
            cols.Add(this._startDate.ToString("u"));
            cols.Add(this._sessionID.ToString());
            cols.Add(this._clientIP);
            cols.Add(this._heloStr);

            // mail from
            if (!string.IsNullOrEmpty(this._mailFrom))
                cols.Add(this._mailFrom);
            else
                cols.Add("");

            // rcpt to
            if (this._rcptTo.Count > 0)
            {
                cols.Add(this._rcptTo.Count.ToString());
                cols.Add(string.Join(",", this._rcptTo));
            }
            else
            {
                cols.Add("0");
                cols.Add("-no-rcpt-");
            }

            // message # and message file name (if any)
            cols.Add(this._msgCount.ToString());
            if (!string.IsNullOrEmpty(this._msgFile))
                cols.Add(this._msgFile);
            else
                cols.Add("-no-file-");

            // dns listing
            if (!string.IsNullOrEmpty(this._dnsListType))
            {
                cols.Add(this._dnsListType);
                cols.Add(this._dnsListName);
                cols.Add(this._dnsListValue);
            }
            else
            {
                cols.Add("-not-listed-");
                cols.Add("-none-");
                cols.Add("0.0.0.0");
            }

            // early talker
            if (this._earlyTalker)
                cols.Add("1");
            else
                cols.Add("0");

            // noop/vrfy/err
            cols.Add(this._noopCount.ToString());
            cols.Add(this._vrfyCount.ToString());
            cols.Add(this._errCount.ToString());

            // builds and logs the record
            //string logRec = string.Join("|", cols);
            //AppGlobals.logSession("{0}", logRec);

            // builds the log record format string
            StringBuilder logFmt = new StringBuilder("{0}");
            for (int i = 1; i < cols.Count; i++)
                logFmt.Append("|{" + i + "}");

            // log the record
            AppGlobals.logSession(logFmt.ToString(), cols.ToArray<string>());
        }
        #endregion

    }
}
