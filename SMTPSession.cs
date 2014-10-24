using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace FakeSMTP
{
	internal class SmtpSession
	{
		#region "privatedata"

		// chars allowed in HELO/EHLO string
		private const string _heloChars = "[]0123456789.-abcdefghijklmnopqrstuvwxyz_";

		// for verbose logging
		private const string _dirTx = "SND";
		private const string _dirRx = "RCV";

		// misc SMTP messages
		private const string _bannerStr = "220 {0} MailRecv 0.1.2-b4; {1}";
		private const string _tempfailMsg = "421 Service temporarily unavailable, closing transmission channel.";
		private const string _dnsblMsg = "442 Connection from {0} temporarily refused, host listed by {1}";
		private const string _timeoutMsg = "442 Connection timed out.";
		private const string _etalkerMsg = "554 Misbehaved SMTP session (EarlyTalker)";

		// SMTP command strings
		private readonly string[] _cmdList =
		{
			"\r\n",
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
		private enum _CmdId
		{
			Invalid,
			Helo,
			Ehlo,
			MailFrom,
			RcptTo,
			Data,
			Rset,
			Quit,
			Vrfy,
			Expn,
			Help,
			Noop
		}

		// network/system
		private bool _initOk; // true = initialized
		private readonly string _hostName; // local host name for banner
		private TcpClient _client; // remote client
		private readonly NetworkStream _stream; // network stream for I/O
		private readonly StreamReader _reader; // network reader
		private readonly StreamWriter _writer; // network writer
		private readonly long _sessCount; // current session count
		private readonly string _sessionId; // ID for this session
		private long _lastMsgId = -1; // last logged message #
		private bool _timedOut; // true = the connection timed out

		// local domains/mailboxes
		private readonly List<string> _mailDomains = new List<string>(); // list of locally handled domains
		private readonly List<string> _mailBoxes = new List<string>(); // list of locally handled mailboxes

		// session
		private DateTime _startDate = DateTime.UtcNow; // session start datetime
		private readonly string _clientIp; // remote IP
		private string _dnsListType; // type of listing
		private string _dnsListName; // name of DNS list flagging the IP
		private string _dnsListValue; // value returned by the DNS list
		private _CmdId _lastCmd = _CmdId.Invalid; // last cmd issued
		private string _heloStr; // HELO/EHLO string
		private string _mailFrom; // MAIL FROM address
		private List<string> _rcptTo = new List<string>(); // RCPT TO list
		private long _msgCount; // # of messages for this session
		private string _msgFile; // message file storage
		private bool _earlyTalker; // true the client is a "early talker"
		private int _noopCount; // # of NOOP issued
		private int _errCount; // # of errors
		private int _vrfyCount; // # of VRFY/EXPN

		// workareas
		private string _mailBox; // mailbox part of a mail address
		private string _mailDom; // domain part of a mail address

		#endregion

		#region "instance"

		// init
		public SmtpSession(TcpClient client)
		{
			try
			{
				_sessCount = AppGlobals.AddSession();
				_sessionId = AppGlobals.SessionId();
				_hostName = AppGlobals.HostName;

				if (null != AppGlobals.LocalDomains)
					_mailDomains = AppGlobals.LocalDomains;
				if (null != AppGlobals.LocalMailBoxes)
					_mailBoxes = AppGlobals.LocalMailBoxes;

				_client = client;
				_clientIp = _client.Client.RemoteEndPoint.ToString();
				var i = _clientIp.IndexOf(':');
				if (-1 != i)
					_clientIp = _clientIp.Substring(0, i);
				_client.ReceiveTimeout = AppGlobals.ReceiveTimeout;

				_stream = _client.GetStream();
				_reader = new StreamReader(_stream);
				_writer = new StreamWriter(_stream);
				_writer.NewLine = "\r\n";
				_writer.AutoFlush = true;

				AppGlobals.WriteConsole("client {0} connected, sess={1}, ID={2}.", _clientIp, _sessCount, _sessionId);
				_initOk = true;
			}
			catch (Exception ex)
			{
				AppGlobals.WriteConsole("SMTPsession::Exception: " + ex.Message);
				_CloseSession();
			}
		}

		#endregion

		#region "methods"

		public void HandleSession()
		{
			var cmdLine = "?";
			var currCmd = _CmdId.Invalid;

			if (false == _initOk)
			{
				_CloseSession();
				return;
			}

			// sessions limit reached, reject session
			if (_sessCount > AppGlobals.MaxSessions)
			{
				_SendLine(_tempfailMsg);
				_CloseSession();
				return;
			}

			// if the remote IP isn't a private one
			if (!_IsPrivateIp(_clientIp))
			{
				// checks the incoming IP against whitelists, if listed skip blacklist checks
				var isDnsListed = _IsListed(_clientIp, AppGlobals.WhiteLists, "white");
				if (!isDnsListed)
				{
					// check the IP against blacklists
					isDnsListed = _IsListed(_clientIp, AppGlobals.BlackLists, "black");
					if ((isDnsListed) && (!AppGlobals.StoreData))
					{
						// if blacklisted and NOT storing messages
						_SendLine(string.Format(_dnsblMsg, _clientIp, _dnsListName));
						_CloseSession();
						return;
					}
				}
			}

			// add a short delay before banner and check for early talker
			// see http://wiki.asrg.sp.am/wiki/Early_talker_detection
			_SleepDown(AppGlobals.BannerDelay);
			_earlyTalker = _IsEarlyTalker();
			if (_earlyTalker)
			{
				_SendLine(_etalkerMsg);
				_CloseSession();
				return;
			}

			// all ok, send out our banner            
			var connOk = _SendLine(_CmdBanner());
			while ((null != cmdLine) && connOk)
			{
				string response;
				if (_lastCmd == _CmdId.Data)
				{
					var mailMsg = _RecvData();
					if (_timedOut)
					{
						// got a receive timeout during the DATA phase
						_SendLine(_timeoutMsg);
						_CloseSession();
						return;
					}
					response = _CmdDot();
					if (String.IsNullOrEmpty(mailMsg))
						response = "422 Recipient mailbox exceeded quota limit.";
					else
					{
						_StoreMailMsg(mailMsg);
						if (AppGlobals.DoTempFail)
						{
							// emit a tempfail AFTER storing the mail DATA
							_SendLine(_tempfailMsg);
							_CloseSession();
							return;
						}
					}
					_ResetSession();
				}
				else
				{
					// read an SMTP command line and deal with the command
					cmdLine = _RecvLine();
					if (null != cmdLine)
					{
						_LogCmdAndResp(_dirRx, cmdLine);
						currCmd = _GetCommandId(cmdLine);
						switch (currCmd)
						{
							case _CmdId.Helo: // HELO
								response = _CmdHelo(cmdLine);
								break;
							case _CmdId.Ehlo: // EHLO
								response = _CmdHelo(cmdLine);
								break;
							case _CmdId.MailFrom: // MAIL FROM:
								response = _CmdMail(cmdLine);
								break;
							case _CmdId.RcptTo: // RCPT TO:
								response = _CmdRcpt(cmdLine);
								break;
							case _CmdId.Data: // DATA
								if ((AppGlobals.DoTempFail) && (!AppGlobals.StoreData))
								{
									// emit a tempfail upon receiving the DATA command
									response = _tempfailMsg;
									cmdLine = null;
									_lastCmd = currCmd = _CmdId.Quit;
								}
								else
									response = _CmdData();
								break;
							case _CmdId.Rset: // RSET
								response = _CmdRset();
								break;
							case _CmdId.Quit: // QUIT
								response = _CmdQuit();
								cmdLine = null; // force closing
								break;
							case _CmdId.Vrfy: // VRFY
								response = _CmdVrfy(cmdLine);
								break;
							case _CmdId.Expn: // EXPN
								response = _CmdVrfy(cmdLine);
								break;
							case _CmdId.Help: // HELP
								response = _CmdHelp();
								break;
							case _CmdId.Noop: // NOOP
								response = _CmdNoop(cmdLine);
								break;
							default: // unkown/unsupported
								response = _CmdUnknown(cmdLine);
								break;
						}
					}
					else
					{
						// the read timed out (or we got an error), emit a message and drop the connection
						response = _timeoutMsg;
						currCmd = _CmdId.Quit;
					}
				}

				// send response
				if ((_errCount > 0) && (_CmdId.Quit != currCmd))
				{
					// tarpit a bad client, time increases with error count
					_SleepDown(AppGlobals.ErrorDelay * _errCount);
				}
				else
				{
					// add a short delay
					_SleepDown(25);
				}

				// checks for early talkers
				_earlyTalker = _IsEarlyTalker();

				// send out the response
				connOk = _SendLine(response);

				// check/enforce hard limits (errors, vrfy ...)
				if (_CmdId.Quit != currCmd && connOk)
				{
					string errMsg = null;
					if (_msgCount > AppGlobals.MaxMessages)
					{
						// above max # of message in a single session
						errMsg = "451 Session messages count exceeded";
					}
					else if (_errCount > AppGlobals.MaxSmtpErr)
					{
						// too many errors
						errMsg = "550 Max errors exceeded";
					}
					else if (_vrfyCount > AppGlobals.MaxSmtpVrfy)
					{
						// tried to VRFY/EXPN too many addresses
						errMsg = "451 Max recipient verification exceeded";
					}
					else if (_noopCount > AppGlobals.MaxSmtpNoop)
					{
						// entered too many NOOP commands
						errMsg = "451 Max NOOP count exceeded";
					}
					else if (_rcptTo.Count > AppGlobals.MaxSmtpRcpt)
					{
						// too many recipients for a single message
						errMsg = "452 Too many recipients";
					}
					else if (_earlyTalker)
					{
						// early talker
						errMsg = _etalkerMsg;
					}
					if (null != errMsg)
					{
						connOk = _SendLine(errMsg);
						cmdLine = null; // force closing
					}
				}

				// check if connection Ok
				if (connOk)
					connOk = _client.Connected;
			} // while null...

			// close/reset this session
			_CloseSession();
		}

		#endregion

		#region "privatecode"

		// retrieves the command ID from command line args
		private _CmdId _GetCommandId(string cmdLine)
		{
			var id = _CmdId.Invalid;
			var tmpBuff = cmdLine.ToUpperInvariant();

			for (var i = 0; i < _cmdList.Length; i++)
			{
				if (!tmpBuff.StartsWith(_cmdList[i]))
					continue;

				id = (_CmdId)i;
				break;
			}
			return id;
		}

		// resets the internal session values
		private void _ResetSession()
		{
			_LogSession(); // logs the session/message to file (if data available) 
			_mailFrom = null;
			_rcptTo = new List<string>();
			_msgFile = null;
			_noopCount = 0;
			_errCount = 0;
			_vrfyCount = 0;
		}

		// closes the socket, terminates the session
		private void _CloseSession()
		{
			if (null != _client)
			{
				if (_client.Connected)
					_SleepDown(25);
				try
				{
					_client.Close();
					_client = null;
				}
				catch (Exception ex)
				{
					Console.WriteLine(ex);
				}
				if (!string.IsNullOrEmpty(_clientIp))
					AppGlobals.WriteConsole("client {0} disconnected, sess={1}, ID={2}.", _clientIp, _sessCount, _sessionId);
			}
			_initOk = false;
			AppGlobals.RemoveSession();
			_ResetSession();
		}

		// banner string (not a real command)
		private string _CmdBanner()
		{
			var banner = String.Format(_bannerStr, _hostName, DateTime.UtcNow.ToString("R"));
			return banner;
		}

		// HELO/EHLO
		private string _CmdHelo(string cmdLine)
		{
			var id = _GetCommandId(cmdLine);
			var parts = _ParseCmdLine(id, cmdLine);
			if (2 != parts.Count)
			{
				_errCount++;
				return String.Format("501 {0} needs argument", parts[0]);
			}
			if (!string.IsNullOrEmpty(_heloStr))
			{
				_errCount++;
				return string.Format("503 you already sent {0} ...", parts[0]);
			}
			if (AppGlobals.CheckHelloFormat && !_CheckHelo(parts[1]))
			{
				_errCount++;
				return String.Format("501 Invalid {0}", parts[0]);
			}
			if (parts[1].ToLower().Equals("localhost") ||
				parts[1].ToLower().Equals(AppGlobals.HostName) ||
				parts[1].StartsWith("[127.") ||
				parts[1].Equals("[" + AppGlobals.ListenAddress + "]")
				)
			{
				_errCount++;
				return String.Format("501 spoofed {0}", parts[0]);
			}

			_heloStr = parts[1];
			_lastCmd = id;
			if (id == _CmdId.Helo)
				return String.Format("250 Hello {0} ([{1}]), nice to meet you.", parts[1], _clientIp);
			return String.Format("250 Hello {0} ([{1}]), nice to meet you.\r\n250-HELP\r\n250-VRFY\r\n250-EXPN\r\n250 NOOP", parts[1], _clientIp);
		}

		// MAIL FROM:
		private string _CmdMail(string cmdLine)
		{
			if (string.IsNullOrEmpty(_heloStr))
			{
				_errCount++;
				return "503 HELO/EHLO Command not issued";
			}
			if (!string.IsNullOrEmpty(_mailFrom))
			{
				_errCount++;
				return "503 Nested MAIL command";
			}
			var parts = _ParseCmdLine(_CmdId.MailFrom, cmdLine);
			if (2 != parts.Count)
			{
				_errCount++;
				return String.Format("501 {0} needs argument", parts[0]);
			}
			if (!_CheckMailAddr(parts[1]))
			{
				_errCount++;
				return String.Format("553 Invalid address {0}", parts[1]);
			}
			_mailFrom = parts[1];
			_lastCmd = _CmdId.MailFrom;
			return string.Format("250 {0}... Sender ok", parts[1]);
		}

		// RCPT TO:
		private string _CmdRcpt(string cmdLine)
		{
			if (string.IsNullOrEmpty(_mailFrom))
			{
				_errCount++;
				return "503 Need MAIL before RCPT";
			}
			var parts = _ParseCmdLine(_CmdId.RcptTo, cmdLine);
			if (2 != parts.Count)
			{
				_errCount++;
				return String.Format("501 {0} needs argument", parts[0]);
			}
			if (!_CheckMailAddr(parts[1]))
			{
				_errCount++;
				return String.Format("553 Invalid address {0}", parts[1]);
			}

			if (!_IsLocalDomain(_mailDom))
			{
				// relaying not allowed...
				_errCount++;
				return "530 Relaying not allowed for policy reasons";
			}
			if (!_IsLocalBox(_mailBox, _mailDom))
			{
				// unkown/invalid recipient
				_errCount++;
				return String.Format("553 Unknown email address {0}", parts[1]);
			}

			_rcptTo.Add(parts[1]);
			_lastCmd = _CmdId.RcptTo;
			return string.Format("250 {0}... Recipient ok", parts[1]);
		}

		// DATA
		private string _CmdData()
		{
			if (_rcptTo.Count < 1)
			{
				_errCount++;
				return "471 Bad or missing RCPT command";
			}
			_lastCmd = _CmdId.Data;
			return "354 Start mail input; end with <CRLF>.<CRLF>";
		}

		// end of DATA (dot)
		private string _CmdDot()
		{
			_lastCmd = _CmdId.Noop;
			return "250 Queued mail for delivery";
		}

		// RSET
		private string _CmdRset()
		{
			_ResetSession();
			_lastCmd = _CmdId.Rset;
			return "250 Reset Ok";
		}

		// QUIT
		private string _CmdQuit()
		{
			_lastCmd = _CmdId.Quit;
			return "221 Closing connection.";
		}

		// VRFY/EXPN
		private string _CmdVrfy(string cmdLine)
		{
			var id = _GetCommandId(cmdLine);
			_vrfyCount++;
			var parts = _ParseCmdLine(id, cmdLine);
			if (2 != parts.Count)
			{
				_errCount++;
				return String.Format("501 {0} needs argument", parts[0]);
			}
			if (!_CheckMailAddr(parts[1]))
			{
				_errCount++;
				return String.Format("553 Invalid address {0}", parts[1]);
			}
			_lastCmd = id;
			if (id == _CmdId.Vrfy)
				return "252 Cannot VRFY user; try RCPT to attempt delivery (or try finger)";
			return String.Format("250 {0}", parts[1]);
		}

		// NOOP
		private string _CmdNoop(string cmdLine)
		{
			_noopCount++;
			var parts = _ParseCmdLine(_CmdId.Noop, cmdLine);
			if (parts.Count > 1)
			{
				// NOOP may have args...
				return string.Format("250 ({0}) OK", parts[1]);
			}
			return "250 OK";
		}

		// HELP
		private string _CmdHelp()
		{
			// dynamically build the help string for our commands list
			var buff = "211";
			for (var i = 1; i < _cmdList.Length; i++)
			{
				var cmd = _cmdList[i];
				var pos = cmd.IndexOf(' ');
				if (-1 != pos)
					cmd = cmd.Substring(0, pos);
				buff = buff + " " + cmd;
			}
			return buff;
		}

		// unknown/unsupported
		private string _CmdUnknown(string cmdLine)
		{
			_errCount++;
			_lastCmd = _CmdId.Invalid;
			return string.IsNullOrEmpty(cmdLine)
				? "500 Command unrecognized"
				: string.Format("500 Command unrecognized ({0})", cmdLine);
		}

		// coarse checks on the HELO string (todo: replace with regexp)
		private bool _CheckHelo(string heloStr)
		{
			// can't be empty
			if (String.IsNullOrEmpty(heloStr))
				return false;

			// can't start with a dot or hypen
			var heloChars = heloStr.ToLowerInvariant().ToCharArray();
			if ((heloChars[0] == '.') || (heloChars[0] == '-'))
				return false;

			// must contain at least a dot
			if (!heloStr.Contains('.'))
				return false;

			// can only contain valid chars
			if (heloChars.Any(t => !_heloChars.Contains(t)))
			{
				return false;
			}

			// if starts with "[" the bracket must match and the
			// enclosed string must be a valid IP address (and
			// match the connecting IP address)
			if ('[' == heloChars[0])
			{
				if (']' != heloChars[heloChars.Length - 1])
					return false;
				var ipAddr = heloStr.Replace('[', ' ');
				ipAddr = ipAddr.Replace(']', ' ').Trim();
				IPAddress ip;
				//if (!ipAddr.Equals(this._clientIP)) return false;
				if (!IPAddress.TryParse(ipAddr, out ip))
					return false;
				//if (isPrivateIP(ipAddr)) return false;
			}
			else
			{
				// run a check on the domain
				var result = _CheckMailAddr("postmaster@" + heloStr);
				if (false == result)
					return false;
			}

			return true;
		}

		// coarse checks on the email address (todo: replace with regexp)
		private bool _CheckMailAddr(string mailAddr)
		{
			// init
			_mailBox = _mailDom = null;
			var email = _CleanupString(mailAddr).ToLowerInvariant();

			// shouldn't be empy and must contain at least a @ and a dot
			if (string.IsNullOrEmpty(email))
				return false;
			if (!email.Contains('@'))
				return false;
			if (!email.Contains('.'))
				return false;

			// if starting with a "<" must end with a ">"
			var chars = email.ToCharArray();
			if ('<' == chars[0])
			{
				if ('>' != chars[email.Length - 1])
					return false;
				email = email.Replace('<', ' ');
				email = email.Replace('>', ' ');
				email = _CleanupString(email);
				if (email.Length < 1)
					return false;
			}

			// can't contain a space
			if (email.Contains(' '))
				return false;

			// the "@" must be unique
			var parts = email.Split('@');
			if (2 != parts.Length)
				return false;

			// cleanup and check parts
			for (var p = 0; p < parts.Length; p++)
			{
				parts[p] = _CleanupString(parts[p]);
				if (string.IsNullOrEmpty(parts[p]))
					return false;
			}

			// formally checks domain (and TLD)
			if (!parts[1].Contains('.'))
				return false;
			if (parts[1].StartsWith("."))
				return false;
			if (parts[1].EndsWith("."))
				return false;
			var domain = parts[1].Split('.');
			if (domain.Length < 2)
				return false;
			foreach (var part in domain)
			{
				if (string.IsNullOrEmpty(part))
					return false;
				if (part.StartsWith("-"))
					return false;
			}
			var tld = domain[domain.Length - 1];
			if (tld.Length < 2)
				return false;

			// store mailbox and domain
			_mailBox = parts[0];
			_mailDom = parts[1];

			return true;
		}

		// checks if a domain is local
		private bool _IsLocalDomain(string maildomain)
		{
			// if no domain, treat as "all domains are ok"
			if (_mailDomains.Count < 1)
				return true;
			return _mailDomains.Any(t => maildomain.Equals(t, StringComparison.InvariantCultureIgnoreCase));
		}

		// checks if a mailbox is local / exists
		private bool _IsLocalBox(string mailbox, string maildomain)
		{
			// check if domain is local
			// if (!isLocalDomain(maildomain)) return false;

			// if no mailbox, treat as "all mailboxes are ok"
			if (_mailBoxes.Count < 1)
				return true;

			// check if the mailbox exists
			var tmpAddr = mailbox + "@" + maildomain;
			return _mailBoxes.Any(t => tmpAddr.Equals(t, StringComparison.InvariantCultureIgnoreCase));
		}

		// sends a line to remote
		private bool _SendLine(string line)
		{
			try
			{
				_LogCmdAndResp(_dirTx, line);
				_writer.WriteLine(line);
				return true;
			}
			catch //(Exception ex)
			{
				//AppGlobals.writeConsole("sendLine(id={0},ip={1}): {2}", this._sessionID, this._clientIP, ex.Message);
				return false;
			}
		}

		// checks the receive buffer (used for early talkers)
		private bool _RecvPeek()
		{
			bool result;

			try
			{
				result = _client.GetStream().DataAvailable;
			}
			catch
			{
				result = false;
			}
			return result;
		}

		// receives a line from remote
		private string _RecvLine()
		{
			string line = null;

			try
			{
				if (_client.Connected)
					line = _reader.ReadLine();
			}
			catch //(Exception ex)
			{
				//AppGlobals.writeConsole("recvLine(id={0},ip={1}): {2}", this._sessionID, this._clientIP, ex.Message);
				_timedOut = true;
				_errCount++;
				line = null;
			}
			return line;
		}

		// receive a full data buffer from remote
		private string _RecvData()
		{
			try
			{
				var buff = new StringBuilder();
				var line = "?";
				var aboveMaxSize = false;

				while (null != line)
				{
					line = _RecvLine();
					if (null == line)
						continue;
					if (AppGlobals.StoreData)
					{
						if (!aboveMaxSize)
						{
							if (buff.Length < AppGlobals.MaxDataSize)
								buff.AppendLine(line);
							else
								aboveMaxSize = true;
						}
					}
					if (line.Equals(".", StringComparison.InvariantCultureIgnoreCase))
						line = null;
				}
				if (aboveMaxSize)
					return null;
				if (!AppGlobals.StoreData)
					buff.AppendLine(".");
				return buff.ToString();
			}
			catch //(Exception ex)
			{
				//AppGlobals.writeConsole("recvData(id={0},ip={1}): {2}", this._sessionID, this._clientIP, ex.Message);
				return null;
			}
		}

		// splits an SMTP command into command and argument(s)
		private List<string> _ParseCmdLine(_CmdId id, string cmdLine)
		{
			var parts = new List<string>();
			if (string.IsNullOrEmpty(cmdLine))
				return parts;
			try
			{
				var cmdStr = _cmdList[(int)id];

				var pos = cmdLine.IndexOf(cmdStr.Contains(':') ? ':' : ' ');
				if (-1 != pos)
				{
					var cmd = _CleanupString(cmdLine.Substring(0, pos));
					var arg = _CleanupString(cmdLine.Substring(pos + 1));
					parts.Add(cmd.ToUpper());
					parts.Add(arg);
				}
				else
					parts.Add(_CleanupString(cmdLine).ToUpper());
			}
			catch
			{
				parts = new List<string>();
			}

			return parts;
		}

		// cleans a string
		private static string _CleanupString(string inputStr)
		{
			// setup...
			if (string.IsNullOrEmpty(inputStr))
				return null;
			var strBuff = inputStr.Trim();
			var chars = strBuff.ToCharArray();

			// turn control chars into spaces
			for (var c = 0; c < chars.Length; c++)
			{
				var chr = chars[c];
				if ((char.IsWhiteSpace(chr) || char.IsControl(chr)) && (!chr.Equals(' ')))
					chars[c] = ' '; // turn controls/tabs/... into spaces
			}

			// trim, remove double spaces, trim again
			var result = new string(chars).Trim();
			while (result.Contains("  "))
				return result.Replace("  ", " ");
			return result.Trim();
		}

		// check for early talkers, that is clients which won't wait
		// for the response and keep sending in commands/stuff, those
		// are usually spambots or the like, so let's deal with them
		private bool _IsEarlyTalker()
		{
			if (!AppGlobals.EarlyTalkers)
				return false;
			var tooEarly = false;
			if (_RecvPeek())
			{
				_errCount++;
				tooEarly = true;
			}
			return tooEarly;
		}

		// "sleeps" for the given time
		private static void _SleepDown(int milliSeconds)
		{
			Thread.Sleep(milliSeconds);
		}

		// checks an IPv4 against DNS lists
		// todo: add parallel lookups to speed things up, stop
		//       the lookups upon the first positive hit
		private bool _IsListed(string ip, string[] lists, string listType)
		{
			if ((null == lists) || (lists.Length < 1))
				return false;
			foreach (var item in lists)
			{
				var queryString = _BuildDnsListQuery(ip, item);
				var result = _QueryDns(queryString);
				if (string.IsNullOrEmpty(result))
					continue;
				_dnsListType = listType;
				_dnsListName = item;
				_dnsListValue = result;
				return true;
			}
			return false;
		}

		// true = the IP falls into a private/reserved range
		// see RFC-1918, RFC-3330, RFC-3927 for details
		private static bool _IsPrivateIp(string ip)
		{
			// 127/8, 10/8, 192.168/16, 169.254/16, 192.0.2/24
			if (ip.StartsWith("127.") ||
				ip.StartsWith("10.") ||
				ip.StartsWith("192.168.") ||
				ip.StartsWith("169.254.") ||
				ip.StartsWith("192.0.2.")
				)
				return true;

			// 172.16/12
			var octets = ip.Split(".".ToCharArray(), 4);
			if (octets[0].Equals("172"))
			{
				var octet = int.Parse(octets[1]);
				if ((octet > 15) && (octet < 32))
					return true;
			}

			return false;
		}

		// reverse an IPv4 and appends the domain name
		private static string _BuildDnsListQuery(string ip, string domain)
		{
			var octets = ip.Split(".".ToCharArray(), 4);

			return _JoinParts(octets[3], octets[2], octets[1], octets[0], domain);
		}

		// joins the given parms using dots as separators
		private static string _JoinParts(params string[] args)
		{
			var ret = new StringBuilder();
			foreach (var s in args)
				ret.AppendFormat("{0}.", s);

			return ret.ToString().Substring(0, ret.ToString().Length - 1);
		}

		// runs a DNS query
		private static string _QueryDns(string query)
		{
			string result = null;

			try
			{
				var entry = Dns.GetHostEntry(query);
				if (null != entry)
				{
					var buff = entry.AddressList.Select(t => t.ToString()).ToList();
					result = string.Join("+", buff);
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex);
			}
			return result;
		}

		// stores a mail message to file, notice that the code doesn't even
		// try to deal with message headers and mime parts nor to check if
		// they're correct, this isn't the purpose for this code, but willing
		// to add such parsing/checks, you may either add them here or after
		// receiving the "." command at end of the DATA stage
		private void _StoreMailMsg(string msgData)
		{
			// bump the message counter
			_msgCount++;
			if (!AppGlobals.StoreData)
				return;

			try
			{
				// build the pathname of the file used to store this email
				var filePath = AppGlobals.StorePath;
				var fileName = "mailmsg-" + Path.GetRandomFileName().Replace('.', '-') + ".txt";

				// record the file name
				_msgFile = fileName;

				// open the file for writing
				var fp = new StreamWriter(filePath + fileName, true);

				// add the envelope infos as headers
				fp.WriteLine("X-FakeSMTP-HostName: {0}", AppGlobals.HostName);
				fp.WriteLine("X-FakeSMTP-Sessions: count={0}, id={1}", _sessCount, _sessionId);
				fp.WriteLine("X-FakeSMTP-MsgCount: {0}", _msgCount);
				fp.WriteLine("X-FakeSMTP-SessDate: {0}", _startDate.ToString("u"));
				fp.WriteLine("X-FakeSMTP-ClientIP: {0}", _clientIp);
				if (null != _dnsListType)
					fp.WriteLine("X-FakeSMTP-DnsList: type={0}, list={1}, result={2}", _dnsListType, _dnsListName, _dnsListValue);
				else
					fp.WriteLine("X-FakeSMTP-DnsList: type={0}, list={1}, result={2}", "notlisted", "none", "0.0.0.0");
				fp.WriteLine("X-FakeSMTP-Helo: {0}", _heloStr);
				fp.WriteLine("X-FakeSMTP-MailFrom: {0}", _mailFrom);
				fp.WriteLine("X-FakeSMTP-RcptCount: {0}", _rcptTo.Count);
				for (var i = 0; i < _rcptTo.Count; i++)
					fp.WriteLine("X-FakeSMTP-RcptTo-{0}: {1}", i + 1, _rcptTo[i]);
				fp.WriteLine("X-FakeSMTP-Counters: noop={0}, vrfy={1}, err={2}", _noopCount, _vrfyCount, _errCount);

				// write the message data
				fp.WriteLine(msgData);

				// all done, flush and close
				fp.Flush();
				fp.Close();
			}
			catch (Exception ex)
			{
				_msgFile = "write_error";
				Debug.WriteLine("storeMailMsg::Error: " + ex.Message);
			}
		}

		// if enabled, logs commands and replies
		private void _LogCmdAndResp(string direction, string line)
		{
			if (AppGlobals.LogVerbose)
				AppGlobals.LogMessage("{0}:{1} {2}: {3}", _clientIp, _sessionId, direction, line);
		}

		// logs session infos to logfile (at each mail); if you want to change
		// the log record format, this is the place to do it, just change the
		// "cols.Add" to include the columns you want and there you'll go :-)
		private void _LogSession()
		{
			// check if already logged
			if (_lastMsgId == _msgCount)
				return;
			_lastMsgId = _msgCount;

			// check if we got some data
			if (string.IsNullOrEmpty(_heloStr))
				_heloStr = "-no-helo-";
			if (string.IsNullOrEmpty(_mailFrom))
				_mailFrom = "-no-from-";
			// if (0 == this._rcptTo.Count) return;

			// build the log array
			var cols = new List<string>();

			// current date/time
			cols.Add(DateTime.UtcNow.ToString("u"));

			// start date, session ID, client IP, helo
			cols.Add(_startDate.ToString("u"));
			cols.Add(_sessionId);
			cols.Add(_clientIp);
			cols.Add(_heloStr);

			// mail from
			cols.Add(!string.IsNullOrEmpty(_mailFrom) ? _mailFrom : "");

			// rcpt to
			if (_rcptTo.Count > 0)
			{
				cols.Add(_rcptTo.Count.ToString());
				cols.Add(string.Join(",", _rcptTo));
			}
			else
			{
				cols.Add("0");
				cols.Add("-no-rcpt-");
			}

			// message # and message file name (if any)
			cols.Add(_msgCount.ToString());
			cols.Add(!string.IsNullOrEmpty(_msgFile) ? _msgFile : "-no-file-");

			// dns listing
			if (!string.IsNullOrEmpty(_dnsListType))
			{
				cols.Add(_dnsListType);
				cols.Add(_dnsListName);
				cols.Add(_dnsListValue);
			}
			else
			{
				cols.Add("-not-listed-");
				cols.Add("-none-");
				cols.Add("0.0.0.0");
			}

			// early talker
			cols.Add(_earlyTalker ? "1" : "0");

			// noop/vrfy/err
			cols.Add(_noopCount.ToString());
			cols.Add(_vrfyCount.ToString());
			cols.Add(_errCount.ToString());

			// builds and logs the record
			//string logRec = string.Join("|", cols);
			//AppGlobals.logSession("{0}", logRec);

			// builds the log record format string
			var logFmt = new StringBuilder("{0}");
			for (var i = 1; i < cols.Count; i++)
				logFmt.Append("|{" + i + "}");

			// log the record
			AppGlobals.LogSession(logFmt.ToString(), cols.ToArray<string>());
		}

		#endregion
	}
}
