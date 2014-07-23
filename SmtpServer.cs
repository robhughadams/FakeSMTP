using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

/*
** fakeSMTP: fakes a full blown SMTP server, useful to test mail sending apps
**           or as a fake SMTP receiver to implement the so-called MX sandwich
**           also known as nolisting; for details about the latter, see
**
** http://nolisting.org/
** http://wiki.apache.org/spamassassin/OtherTricks
** http://www.mail-archive.com/users@spamassassin.apache.org/msg51583.html
** 
** the code for this app was inspired from:
**
** http://forums.whirlpool.net.au/archive/654973
** http://www.codeproject.com/Tips/286952/create-a-simple-smtp-server-in-csharp
** http://ndumbster.sourceforge.net/default.html
**
*/

namespace FakeSMTP
{
	public class SmtpServer
	{
		public bool TimeToStop;

		#region "privatedata"

		private TcpListener _listener;

		#endregion

		#region "entrypoint"

		public int Start()
		{
			// clear the flag in case we've previously been stopped.
			TimeToStop = false;

			// our internal stuff
			var retCode = 0;

			// load the config
			_LoadConfig();

			// tell we're starting up and, if verbose, dump config parameters
			AppGlobals.WriteConsole("{0} {1} starting up (NET {2})", AppGlobals.AppName, AppGlobals.AppVersion, AppGlobals.AppRuntime);
			if (AppGlobals.LogVerbose)
				_DumpSettings();

			// setup the listening IP:port
			var listenAddr = AppGlobals.ListenIp;
			var listenPort = AppGlobals.ListenPort;

			// try starting the listener
			try
			{
				_listener = new TcpListener(listenAddr, listenPort);
				_listener.Start();
			}
			catch (Exception ex)
			{
				AppGlobals.WriteConsole("Listener::Error: " + ex.Message);
				return 1;
			}

			// tell we're ready to accept connections
			AppGlobals.WriteConsole("Listening for connections on {0}:{1}", listenAddr, listenPort);

			// run until interrupted (Ctrl-C in our case)
			while (!TimeToStop)
			{
				try
				{
					// wait for an incoming connection, accept it and spawn a thread to handle it
					var handler = new SmtpSession(_listener.AcceptTcpClient());
					var thread = new Thread(handler.HandleSession);
					thread.Start();
				}
				catch (Exception ex)
				{
					// we got an error
					retCode = 2;
					AppGlobals.WriteConsole("Handler::Error: " + ex.Message);
					TimeToStop = true;
				}
			}

			// finalize
			if (_listener != null)
			{
				try
				{
					_listener.Stop();
				}
				catch (Exception ex)
				{
					Console.WriteLine(ex);
				}
			}
			return retCode;
		}

		#endregion

		#region "settings"

		// loads/parses the config values
		private static void _LoadConfig()
		{
			// listen address
			IPAddress listenIp;
			var listenAddress = ConfigurationManager.AppSettings["ListenAddress"];
			if (String.IsNullOrEmpty(listenAddress))
				listenAddress = "127.0.0.1";
			if (false == IPAddress.TryParse(listenAddress, out listenIp))
			{
				listenAddress = "127.0.0.1";
				listenIp = IPAddress.Loopback;
			}

			// listen port
			var listenPort = int.Parse(ConfigurationManager.AppSettings["ListenPort"]);
			if ((listenPort < 1) || (listenPort > 65535))
				listenPort = 25;

			// receive timeout
			var receiveTimeout = int.Parse(ConfigurationManager.AppSettings["ReceiveTimeOut"]);
			if (receiveTimeout < 0)
				receiveTimeout = 0;

			// hostname (for the banner)
			var hostName = ConfigurationManager.AppSettings["HostName"];
			if (string.IsNullOrEmpty(hostName))
				hostName = Dns.GetHostEntry("").HostName;

			// true=emits a "tempfail" when receiving the DATA command
			var doTempFail = bool.Parse(ConfigurationManager.AppSettings["DoTempFail"]);

			// true=stores the email envelope and data into files
			var storeData = bool.Parse(ConfigurationManager.AppSettings["StoreData"]);

			// max size for a given email message
			var storeSize = long.Parse(ConfigurationManager.AppSettings["MaxDataSize"]);
			if (storeSize < 0)
				storeSize = 0;

			// max # of messages for a session
			var maxMsgs = int.Parse(ConfigurationManager.AppSettings["MaxMessages"]);
			if (maxMsgs < 1)
				maxMsgs = 10;

			// path for the email storage
			var storePath = ConfigurationManager.AppSettings["StorePath"];
			if (String.IsNullOrEmpty(storePath))
				storePath = Path.GetTempPath();
			if (!storePath.EndsWith("\\"))
				storePath = storePath + "\\";

			// max # of parallel sessions, further requests will be rejected
			var maxSessions = long.Parse(ConfigurationManager.AppSettings["MaxSessions"]);
			if (maxSessions < 1)
				maxSessions = 16;

			// path for the log file
			var logPath = ConfigurationManager.AppSettings["LogPath"];
			if (String.IsNullOrEmpty(logPath))
				logPath = Path.GetTempPath();
			if (!logPath.EndsWith("\\"))
				logPath = logPath + "\\";

			// verbose logging
			var verboseLog = bool.Parse(ConfigurationManager.AppSettings["VerboseLogging"]);

			// early talker detection
			var earlyTalk = bool.Parse(ConfigurationManager.AppSettings["DoEarlyTalk"]);

			// DNS whitelist providers, empty to not perform the check
			var whiteLists = ConfigurationManager.AppSettings["RWLproviders"];
			string[] rwl = null;
			if (!string.IsNullOrEmpty(whiteLists))
				rwl = whiteLists.Split(',');

			// DNS blacklist providers, empty to not perform the check
			var blackLists = ConfigurationManager.AppSettings["RBLproviders"];
			string[] rbl = null;
			if (!string.IsNullOrEmpty(blackLists))
				rbl = blackLists.Split(',');

			// hardlimits for errors, noop etc..
			var maxErrors = int.Parse(ConfigurationManager.AppSettings["MaxSmtpErrors"]);
			if (maxErrors < 1)
				maxErrors = 5;
			var maxNoop = int.Parse(ConfigurationManager.AppSettings["MaxSmtpNoop"]);
			if (maxNoop < 1)
				maxNoop = 7;
			var maxVrfy = int.Parse(ConfigurationManager.AppSettings["MaxSmtpVrfy"]);
			if (maxVrfy < 1)
				maxVrfy = 10;
			var maxRcpt = int.Parse(ConfigurationManager.AppSettings["MaxSmtpRcpt"]);
			if (maxRcpt < 1)
				maxRcpt = 100;

			// delays (tarpitting)
			var bannerDelay = int.Parse(ConfigurationManager.AppSettings["BannerDelay"]);
			if (bannerDelay < 0)
				bannerDelay = 0;
			var errorDelay = int.Parse(ConfigurationManager.AppSettings["ErrorDelay"]);
			if (errorDelay < 0)
				errorDelay = 0;

			// local domains and mailboxes
			var domains = new List<string>();
			var mailboxes = new List<string>();
			var fileName = ConfigurationManager.AppSettings["LocalDomains"];
			if (!string.IsNullOrEmpty(fileName))
				domains = AppGlobals.LoadFile(fileName);
			fileName = ConfigurationManager.AppSettings["LocalMailBoxes"];
			if (!string.IsNullOrEmpty(fileName))
				mailboxes = AppGlobals.LoadFile(fileName);

			// set the global values
			AppGlobals.ListenIp = listenIp;
			AppGlobals.ListenAddress = listenAddress;
			AppGlobals.ListenPort = listenPort;
			AppGlobals.ReceiveTimeout = receiveTimeout;
			AppGlobals.HostName = hostName.ToLower();
			AppGlobals.DoTempFail = doTempFail;
			AppGlobals.StoreData = storeData;
			AppGlobals.MaxDataSize = storeSize;
			AppGlobals.MaxMessages = maxMsgs;
			AppGlobals.StorePath = storePath;
			AppGlobals.MaxSessions = maxSessions;
			AppGlobals.LogPath = logPath;
			AppGlobals.LogVerbose = verboseLog;
			AppGlobals.EarlyTalkers = earlyTalk;
			AppGlobals.WhiteLists = rwl;
			AppGlobals.BlackLists = rbl;
			AppGlobals.MaxSmtpErr = maxErrors;
			AppGlobals.MaxSmtpNoop = maxNoop;
			AppGlobals.MaxSmtpVrfy = maxVrfy;
			AppGlobals.MaxSmtpRcpt = maxRcpt;
			AppGlobals.BannerDelay = bannerDelay;
			AppGlobals.ErrorDelay = errorDelay;
			AppGlobals.LocalDomains = domains;
			AppGlobals.LocalMailBoxes = mailboxes;
		}

		// dump the current settings
		private static void _DumpSettings()
		{
			// base/network
			AppGlobals.WriteConsole("Host name..................: {0}", AppGlobals.HostName);
			AppGlobals.WriteConsole("listen IP..................: {0}", AppGlobals.ListenAddress);
			AppGlobals.WriteConsole("listen port................: {0}", AppGlobals.ListenPort);
			AppGlobals.WriteConsole("Receive timeout............: {0}", AppGlobals.ReceiveTimeout);
			// hardlimits
			AppGlobals.WriteConsole("Max errors.................: {0}", AppGlobals.MaxSmtpErr);
			AppGlobals.WriteConsole("Max NOOP...................: {0}", AppGlobals.MaxSmtpNoop);
			AppGlobals.WriteConsole("Max VRFY/EXPN..............: {0}", AppGlobals.MaxSmtpVrfy);
			AppGlobals.WriteConsole("Max RCPT TO................: {0}", AppGlobals.MaxSmtpRcpt);
			// sessions
			AppGlobals.WriteConsole("Max messages per session...: {0}", AppGlobals.MaxMessages);
			AppGlobals.WriteConsole("Max parallel sessions......: {0}", AppGlobals.MaxSessions);
			// messages
			AppGlobals.WriteConsole("Store message data.........: {0}", AppGlobals.StoreData);
			AppGlobals.WriteConsole("Storage path...............: {0}", AppGlobals.StorePath);
			AppGlobals.WriteConsole("Max message size...........: {0}", AppGlobals.MaxDataSize);
			// logs
			AppGlobals.WriteConsole("Logfiles path..............: {0}", AppGlobals.LogPath);
			AppGlobals.WriteConsole("Verbose logging............: {0}", AppGlobals.LogVerbose);
			// tarpitting
			AppGlobals.WriteConsole("Initial banner delay.......: {0}", AppGlobals.BannerDelay);
			AppGlobals.WriteConsole("Error delay................: {0}", AppGlobals.ErrorDelay);
			// filtering/rejecting
			AppGlobals.WriteConsole("Do tempfail (4xx) on DATA..: {0}", AppGlobals.DoTempFail);
			AppGlobals.WriteConsole("Check for early talkers....: {0}", AppGlobals.EarlyTalkers);
			// DNS filtering
			AppGlobals.WriteConsole("DNS Whitelists.............: {0}", AppGlobals.WhiteLists.Length);
			AppGlobals.WriteConsole("DNS Blacklists.............: {0}", AppGlobals.BlackLists.Length);
			// local domains/mailboxes
			AppGlobals.WriteConsole("Local domains..............: {0}", AppGlobals.LocalDomains.Count);
			AppGlobals.WriteConsole("Local mailboxes............: {0}", AppGlobals.LocalMailBoxes.Count);
		}

		#endregion
	}
}
