using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Configuration;
using System.IO;

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
    public class SMTPServer
    {
        #region "privatedata"
        private static bool         timeToStop = false;
        private static TcpListener  listener = null;
        #endregion

        #region "entrypoint"
        // main entry point
        static int Main(string[] args)
        {
            // our internal stuff
            IPAddress listenAddr = IPAddress.Loopback;
            int listenPort = 25;
            int retCode = 0;

            // load the config
            loadConfig();

            // tell we're starting up and, if verbose, dump config parameters
            AppGlobals.writeConsole("{0} {1} starting up (NET {2})", AppGlobals.appName, AppGlobals.appVersion, AppGlobals.appRuntime);
            if (AppGlobals.logVerbose)
                dumpSettings();            

            // setup the listening IP:port
            listenAddr = AppGlobals.listenIP;
            listenPort = AppGlobals.listenPort;

            // try starting the listener
            try
            {
                listener = new TcpListener(listenAddr, listenPort);
                listener.Start();
            }
            catch (Exception ex)
            {
                AppGlobals.writeConsole("Listener::Error: " + ex.Message);
                return 1;
            }

            // tell we're ready to accept connections
            AppGlobals.writeConsole("Listening for connections on {0}:{1}", listenAddr, listenPort);

            // run until interrupted (Ctrl-C in our case)
            while (!timeToStop)
            {
                try
                {
                    // wait for an incoming connection, accept it and spawn a thread to handle it
                    SMTPsession handler = new SMTPsession(listener.AcceptTcpClient());
                    Thread thread = new System.Threading.Thread(new ThreadStart(handler.handleSession));
                    thread.Start();
                }
                catch (Exception ex)
                {
                    // we got an error
                    retCode = 2;
                    AppGlobals.writeConsole("Handler::Error: " + ex.Message);
                    timeToStop = true;
                }
            }

            // finalize
            if (null != listener)
            {
                try { listener.Stop(); }
                catch { }
            }
            return retCode;
        }
        #endregion

        #region "settings"
        // loads/parses the config values
        static void loadConfig()
        {
            // listen address
            IPAddress listenIP = IPAddress.Loopback;
            string listenAddress = ConfigurationManager.AppSettings["ListenAddress"];
            if (String.IsNullOrEmpty(listenAddress)) listenAddress = "127.0.0.1";
            if (false == IPAddress.TryParse(listenAddress, out listenIP))
            {
                listenAddress = "127.0.0.1";
                listenIP = IPAddress.Loopback;
            }

            // listen port
            int listenPort = int.Parse(ConfigurationManager.AppSettings["ListenPort"]);
            if ((listenPort < 1) || (listenPort > 65535))
                listenPort = 25;

            // receive timeout
            int receiveTimeout = int.Parse(ConfigurationManager.AppSettings["ReceiveTimeOut"]);
            if (receiveTimeout < 0)
                receiveTimeout = 0;

            // hostname (for the banner)
            string hostName = ConfigurationManager.AppSettings["HostName"];
            if (string.IsNullOrEmpty(hostName))
                hostName = System.Net.Dns.GetHostEntry("").HostName;

            // true=emits a "tempfail" when receiving the DATA command
            bool doTempFail = bool.Parse(ConfigurationManager.AppSettings["DoTempFail"]);

            // true=stores the email envelope and data into files
            bool storeData = bool.Parse(ConfigurationManager.AppSettings["StoreData"]);

            // max size for a given email message
            long storeSize = long.Parse(ConfigurationManager.AppSettings["MaxDataSize"]);
            if (storeSize < 0) storeSize = 0;

            // max # of messages for a session
            int maxMsgs = int.Parse(ConfigurationManager.AppSettings["MaxMessages"]);
            if (maxMsgs < 1) maxMsgs = 10;

            // path for the email storage
            string storePath = ConfigurationManager.AppSettings["StorePath"];
            if (String.IsNullOrEmpty(storePath))
                storePath = Path.GetTempPath();
            if (!storePath.EndsWith("\\"))
                storePath = storePath + "\\";

            // max # of parallel sessions, further requests will be rejected
            long maxSessions = long.Parse(ConfigurationManager.AppSettings["MaxSessions"]);
            if (maxSessions < 1) maxSessions = 16;

            // path for the log file
            string logPath = ConfigurationManager.AppSettings["LogPath"];
            if (String.IsNullOrEmpty(logPath))
                logPath = Path.GetTempPath();
            if (!logPath.EndsWith("\\"))
                logPath = logPath + "\\";

            // verbose logging
            bool verboseLog = bool.Parse(ConfigurationManager.AppSettings["VerboseLogging"]);

            // early talker detection
            bool earlyTalk = bool.Parse(ConfigurationManager.AppSettings["DoEarlyTalk"]);

            // DNS whitelist providers, empty to not perform the check
            string whiteLists = ConfigurationManager.AppSettings["RWLproviders"];
            string[] RWL = null;
            if (!string.IsNullOrEmpty(whiteLists))
            {
                RWL = whiteLists.Split(',');
            }

            // DNS blacklist providers, empty to not perform the check
            string blackLists = ConfigurationManager.AppSettings["RBLproviders"];
            string[] RBL = null;
            if (!string.IsNullOrEmpty(blackLists))
            {
                RBL = blackLists.Split(',');
            }

            // hardlimits for errors, noop etc..
            int maxErrors = int.Parse(ConfigurationManager.AppSettings["MaxSmtpErrors"]);
            if (maxErrors < 1) maxErrors = 5;
            int maxNoop = int.Parse(ConfigurationManager.AppSettings["MaxSmtpNoop"]);
            if (maxNoop < 1) maxNoop = 7;
            int maxVrfy = int.Parse(ConfigurationManager.AppSettings["MaxSmtpVrfy"]);
            if (maxVrfy < 1) maxVrfy = 10;
            int maxRcpt = int.Parse(ConfigurationManager.AppSettings["MaxSmtpRcpt"]);
            if (maxRcpt < 1) maxRcpt = 100;

            // delays (tarpitting)
            int bannerDelay = int.Parse(ConfigurationManager.AppSettings["BannerDelay"]);
            if (bannerDelay < 0) bannerDelay = 0;
            int errorDelay = int.Parse(ConfigurationManager.AppSettings["ErrorDelay"]);
            if (errorDelay < 0) errorDelay = 0;

            // local domains and mailboxes
            List<string> domains = new List<string>();
            List<string> mailboxes = new List<string>();
            string fileName = ConfigurationManager.AppSettings["LocalDomains"];
            if (!string.IsNullOrEmpty(fileName))
                domains = AppGlobals.loadFile(fileName);
            fileName = ConfigurationManager.AppSettings["LocalMailBoxes"];
            if (!string.IsNullOrEmpty(fileName))
                mailboxes = AppGlobals.loadFile(fileName);

            // set the global values
            AppGlobals.listenIP = listenIP;
            AppGlobals.listenAddress = listenAddress;
            AppGlobals.listenPort = listenPort;
            AppGlobals.receiveTimeout = receiveTimeout;
            AppGlobals.hostName = hostName.ToLower();
            AppGlobals.doTempFail = doTempFail;
            AppGlobals.storeData = storeData;
            AppGlobals.maxDataSize = storeSize;
            AppGlobals.maxMessages = maxMsgs;
            AppGlobals.storePath = storePath;
            AppGlobals.maxSessions = maxSessions;
            AppGlobals.logPath = logPath;
            AppGlobals.logVerbose = verboseLog;
            AppGlobals.earlyTalkers = earlyTalk;
            AppGlobals.whiteLists = RWL;
            AppGlobals.blackLists = RBL;
            AppGlobals.maxSmtpErr = maxErrors;
            AppGlobals.maxSmtpNoop = maxNoop;
            AppGlobals.maxSmtpVrfy = maxVrfy;
            AppGlobals.maxSmtpRcpt = maxRcpt;
            AppGlobals.bannerDelay = bannerDelay;
            AppGlobals.errorDelay = errorDelay;
            AppGlobals.LocalDomains = domains;
            AppGlobals.LocalMailBoxes = mailboxes;
        }

        // dump the current settings
        private static void dumpSettings()
        {
            // base/network
            AppGlobals.writeConsole("Host name..................: {0}", AppGlobals.hostName);
            AppGlobals.writeConsole("listen IP..................: {0}", AppGlobals.listenAddress);
            AppGlobals.writeConsole("listen port................: {0}", AppGlobals.listenPort);
            AppGlobals.writeConsole("Receive timeout............: {0}", AppGlobals.receiveTimeout);
            // hardlimits
            AppGlobals.writeConsole("Max errors.................: {0}", AppGlobals.maxSmtpErr);
            AppGlobals.writeConsole("Max NOOP...................: {0}", AppGlobals.maxSmtpNoop);
            AppGlobals.writeConsole("Max VRFY/EXPN..............: {0}", AppGlobals.maxSmtpVrfy);
            AppGlobals.writeConsole("Max RCPT TO................: {0}", AppGlobals.maxSmtpRcpt);
            // sessions
            AppGlobals.writeConsole("Max messages per session...: {0}", AppGlobals.maxMessages);
            AppGlobals.writeConsole("Max parallel sessions......: {0}", AppGlobals.maxSessions);
            // messages
            AppGlobals.writeConsole("Store message data.........: {0}", AppGlobals.storeData);
            AppGlobals.writeConsole("Storage path...............: {0}", AppGlobals.storePath);
            AppGlobals.writeConsole("Max message size...........: {0}", AppGlobals.maxDataSize);
            // logs
            AppGlobals.writeConsole("Logfiles path..............: {0}", AppGlobals.logPath);
            AppGlobals.writeConsole("Verbose logging............: {0}", AppGlobals.logVerbose);
            // tarpitting
            AppGlobals.writeConsole("Initial banner delay.......: {0}", AppGlobals.bannerDelay);
            AppGlobals.writeConsole("Error delay................: {0}", AppGlobals.errorDelay);
            // filtering/rejecting
            AppGlobals.writeConsole("Do tempfail (4xx) on DATA..: {0}", AppGlobals.doTempFail);
            AppGlobals.writeConsole("Check for early talkers....: {0}", AppGlobals.earlyTalkers);
            // DNS filtering
            AppGlobals.writeConsole("DNS Whitelists.............: {0}", AppGlobals.whiteLists.Length);
            AppGlobals.writeConsole("DNS Blacklists.............: {0}", AppGlobals.blackLists.Length);
            // local domains/mailboxes
            AppGlobals.writeConsole("Local domains..............: {0}", AppGlobals.LocalDomains.Count);
            AppGlobals.writeConsole("Local mailboxes............: {0}", AppGlobals.LocalMailBoxes.Count);
        }
        #endregion
    }

}
