 using System;
 using System.Collections.Generic;
 using System.Diagnostics;
 using System.Net;
 using System.IO;
 
 namespace FakeSMTP
 {
     public static class AppGlobals
     {
         #region "privateData"
         private static IPAddress    _listenIP = IPAddress.Loopback;
 
         private static string       _listenAddress = null;
         private static int          _listenPort = 0;
         private static int          _receiveTimeout = 0;
         private static string       _hostName = null;
         private static bool         _doTempFail = false;
         private static string       _logPath = null;
         private static bool         _verboseLog = false;
         private static long         _maxSessions = 0;
         private static int          _maxMessages = 0;
         private static bool         _storeData = false;
         private static long         _maxDataSize = 0;
         private static string       _storePath = null;
         private static bool         _earlyTalk = false;
         private static string[]     _whiteLists = null;
         private static string[]     _blackLists = null;
         private static int          _maxSmtpErr = 0;
         private static int          _maxSmtpNoop = 0;
         private static int          _maxSmtpVrfy = 0;
         private static int          _maxSmtpRcpt = 0;
         private static int          _bannerDelay = 0;
         private static int          _errorDelay = 0;
 
         private static List<string> _localDomains = null;
         private static List<string> _localMailBoxes = null;        
 
         // sessions count
         private static object       _lkSessions = new object();
         private static long         _sessions = 0;
 
         private static object       _lkSessID = new object();
         private static long         _sessID = 0;
 
         private static object       _lkAppLog = new object();
         private static object       _lkSesLog = new object();
         #endregion
 
         #region "properties"
         // application name
         public static string appName
         {
             get
             {
                 return System.Reflection.Assembly.GetExecutingAssembly().GetName().Name;
             }
         }
 
         // application version
         public static string appVersion
         {
             get
             {
                 return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
             }
         }
 
         // runtime version
         public static string appRuntime
         {
             get
             {
                 return System.Reflection.Assembly.GetExecutingAssembly().ImageRuntimeVersion;
             }
         }
         
         // listen IP
         public static IPAddress listenIP
         {
             get { return _listenIP; }
             set { _listenIP = value; }
         }
 
         // listen address (as a string)
         public static string listenAddress
         {
             get { return _listenAddress; }
             set { _listenAddress = value; }
         }
 
         // listen port
         public static int listenPort
         {
             get { return _listenPort; }
             set { _listenPort = value; }
         }
 
         // timeout for receiving commands/data (milliseconds)
         public static int receiveTimeout
         {
             get { return _receiveTimeout; }
             set { _receiveTimeout = value; }
         }
 
         // host name (used for banner, if blank retrieved from network settings)
         public static string hostName
         {
             get { return _hostName; }
             set { _hostName = value; }
         }
 
         // true = terminate sessions with a 4xx temporary failure
         public static bool doTempFail
         {
             get { return _doTempFail; }
             set { _doTempFail = value; }
         }
 
         // path for log file(s)
         public static string logPath
         {
             get { return _logPath; }
             set { _logPath = value; }
         }
 
         // verbose logging
         public static bool logVerbose
         {
             get { return _verboseLog; }
             set { _verboseLog = value; }
         }
 
         // max # of parallel sessions allowed
         public static long maxSessions
         {
             get { return _maxSessions; }
             set { _maxSessions = value; }
         }
 
         // max # of messages in a single session
         public static int maxMessages
         {
             get { return _maxMessages; }
             set { _maxMessages = value; }
         }
 
         // true = store the email envelope/mime data to files
         public static bool storeData
         {
             get { return _storeData; }
             set { _storeData = value; }
         }
 
         // max size for a given mail message (DATA)
         public static long maxDataSize
         {
             get { return _maxDataSize; }
             set { _maxDataSize = value; }
         }
 
         // path to store the mail data
         public static string storePath
         {
             get { return _storePath; }
             set { _storePath = value; }
         }
 
         // early talkers check
         public static bool earlyTalkers
         {
             get { return _earlyTalk; }
             set { _earlyTalk = value; }
         }
 
         // whitelist to check incoming IPs
         public static string[] whiteLists
         {
             get { return _whiteLists; }
             set { _whiteLists = value; }
         }
 
         // blacklists to check incoming IPs
         public static string[] blackLists
         {
             get { return _blackLists; }
             set { _blackLists = value; }
         }
 
         // max # of smtp errors for a session
         public static int maxSmtpErr
         {
             get { return _maxSmtpErr; }
             set { _maxSmtpErr = value; }
         }
 
         // max # of smtp NOOP commands for a session
         public static int maxSmtpNoop
         {
             get { return _maxSmtpNoop; }
             set { _maxSmtpNoop = value; }
         }
 
         // max # of smtp VRFY commands for a session
         public static int maxSmtpVrfy
         {
             get { return _maxSmtpVrfy; }
             set { _maxSmtpVrfy = value; }
         }
 
         // max # of smtp RCPT TO for a session
         public static int maxSmtpRcpt
         {
             get { return _maxSmtpRcpt; }
             set { _maxSmtpRcpt = value; }
         }
 
         // delay before emitting the banner
         public static int bannerDelay
         {
             get { return _bannerDelay; }
             set { _bannerDelay = value; }
         }
 
         // delay for responses after errors
         public static int errorDelay
         {
             get { return _errorDelay; }
             set { _errorDelay = value; }
         }
 
         // locally handled domains
         public static List<string> LocalDomains
         {
             get { return _localDomains; }
             set { _localDomains = value; }
         }
 
         // locally handled mailboxes
         public static List<string> LocalMailBoxes
         {
             get { return _localMailBoxes; }
             set { _localMailBoxes = value; }
         }
 
         #endregion
 
         #region "methods"
         // increase the global session count
         public static long addSession()
         {
             long ret;
 
             lock (_lkSessions)
             {
                 ret = ++_sessions;
             }
             return ret;
         }
 
         // decrease the global session count
         public static long removeSession()
         {
             long ret;
             lock (_lkSessions)
             {
                 if (--_sessions < 0) _sessions = 0;
                 ret = _sessions;
             }
             return ret;
         }
 
         // get a session ID#
         public static string sessionID()
         {
             string ret;
 
             lock (_lkSessID)
             {
                 if (_sessID == long.MaxValue) _sessID = 0;
                 ret = string.Format("{0:X}{1:X}", DateTime.Now.Ticks, ++_sessID);
             }
             return ret;
         }
 
         // writes a message to console
         public static void writeConsole(string format, params object[] args)
         {
             try {
                 Debug.WriteLine(string.Format(format, args));
                 logMessage(format, args);
                 Console.Out.WriteLine(DateTime.UtcNow.ToString("HH:mm:ss.ffff") + " " + String.Format(format, args)); 
             }
             catch (Exception ex) 
             { 
                 Debug.WriteLine("writeConsole::Exception: " + ex.Message);
             }
         }
 
         // writes a message to the log file
         public static void logMessage(string format, params object[] args)
         {
             lock (_lkAppLog)
             {
                 try
                 {
                     Debug.WriteLine(string.Format(format, args));
                     string logFile = _logPath + "fakesmtp-" + DateTime.UtcNow.ToString("MM") + ".log";
                     rollFile(logFile);
                     StreamWriter fp = new StreamWriter(logFile, true);
                     fp.WriteLine(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " " + string.Format(format, args));
                     fp.Flush();
                     fp.Close();
                 }
                 catch (Exception ex)
                 {
                     Debug.WriteLine("logMessage::Exception: " + ex.Message);
                 }
             }
         }
 
         // writes a session record to the log file
         public static void logSession(string format, params object[] args)
         {
             lock (_lkSesLog)
             {
                 try
                 {
                     Debug.WriteLine(string.Format(format, args));
                     string logFile = _logPath + "smtpsess-" + DateTime.UtcNow.ToString("MM") + ".log";
                     rollFile(logFile);
                     StreamWriter fp = new StreamWriter(logFile, true);
                     fp.WriteLine(string.Format(format, args));
                     fp.Flush();
                     fp.Close();
                 }
                 catch (Exception ex)
                 {
                     writeConsole("logSession::Exception: {0}", ex.Message);
                 }
             }
         }
 
         // loads a text file and returns it as a string list
         public static List<string> loadFile(string fileName)
         {
             List<string> lines = new List<string>();
             try
             {
                 StreamReader fp = new StreamReader(fileName);
                 string buffer = null;
                 while (null != (buffer = fp.ReadLine()))
                 {
                     // skip empty lines and comment lines (#=comment sign)
                     if (!string.IsNullOrEmpty(buffer))
                         if (!buffer.StartsWith("#"))
                             lines.Add(buffer);
                 }
                 fp.Close();
             }
             catch
             {
                 lines = new List<string>();
             }
             return lines;
         }
         #endregion
 
         #region "privatecode"
         // checks if a file needs "rolling"
         private static void rollFile(string pathName)
         {
             try
             {
                 if (File.Exists(pathName))
                 {
                     DateTime lastWrite = File.GetLastWriteTime(pathName);
                     if (!DateTime.Now.Year.Equals(lastWrite.Year))
                     {
                         File.Delete(pathName);
                     }
 
                 }
             }
             catch (Exception ex)
             {
                 Debug.WriteLine("rollFile::Exception: " + ex.Message);
             }
         }
         #endregion
     }
 }
