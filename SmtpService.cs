using System;
using System.ServiceProcess;
using System.Threading;

namespace FakeSMTP
{
	public partial class SmtpService : ServiceBase
	{
		private readonly SmtpServer _server = new SmtpServer();
		private Thread _serverThread;

		public SmtpService()
		{
			InitializeComponent();
		}

		protected override void OnStart(string[] args)
		{
			_serverThread = new Thread(() => _server.Start());
			_serverThread.Start();
		}

		protected override void OnStop()
		{
			_server.TimeToStop = true;
			_serverThread.Join(TimeSpan.FromSeconds(10));
		}
	}
}
