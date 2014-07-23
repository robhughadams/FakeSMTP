using System.ServiceProcess;

namespace FakeSMTP
{
	internal static class Program
	{
		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		public static int Main(string[] args)
		{
			if (args.Length <= 0 || !args[0].StartsWith("/d"))
			{
				var servicesToRun = new ServiceBase[]
				{
					new SmtpService()
				};
				ServiceBase.Run(servicesToRun);
				return 0;
			}

			var server = new SmtpServer();
			return server.Start();
		}
	}
}
