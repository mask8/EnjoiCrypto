using System;

using System.Reflection;

using System.IO;

namespace Test
{
	class Test
	{
		[STAThread]
		static void Main(string[] args)
		{
			Console.WriteLine ("Full path of the executing file name: ");
			Console.WriteLine (Assembly.GetExecutingAssembly().Location);

			Console.WriteLine ("Directory path of the executing file name: ");
			Console.WriteLine (Path.GetDirectoryName (Assembly.GetExecutingAssembly().Location));

			Console.WriteLine ("File name of the executing file name: ");
			Console.WriteLine (Path.GetFileName (Assembly.GetExecutingAssembly().Location));

			Console.WriteLine ("Temporary file name path: ");
			Console.WriteLine (Path.GetTempFileName ());

		}
	}
}