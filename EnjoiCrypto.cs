using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Resources;
using System.CodeDom.Compiler;
using Microsoft.CSharp;

namespace EnjoiCrypto
{
	/// <summary>
	/// 
	/// </summary>
	class EnjoiCrypto
	{
		/// <summary>
		/// 
		/// </summary>
		[STAThread]
		static void Main(string[] args)
		{
			string strInFilePath	= string.Empty;
			string strOutFilePath	= string.Empty;
			string strPass1			= string.Empty;
			string strPass2			= string.Empty;
			string strHash			= string.Empty;

			FileStream fsInput = null;

			int totalEncrBytes = 0;
			byte[] encrData = null;

			bool blError = false;

			//========================================================
			// get the file information and chech to see if it exists.
			//========================================================

			Console.Write ("Please input the file name or drag and drop the file here for crypto: ");
			strInFilePath = Console.ReadLine ();
            strInFilePath = strInFilePath.Trim("\"".ToCharArray());
			try
			{
				fsInput = new FileStream (strInFilePath, FileMode.Open, FileAccess.Read);
			}
			catch (Exception e)
			{
				Console.WriteLine (e.Message);
				return;
			}

			//============================================
			// get the output file and check if it exists.
			//============================================

			while (true)
			{
				Console.Write ("Please output the file name for decrypto: ");
				strOutFilePath = Console.ReadLine ();

				if (! strOutFilePath.EndsWith (".exe"))
				{
					Console.WriteLine ("Please input the file name with a suffix \".exe\".");
					continue;
				}

				if (File.Exists (strOutFilePath))
				{
					Console.Write ("Override, OK? [y/n]: ");
					if (Console.ReadLine () == "y")
					{
						break;
					}
				}
				else
				{
					break;
				}
			}

			//====================================
			// get the passwords and validate them 
			//====================================

			while (true)
			{
				Console.Write ("Please type the password: ");
				strPass1 = EnjoiCrypto.ReadPasswordLine ();
				Console.Write ("Please retype the password to confirm: ");
				strPass2 = EnjoiCrypto.ReadPasswordLine ();
				if (strPass1 == "" || strPass1 != strPass2)
				{
					Console.Write ("Password did not match.");
				}
				else
				{
					break;
				}
			}
			strHash = computeHashSHA512 (strPass1, null);

			//===============================================
			// create the byte array of the password and salt
			//===============================================

            byte[] salt = createRandomSalt(13);

			//===========================================
			// initialize Service Provider for Triple DES
			//===========================================

			byte[] Key = null, IV = null;
			SymmetricAlgorithm symalg = null;

			try
			{

				//======================================
				// create a key from PasswordDeriveBytes
				//======================================

				Console.WriteLine("Creating a key...");
				
				PasswordDeriveBytes pdb = new PasswordDeriveBytes(strPass1, salt, "SHA512", 100);
				Key = pdb.GetBytes (32);
				IV = pdb.GetBytes (16);
				symalg = SymmetricAlgorithm.Create ("Rijndael");
				ICryptoTransform encryptor = symalg.CreateEncryptor (Key, IV);

				//=========
				// encrypto
				//=========

				Console.Write ("Input file size: ");
				Console.WriteLine (fsInput.Length);
				Console.Write ("Encrypto output block size: ");
				Console.WriteLine (encryptor.OutputBlockSize);
            	Console.WriteLine("Encryting...");

				CryptoStream cryptStream = new CryptoStream (fsInput, encryptor, CryptoStreamMode.Read);
				encrData = new byte[fsInput.Length + encryptor.OutputBlockSize];
				int readBlockSize = encryptor.OutputBlockSize * 1000;

				for (int BytesRead = 0; totalEncrBytes < encrData.Length; totalEncrBytes += BytesRead)
				{
					if (totalEncrBytes + readBlockSize > encrData.Length)
					{
						readBlockSize = encrData.Length - totalEncrBytes;
					}
					BytesRead = cryptStream.Read (encrData, totalEncrBytes, readBlockSize);
					if (BytesRead == 0)
					{
						break;
					}
				}
				
				encryptor.Dispose();
				cryptStream.Clear();
				cryptStream.Close();
				symalg.Clear();
            }
            catch (Exception e)
	        {
	            Console.WriteLine(e.Message);
	            blError = true;
	        }
	        finally
	        {
                // Clear the key.
				Array.Clear (Key, 0, Key.Length);
				Array.Clear (IV, 0, IV.Length);

				// Close the file
				fsInput.Close ();
			}

			if (blError)
			{
				return;
			}

			//===========================================
			// create a resource file for executable file
			//===========================================

			string strRsrcFile = Path.GetTempFileName ();
			string strInputFileName = Path.GetFileName (strInFilePath);
            ResourceWriter resWriter = new ResourceWriter(strRsrcFile);

			Console.Write ("Resource file name: ");
			Console.WriteLine (strRsrcFile);
			Console.Write ("Total encrypting file size: ");
			Console.WriteLine (totalEncrBytes);
			Console.Write("Salt size: ");
			Console.WriteLine(salt.Length);
			Console.WriteLine("Creating a resource file...");

			resWriter.AddResource ("1", strHash);
			resWriter.AddResource ("2", salt);
			resWriter.AddResource ("3", strInputFileName);
            resWriter.AddResource("4", totalEncrBytes);
            resWriter.AddResource("5", encrData);

			resWriter.Generate();
			resWriter.Dispose();

			Console.WriteLine ("Creating an assemble...");
			BuildDecryptorAssembly (strRsrcFile, strOutFilePath);

			// delete resource file
			Console.WriteLine ("Finalizing...");
			File.Delete (strRsrcFile);
			Array.Clear (IV, 0, IV.Length);
			Array.Clear (salt, 0, salt.Length);
		}

		///
		///
		///
		private static void BuildDecryptorAssembly(string strRsrcFile, string strOutFileName)
		{
			CSharpCodeProvider csprov = new CSharpCodeProvider();
			ICodeCompiler compiler = csprov.CreateCompiler();
			CompilerParameters compilerparams = new CompilerParameters(new string[] {"System.dll"}, strOutFileName, false);
            compilerparams.ReferencedAssemblies.Add("System.Security.dll");
            compilerparams.GenerateExecutable = true;
			compilerparams.CompilerOptions = "/target:exe /resource:\""+ strRsrcFile + "\",encrypted";

			try
			{
				#region Embeded Source

                CompilerResults cr = compiler.CompileAssemblyFromSource (compilerparams,
@"using System;
using System.Text;
using System.Resources;
using System.IO;
using System.Reflection;
using System.Collections;
using System.Security.Cryptography;

namespace EnjoiDecrypto
{
	class EnjoiDecrypto
	{
		[STAThread]
		static void Main(string[] args)
		{
			string strHash = string.Empty;
			string strFileTitle = string.Empty;
			int totalEncrBytes = 0;
			byte[] salt = null;
			byte[] encrData = null;
			string strPassword = string.Empty;
" +
"			Console.Write (\"Input the password: \");" + 
@"			strPassword = EnjoiDecrypto.ReadPasswordLine ();
" +
"			Stream resStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(\"encrypted\");" +
@"			ResourceReader resRdr = new ResourceReader (resStream);
			foreach (DictionaryEntry entry in resRdr)
			{
				string resID = (string)entry.Key;
				switch (resID)
				{" +
"					case \"1\":" +
@"						strHash = (string)entry.Value;
						break;" +
"					case \"2\":" +
@"						salt = (byte[])entry.Value;
						break;" +
"					case \"3\":" +
@"						strFileTitle = (string)entry.Value;
						break;" +
"					case \"4\":" +
@"						totalEncrBytes = (int)entry.Value;
						break;" +
"					case \"5\":" +
@"					encrData = (byte[]) entry.Value;
					break;
				}
			}

			if (! verifyHashSHA512 (strPassword, strHash))
			{" +
"				Console.WriteLine (\"The password isn't much\");" +
@"				return;
			}

			if (File.Exists (strFileTitle))
			{" +
"				Console.WriteLine (\"File exists. Couldn't make file \\\"{0}\\\".\", strFileTitle);" +
@"				return;
			}
" +
"			Console.Write (\"File name: \");" +
@"			Console.WriteLine (strFileTitle);" +
"			Console.Write (\"Encripto file size: \");" +
@"			Console.WriteLine (totalEncrBytes);" +
"           Console.Write(\"Encripto real size: \");" +
@"          Console.WriteLine(encrData.Length);" +
"           Console.Write(\"Salt size: \");" +
@"          Console.WriteLine(salt.Length);

			byte[] pswd = Encoding.Unicode.GetBytes (strPassword);
			byte[] Key = null, IV = null;" +
"           PasswordDeriveBytes pdb = new PasswordDeriveBytes(strPassword, salt, \"SHA512\", 100);" +
"			Key = pdb.GetBytes (32);" +
"			IV = pdb.GetBytes (16);" +
"			SymmetricAlgorithm symalg = SymmetricAlgorithm.Create (\"Rijndael\");" +
@"			ICryptoTransform decryptor = symalg.CreateDecryptor (Key, IV);
			Array.Clear (Key, 0, Key.Length);
			Array.Clear (IV, 0, IV.Length);
" +
"			Console.WriteLine (\"Decripting...\");" +
@"
			Stream outStream = new FileStream (strFileTitle, FileMode.CreateNew, FileAccess.Write);
			CryptoStream cryptStream = new CryptoStream (outStream, decryptor, CryptoStreamMode.Write);
			cryptStream.Write(encrData, 0, totalEncrBytes);
			cryptStream.FlushFinalBlock();
			cryptStream.Clear();
			cryptStream.Close();
			outStream.Close();
			decryptor.Dispose();
			symalg.Clear();
		}

		private static bool verifyHashSHA512 (string strPass, string strHash)
		{
			byte[] hashWithSaltBytes = Convert.FromBase64String (strHash);
			byte[] saltBytes = new byte[hashWithSaltBytes.Length - 512 / 8];
			Array.Copy (hashWithSaltBytes, 512 / 8, saltBytes, 0, saltBytes.Length);
			string strExpectedHash = computeHashSHA512 (strPass, saltBytes);

			return (strHash == strExpectedHash);
		}

		private static string computeHashSHA512 (string strPass, byte[] saltBytes)
		{
			byte[] plainTextBytes = Encoding.UTF8.GetBytes (strPass);
			byte[] plainTextWithSaltBytes = new byte[plainTextBytes.Length + saltBytes.Length];

			// Copy plain text bytes into resulting array.
			Array.Copy (plainTextBytes, plainTextWithSaltBytes, plainTextBytes.Length);
			Array.Copy (saltBytes, 0, plainTextWithSaltBytes, plainTextBytes.Length, saltBytes.Length);

			HashAlgorithm hash = new SHA512Managed ();
			byte[] hashBytes = hash.ComputeHash(plainTextWithSaltBytes);
			byte[] hashWithSaltBytes = new byte[hashBytes.Length + saltBytes.Length];
			Array.Copy (hashBytes, hashWithSaltBytes, hashBytes.Length);
			Array.Copy (saltBytes, 0, hashWithSaltBytes, hashBytes.Length, saltBytes.Length);
			string hashValue = Convert.ToBase64String (hashWithSaltBytes);

			return hashValue;
		}

		private static string ReadPasswordLine ()
		{
			StringBuilder sb = new StringBuilder();
			while (true)
			{
				System.ConsoleKeyInfo cki = Console.ReadKey(true);
				if (cki.Key == ConsoleKey.Enter)
				{
					Console.WriteLine();
					break;
				}

				if (cki.Key == ConsoleKey.Backspace)
				{
					if (sb.Length > 0)
					{" +
"						Console.Write (\"\\b\\0\\b\");" +
@"						sb.Length--;
					}
					continue;
				}
				Console.Write('*');
				sb.Append (cki.KeyChar);
			}
			return sb.ToString();
		}
	}
}");
				#endregion
			}
			catch (Exception e)
			{
				Console.WriteLine (e.Message);
			}
		}


		///
		///
		///
		private static string ReadPasswordLine ()
		{
			StringBuilder sb = new StringBuilder();
			while (true)
			{
				System.ConsoleKeyInfo cki = Console.ReadKey(true);
				if (cki.Key == ConsoleKey.Enter)
				{
					Console.WriteLine();
					break;
				}

				if (cki.Key == ConsoleKey.Backspace)
				{
					if (sb.Length > 0)
					{
						Console.Write ("\b\0\b");
						sb.Length--;
					}
					continue;
				}
				Console.Write('*');
				sb.Append (cki.KeyChar);
			}
			return sb.ToString();
		}

		///
		///
		///
		public static byte[] createRandomSalt(int Length)
		{
			// Create a buffer
			byte[] randBytes;
			
			if (Length >= 1)
			{
			    randBytes = new byte[Length];
			}
			else
			{
			    randBytes = new byte[1];
			}
			
			// Create a new RNGCryptoServiceProvider.
			RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();
			
			// Fill the buffer with random bytes.
			rand.GetBytes(randBytes);
			
			// return the bytes.
			return randBytes;
		}

		///
		///
		///
		public static string computeHashSHA512 (string strPass, byte[] saltBytes)
		{
			if (saltBytes == null)
			{
				Random random = new Random();
				int saltSize = random.Next (4, 8);
				saltBytes = createRandomSalt (saltSize);
			}

			byte[] plainTextBytes = Encoding.UTF8.GetBytes (strPass);
			byte[] plainTextWithSaltBytes = new byte[plainTextBytes.Length + saltBytes.Length];

			// Copy plain text bytes into resulting array.
			Array.Copy (plainTextBytes, plainTextWithSaltBytes, plainTextBytes.Length);
			Array.Copy (saltBytes, 0, plainTextWithSaltBytes, plainTextBytes.Length, saltBytes.Length);

			HashAlgorithm hash = new SHA512Managed ();
			byte[] hashBytes = hash.ComputeHash(plainTextWithSaltBytes);
			byte[] hashWithSaltBytes = new byte[hashBytes.Length + saltBytes.Length];
			Array.Copy (hashBytes, hashWithSaltBytes, hashBytes.Length);
			Array.Copy (saltBytes, 0, hashWithSaltBytes, hashBytes.Length, saltBytes.Length);
			string hashValue = Convert.ToBase64String (hashWithSaltBytes);

			return hashValue;
		}
	}
}
