using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace RunProcess
{
	class Program
	{
		static string _commandline = string.Empty;
		static string _args = string.Empty;
		static string _encKey = string.Empty;
		static void Main(string[] args)
		{			
			if (!File.Exists("config.json"))
			{
				Console.Error.WriteLine("config.json not found");
				Environment.Exit(0);
			}

			var configModel = JsonConvert.DeserializeObject<ConfigModel>(File.ReadAllText("config.json"));
			if (string.IsNullOrEmpty(configModel.CustomEncryptionKey) || configModel.CustomEncryptionKey.Length != 32)
			{
				Console.Error.WriteLine("Please set CustomEncryptionKey (length = 32 chars) and hash your password by using RunProcess.exe -hash <your_password> and copy the resulting hash in to the corresonding account in the config");
				Environment.Exit(0);
			}

			_commandline = configModel.ProcessPath;
			_args = configModel.AppArgs;
			_encKey = configModel.CustomEncryptionKey;

			if (args.Length == 2)
			{
				if (args[0].ToLower().Equals("-hash"))
				{
					Console.WriteLine(EncryptString(args[1]));
					Environment.Exit(0);
				}
			}
			
			foreach (var acc in configModel.Accounts)
			{
				if (string.IsNullOrEmpty(acc.PassHash))
				{
					Console.Error.WriteLine("Please Hash your password by using RunProcess.exe -hash <your_password> and copy the resulting hash in to the corresonding account in the config");
					Environment.Exit(0);
				}
				Console.WriteLine($"Executing {_commandline} for user {acc.UserName}");
				RunAs(acc.Domain, acc.UserName, DecryptString(acc.PassHash));
			}			
		}

		static void RunAs(string domain, string username, string password)
		{
			var process = new Process();
			var pwd = new SecureString();

			process.StartInfo.UseShellExecute = false;
			process.StartInfo.FileName = _commandline;
			process.StartInfo.Arguments = _args;
			process.StartInfo.Domain = domain;
			process.StartInfo.UserName = username;
			password.ToCharArray().ToList().ForEach(c =>
			{
				pwd.AppendChar(c);
			});
			process.StartInfo.Password = pwd;
			process.Start();
		}

		public static string EncryptString(string plainText)
		{
			string key = _encKey;
			byte[] iv = new byte[16];
			byte[] array;

			using (Aes aes = Aes.Create())
			{
				aes.Key = Encoding.UTF8.GetBytes(key);
				aes.IV = iv;

				ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

				using (MemoryStream memoryStream = new MemoryStream())
				{
					using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, encryptor, CryptoStreamMode.Write))
					{
						using (StreamWriter streamWriter = new StreamWriter((Stream) cryptoStream))
						{
							streamWriter.Write(plainText);
						}

						array = memoryStream.ToArray();
					}
				}
			}

			return Convert.ToBase64String(array);
		}

		public static string DecryptString(string cipherText)
		{
			string key = _encKey;
			byte[] iv = new byte[16];
			byte[] buffer = Convert.FromBase64String(cipherText);

			using (Aes aes = Aes.Create())
			{
				aes.Key = Encoding.UTF8.GetBytes(key);
				aes.IV = iv;
				ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

				using (MemoryStream memoryStream = new MemoryStream(buffer))
				{
					using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, decryptor, CryptoStreamMode.Read))
					{
						using (StreamReader streamReader = new StreamReader((Stream) cryptoStream))
						{
							return streamReader.ReadToEnd();
						}
					}
				}
			}
		}
	}

	class ConfigModel
	{
		internal class Account
		{
			public string Domain { get; set; }
			public string UserName { get; set; }
			public string PassHash { get; set; }
		}

		public string ProcessPath { get; set; }
		public string AppArgs { get; set; }
		public string CustomEncryptionKey { get; set; }
		public List<Account> Accounts { get; set; }
	}	
}
