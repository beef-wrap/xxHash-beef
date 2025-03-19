using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Interop;
using System.Text;

using static xxHash.xxHash;

namespace example;

static class Program
{
	static int Main(params String[] args)
	{
		let hash32 = XXH32("test", 4, 0);
		Debug.WriteLine($"{hash32}");

		let hash64 = XXH64("test", 4, 0);
		Debug.WriteLine($"{hash64}");

		return 0;
	}
}