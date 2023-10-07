using System;
using System.Security.Cryptography;

namespace Klinkby.Security;

internal static class RndGen
{
    [ThreadStatic] private static RNGCryptoServiceProvider? _rnd;

    internal static RNGCryptoServiceProvider Random => _rnd ?? (_rnd = new RNGCryptoServiceProvider());
}