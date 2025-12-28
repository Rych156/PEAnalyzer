using System;

namespace PEAnalyzer.Pe
{
    internal sealed class PeFormatException : Exception
    {
        public PeFormatException(string message) : base(message)
        {
        }

        public PeFormatException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}

