using System;
using Zyborg.Security.Cryptography;

namespace servicecerts
{
    class Program
    {
        static int Main(string[] args) => 0;

        public void OnExecute()
        {
            var store = ServiceCertStore.OpenStore("foo", "bar");
        }
    }
}
