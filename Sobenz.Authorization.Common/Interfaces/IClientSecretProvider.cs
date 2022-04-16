using System;

namespace Sobenz.Authorization.Common.Interfaces
{
    public interface IClientSecretProvider
    {
        string Generate(out string hash);
        bool Validate(string secret, string hash);
    }
}
