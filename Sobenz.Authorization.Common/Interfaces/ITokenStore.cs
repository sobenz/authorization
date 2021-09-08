using System;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Common.Interfaces
{
    public interface ITokenStore
    {
        public Task<TToken> GetTokenAsync<TToken>(string tokenKey, CancellationToken cancellationToken = default);
        public Task DeleteTokenAsync<TToken>(string tokenKey, CancellationToken cancellationToken = default);
        public Task UpsertTokenAsync<TToken>(string tokenKey, TToken token, TimeSpan ttl, CancellationToken cancellationToken = default);
    }
}
