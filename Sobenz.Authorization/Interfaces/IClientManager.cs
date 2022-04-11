using Sobenz.Authorization.Common.Models;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sobenz.Authorization.Interfaces
{
    public interface IClientManager
    {
        Task<Client> CreateClientAsync(bool isConfidential, string name, IEnumerable<string> redirectUrls, string logoUrl = null, IEnumerable<string> contacts = null, CancellationToken cancellationToken = default);
        //Task<IEnumerable<ApplicationSummary>> ListClientsAsync(/*Id,Name,State,WhenCreated,LastUpdated*/CancellationToken cancellationToken = default);
        Task<Client> GetClientAsync(Guid clientId, CancellationToken cancellationToken);
        //void SetClientState(/*Enabled/Disabled*/);
        //void DeleteClient();
        //void SetClientScopes(/*GrantedScopes,UserAccessibleScopes*/);
        //void SetClientRoles(/*Global Roles, OrgSpecificRoles*/);
        //void SetClientDetails(/*Name, Contacts, LogoUrl*/);
        //string CreateClientSecret(string name);
        //void DeleteClientSecret(string secretHash);
    }
}
