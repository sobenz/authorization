using System.Collections.Generic;

namespace Sobenz.Authorization.Models
{
    public static class Scopes
    {
        #region Auth Service Specific Scopes
        /// <summary>
        /// This scope allows the creation of new clients. Should only be given to clients or users that should be able to do this.
        /// </summary>
        public const string ClientRegistration = "client_reg";
        #endregion

        #region User/Cleint Type Scopes
        /// <summary>
        /// A user scope defines that the requested access token will interact as an end user and should not be able to operate API's outside this scope.
        /// </summary>
        public const string User = "user";

        /// <summary>
        /// The user/client will perform merchant level operations and will have specific roles to carry out various operations.
        /// </summary>
        public const string Merchant = "merchant";
        #endregion

        #region User Profile Scopes
        /// <summary>
        /// Grants access to the user's identifier.
        /// </summary>
        public const string OpenId = "openid";

        /// <summary>
        /// Grants access to the user's profile details.
        /// </summary>
        public const string Profile = "profile";

        /// <summary>
        /// Grants access to the user's email address.
        /// </summary>
        public const string Email = "email";
        #endregion

        public static IEnumerable<string> ExplicitGrantScopes = new [] { OpenId, Profile, Email };
        public static IEnumerable<string> ImplicitGrantScopes = new[] { ClientRegistration, User, Merchant };
    }
}
