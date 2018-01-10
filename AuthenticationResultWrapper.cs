using System;
using System.Runtime.Serialization;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace DoctorJones.IdentityModel.Clients.ActiveDirectory
{
    [DataContract]
    public class AuthenticationResultWrapper : IAuthenticationResultWrapper
    {
        private readonly AuthenticationResult _authenticationResult;

        public AuthenticationResultWrapper(AuthenticationResult authenticationResult)
        {
            _authenticationResult = authenticationResult;
        }

        /// <Summary>
        /// Gets the type of the Access Token returned.         
        /// </Summary>
        [DataMember]
        public string AccessTokenType => _authenticationResult.AccessTokenType;
        /// <Summary>
        /// Gets the Access Token requested.         
        /// </Summary>
        [DataMember]
        public string AccessToken => _authenticationResult.AccessToken;
        /// <Summary>
        /// Gets the point in time in which the Access Token returned in the AccessToken property ceases to be valid. This value is calculated based on current UTC time measured locally and the value expiresIn received from the service.       
        /// </Summary>
        [DataMember]
        public DateTimeOffset ExpiresOn => _authenticationResult.ExpiresOn;
        /// <Summary>
        /// Gives information to the developer whether token returned is during normal or extended lifetime.        
        /// </Summary>
        [DataMember]
        public bool ExtendedLifeTimeToken => _authenticationResult.ExtendedLifeTimeToken;
        /// <Summary>
        /// Gets an identifier for the tenant the token was acquired from. This property will be null if tenant information is not returned by the service.        
        /// </Summary>
        [DataMember]
        public string TenantId => _authenticationResult.TenantId;
        /// <Summary>
        /// Gets user information including user Id. Some elements in UserInfo might be null if not returned by the service.        
        /// </Summary>
        [DataMember]
        public UserInfo UserInfo => _authenticationResult.UserInfo;
        /// <Summary>
        /// Gets the entire Id Token if returned by the service or null if no Id Token is returned.        
        /// </Summary>
        [DataMember]
        public string IdToken => _authenticationResult.IdToken;

        /// <Summary>
        /// Creates authorization header from authentication result.         
        /// </Summary>
        /// <Returns>
        /// Created authorization header         
        /// </Returns>
        public string CreateAuthorizationHeader() => _authenticationResult.CreateAuthorizationHeader();
    }
}
