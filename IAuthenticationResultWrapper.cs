using System;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace DoctorJones.IdentityModel.Clients.ActiveDirectory
{
    public interface IAuthenticationResultWrapper
    {
        /// <Summary>
        /// Gets the type of the Access Token returned.         
        /// </Summary>
        string AccessTokenType { get; }

        /// <Summary>
        /// Gets the Access Token requested.         
        /// </Summary>
        string AccessToken { get; }

        /// <Summary>
        /// Gets the point in time in which the Access Token returned in the AccessToken property ceases to be valid. This value is calculated based on current UTC time measured locally and the value expiresIn received from the service.       
        /// </Summary>
        DateTimeOffset ExpiresOn { get; }

        /// <Summary>
        /// Gives information to the developer whether token returned is during normal or extended lifetime.        
        /// </Summary>
        bool ExtendedLifeTimeToken { get; }

        /// <Summary>
        /// Gets an identifier for the tenant the token was acquired from. This property will be null if tenant information is not returned by the service.        
        /// </Summary>
        string TenantId { get; }

        /// <Summary>
        /// Gets user information including user Id. Some elements in UserInfo might be null if not returned by the service.        
        /// </Summary>
        UserInfo UserInfo { get; }

        /// <Summary>
        /// Gets the entire Id Token if returned by the service or null if no Id Token is returned.        
        /// </Summary>
        string IdToken { get; }

        /// <Summary>
        /// Creates authorization header from authentication result.         
        /// </Summary>
        /// <Returns>
        /// Created authorization header         
        /// </Returns>
        string CreateAuthorizationHeader();
    }
}
