using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace DoctorJones.IdentityModel.Clients.ActiveDirectory
{
    public class AuthenticationContextWrapper : IAuthenticationContextWrapper
    {
        private readonly AuthenticationContext _authenticationContext;

        public AuthenticationContextWrapper(AuthenticationContext authenticationContext)
        {
            _authenticationContext = authenticationContext;
        }

        /// <Summary>
        /// Constructor to create the context with the address of the authority. Using this constructor will turn ON validation of the authority URL by default if validation is supported for the authority address.       
        /// </Summary>
        /// <param name="authority">Address of the authority to issue token.</param>
        public AuthenticationContextWrapper(string authority) => _authenticationContext = new AuthenticationContext(authority);
        /// <Summary>
        /// Constructor to create the context with the address of the authority and flag to turn address validation off. Using this constructor, address validation can be turned off. Make sure you are aware of the security implication of not validating the address.      
        /// </Summary>
        /// <param name="authority">Address of the authority to issue token.</param>
        /// <param name="validateAuthority">Flag to turn address validation ON or OFF.</param>
        public AuthenticationContextWrapper(string authority, bool validateAuthority) => _authenticationContext = new AuthenticationContext(authority, validateAuthority);
        /// <Summary>
        /// Constructor to create the context with the address of the authority. Using this constructor will turn ON validation of the authority URL by default if validation is supported for the authority address.       
        /// </Summary>
        /// <param name="authority">Address of the authority to issue token.</param>
        /// <param name="tokenCache">Token cache used to lookup cached tokens on calls to AcquireToken</param>
        public AuthenticationContextWrapper(string authority, TokenCache tokenCache) => _authenticationContext = new AuthenticationContext(authority, tokenCache);
        /// <Summary>
        /// Constructor to create the context with the address of the authority and flag to turn address validation off. Using this constructor, address validation can be turned off. Make sure you are aware of the security implication of not validating the address.      
        /// </Summary>
        /// <param name="authority">Address of the authority to issue token.</param>
        /// <param name="validateAuthority">Flag to turn address validation ON or OFF.</param>
        /// <param name="tokenCache">Token cache used to lookup cached tokens on calls to AcquireToken</param>
        public AuthenticationContextWrapper(string authority, bool validateAuthority, TokenCache tokenCache) => _authenticationContext = new AuthenticationContext(authority, validateAuthority, tokenCache);

        /// <Summary>
        /// Gets a value indicating whether address validation is ON or OFF.         
        /// </Summary>
        public bool ValidateAuthority => _authenticationContext.ValidateAuthority;
        /// <Summary>
        /// Gets address of the authority to issue token.         
        /// </Summary>
        public string Authority => _authenticationContext.Authority;
        /// <Summary>
        /// Used to set the flag for AAD extended lifetime         
        /// </Summary>
        public bool ExtendedLifeTimeEnabled { get => _authenticationContext.ExtendedLifeTimeEnabled; set => _authenticationContext.ExtendedLifeTimeEnabled = value; }
        /// <Summary>
        /// Property to provide ADAL's token cache. Depending on the platform, TokenCache may have a default persistent cache or not. Library will automatically save tokens in default TokenCache whenever you obtain them. Cached tokens will be available only to the application that saved them. If the cache is persistent, the tokens stored in it will outlive the application's execution, and will be available in subsequent runs. To turn OFF token caching, set TokenCache to null.    
        /// </Summary>
        public TokenCache TokenCache => _authenticationContext.TokenCache;
        /// <Summary>
        /// Gets or sets correlation Id which would be sent to the service with the next request. Correlation Id is to be used for diagnostics purposes.        
        /// </Summary>
        public Guid CorrelationId { get => _authenticationContext.CorrelationId; set => _authenticationContext.CorrelationId = value; }

        /// <Summary>
        /// Acquires device code from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <Returns>
        /// It contains Device Code, its expiration time, User Code.         
        /// </Returns>
        public Task<DeviceCodeResult> AcquireDeviceCodeAsync(string resource, string clientId) => _authenticationContext.AcquireDeviceCodeAsync(resource, clientId);
        /// <Summary>
        /// Acquires device code from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authenticationrequest to the authority. The parameter can be null.</param>
        /// <Returns>
        /// It contains Device Code, its expiration time, User Code.         
        /// </Returns>
        public Task<DeviceCodeResult> AcquireDeviceCodeAsync(string resource, string clientId, string extraQueryParameters) => _authenticationContext.AcquireDeviceCodeAsync(resource, clientId, extraQueryParameters);

        /// <Summary>
        /// Acquires an access token from the authority on behalf of a user, passing in the necessary claims for authentication. It requires using a user token previously received.       
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="parameters">Instance of PlatformParameters containing platform specific arguments and information.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authenticationrequest to the authority. The parameter can be null.</param>
        /// <param name="claims">Additional claims that are needed for authentication. Acquired from the AdalClaimChallengeException</param>
        /// <Returns>
        /// It contains Access Token and the Access Token's expiration time.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, Uri redirectUri, IPlatformParameters parameters, UserIdentifier userId, string extraQueryParameters, string claims)
        {
                return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientId, redirectUri, parameters, userId, extraQueryParameters, claims));
        }

        /// <Summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.        
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token and the Access Token's expiration time.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, IClientAssertionCertificate clientCertificate, UserAssertion userAssertion)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientCertificate, userAssertion));
        }

        /// <Summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.        
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCredential">The client credential to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token and the Access Token's expiration time.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, ClientCredential clientCredential, UserAssertion userAssertion)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientCredential, userAssertion));
        }

        /// <Summary>
        /// Acquires security token from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token and the Access Token's expiration time. Refresh Token property will be null for this overload.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, IClientAssertionCertificate clientCertificate)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientCertificate));
        }
        /// <Summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.        
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token and the Access Token's expiration time.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, ClientAssertion clientAssertion, UserAssertion userAssertion)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientAssertion, userAssertion));
        }
        /// <Summary>
        /// Acquires security token from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token and the Access Token's expiration time. Refresh Token property will be null for this overload.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, ClientAssertion clientAssertion)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientAssertion));
        }
        /// <Summary>
        /// Acquires security token from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="userAssertion">The assertion to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token and the Access Token's expiration time. Refresh Token property will be null for this overload.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, UserAssertion userAssertion)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientId, userAssertion));
        }
        /// <Summary>
        /// Acquires security token from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="userId">Identifier of the user token is requested for. If created from DisplayableId,this parameter will be used to pre-populate the username field in the authenticationform. Please note that the end user can still edit the username field and authenticateas a different user. If you want to be notified of such change with an exception,create UserIdentifier with type RequiredDisplayableId. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <param name="parameters">Parameters needed for interactive flow requesting authorization code. Pass aninstance of PlatformParameters.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authenticationrequest to the authority. The parameter can be null.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, Uri redirectUri, IPlatformParameters parameters, UserIdentifier userId, string extraQueryParameters)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientId, redirectUri, parameters, userId, extraQueryParameters));
        }
        /// <Summary>
        /// Acquires security token from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="parameters">An object of type PlatformParameters which may pass additional parameters usedfor authorization.</param>
        /// <param name="userId">Identifier of the user token is requested for. If created from DisplayableId,this parameter will be used to pre-populate the username field in the authenticationform. Please note that the end user can still edit the username field and authenticateas a different user. If you want to be notified of such change with an exception,create UserIdentifier with type RequiredDisplayableId. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, Uri redirectUri, IPlatformParameters parameters, UserIdentifier userId)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientId, redirectUri, parameters, userId));
        }
        /// <Summary>
        /// Acquires security token from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="parameters">An object of type PlatformParameters which may pass additional parameters usedfor authorization.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, Uri redirectUri, IPlatformParameters parameters)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientId, redirectUri, parameters));
        }
        /// <Summary>
        /// Acquires security token from the authority.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCredential">The client credential to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token and the Access Token's expiration time. Refresh Token property will be null for this overload.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, ClientCredential clientCredential)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenAsync(resource, clientCredential));
        }
        /// <Summary>
        /// Acquires security token from the authority using authorization code previously received. This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier).       
        /// </Summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="clientCredential">The credential to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientCredential clientCredential)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientCredential));
        }
        /// <Summary>
        /// Acquires security token from the authority using an authorization code previously received. This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier).       
        /// </Summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="clientCredential">The credential to use for token acquisition.</param>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.It can be null if provided earlier to acquire authorizationCode.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientCredential clientCredential, string resource)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientCredential, resource));
        }
        /// <Summary>
        /// Acquires security token from the authority using an authorization code previously received. This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier).       
        /// </Summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientAssertion clientAssertion)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientAssertion));
        }
        /// <Summary>
        /// Acquires security token from the authority using an authorization code previously received. This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier).       
        /// </Summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, IClientAssertionCertificate clientCertificate)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientCertificate));
        }
        /// <Summary>
        /// Acquires security token from the authority using an authorization code previously received. This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier).       
        /// </Summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.It can be null if provided earlier to acquire authorizationCode.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, IClientAssertionCertificate clientCertificate, string resource)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientCertificate, resource));
        }
        /// <Summary>
        /// Acquires security token from the authority using an authorization code previously received. This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier).       
        /// </Summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.It can be null if provided earlier to acquire authorizationCode.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientAssertion clientAssertion, string resource)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientAssertion, resource));
        }
        /// <Summary>
        /// Acquires security token from the authority using an device code previously received. This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier).       
        /// </Summary>
        /// <param name="deviceCodeResult">The device code result received from calling AcquireDeviceCodeAsync.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information.         
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByDeviceCodeAsync(DeviceCodeResult deviceCodeResult)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenByDeviceCodeAsync(deviceCodeResult));
        }
        /// <Summary>
        /// Acquires security token without asking for user credential.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information. If acquiring token without user credential is not possible, the method throws AdalException.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, string clientId, UserIdentifier userId)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenSilentAsync(resource, clientId, userId));
        }
        /// <Summary>
        /// Acquires security token without asking for user credential.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information. If acquiring token without user credential is not possible, the method throws AdalException.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, IClientAssertionCertificate clientCertificate, UserIdentifier userId)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenSilentAsync(resource, clientCertificate, userId));
        }
        /// <Summary>
        /// Acquires security token without asking for user credential.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCredential">The client credential to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information. If acquiring token without user credential is not possible, the method throws AdalException.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, ClientCredential clientCredential, UserIdentifier userId)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenSilentAsync(resource, clientCredential, userId));
        }
        /// <Summary>
        /// Acquires security token without asking for user credential.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <param name="parameters">Instance of PlatformParameters containing platform specific arguments and information.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information. If acquiring token without user credential is not possible, the method throws AdalException.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, string clientId, UserIdentifier userId, IPlatformParameters parameters)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenSilentAsync(resource, clientId, userId, parameters));
        }
        /// <Summary>
        /// Acquires security token without asking for user credential.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information. If acquiring token without user credential is not possible, the method throws AdalException.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, string clientId)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenSilentAsync(resource, clientId));
        }
        /// <Summary>
        /// Acquires security token without asking for user credential.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <Returns>
        /// It contains Access Token, its expiration time, user information. If acquiring token without user credential is not possible, the method throws AdalException.        
        /// </Returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, ClientAssertion clientAssertion, UserIdentifier userId)
        {
            return new AuthenticationResultWrapper(await _authenticationContext.AcquireTokenSilentAsync(resource, clientAssertion, userId));
        }
        /// <Summary>
        /// Gets URL of the authorize endpoint including the query parameters.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authenticationrequest to the authority. The parameter can be null.</param>
        /// <param name="claims">Additional claims that are needed for authentication. Acquired from the AdalClaimChallengeException.This parameter can be null.</param>
        /// <Returns>
        /// URL of the authorize endpoint including the query parameters.         
        /// </Returns>
        public Task<Uri> GetAuthorizationRequestUrlAsync(string resource, string clientId, Uri redirectUri, UserIdentifier userId, string extraQueryParameters, string claims) => _authenticationContext.GetAuthorizationRequestUrlAsync(resource, clientId, redirectUri, userId, extraQueryParameters, claims);
        /// <Summary>
        /// Gets URL of the authorize endpoint including the query parameters.         
        /// </Summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.Any.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authenticationrequest to the authority. The parameter can be null.</param>
        /// <Returns>
        /// URL of the authorize endpoint including the query parameters.         
        /// </Returns>
        public Task<Uri> GetAuthorizationRequestUrlAsync(string resource, string clientId, Uri redirectUri, UserIdentifier userId, string extraQueryParameters) => _authenticationContext.GetAuthorizationRequestUrlAsync(resource, clientId, redirectUri, userId, extraQueryParameters);
    }
}
