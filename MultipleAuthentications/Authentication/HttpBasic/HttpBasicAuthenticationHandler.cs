using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text;
using Microsoft.Net.Http.Headers;
using System.Net;
using System.Diagnostics;
using MultipleAuthenticatons.Utils;

namespace MultipleAuthenticatons.Authentication.HttpBasic
{
    /// <summary>
    /// HTTP request interceptor (middleware) which performs authentication and adds info to request on success or returns a response on failed authentication.
    /// <br>Implements <c>HTTP Basic</c> authentication scheme.</br>
    /// </summary>
    public class HttpBasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        /// <summary>
        /// The handler is to be registered under this authentication scheme name in application startup configuration.
        /// <br>Note: HTTP Authentication header scheme name is case insensitive according to RFC 7235</br>
        /// </summary>
        public const string AuthenticationSchemeName = "Basic";

        /// <summary>
        /// Used in HTTP Basic authentication case of failed authentication in <see cref="HeaderNames.WWWAuthenticate"/> header in <see cref="HttpResponse"/>
        /// </summary>
        private const string Realm = "My realm";

        public HttpBasicAuthenticationHandler(
           IOptionsMonitor<AuthenticationSchemeOptions> options,
           ILoggerFactory logger,
           UrlEncoder encoder,
           ISystemClock clock
           ) : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// Implementation of the authentication HTTP request interception - the authentication process for this authentication scheme.
        /// <br>This method is provided by the <see cref="AuthenticationHandler{TOptions}"/> class 
        /// and called when the handler is activated in the HTTP request processing pipeline 
        /// which is to be set up in the server application startup config and/or by [Authorize] annotations on controllers and their methods manually.</br>
        /// <br>Expects UTF-8 encoding of the string converted to base64</br>
        /// </summary>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            Trace.WriteLine($"Running HTTP Basic AuthenticationHandler");

            //HTTP Basic authorization expects that the Authorization header contains "Basic username:password" string encoded in base64 (to allow all characters)
            bool authHeaderPresent = Request.Headers.ContainsKey(HeaderNames.Authorization);
            if (authHeaderPresent == false)
            {
                AddAuthenticationFailedInfoToResponse(Response);
                return Task.FromResult(AuthenticateResult.Fail($"{HeaderNames.Authorization} header not found."));
            }

            var authHeader = Request.Headers[HeaderNames.Authorization].ToString();

            #region not important for the issue, just HTTP Basic authentication header parsing

            //requested content is: "Basic xxxx" where xxxx is base64 encoded username:password
            string[] authHeaderParts = authHeader.Split();
            if (authHeaderParts.Length != 2)
            {
                AddAuthenticationFailedInfoToResponse(Response);
                return Task.FromResult(AuthenticateResult.Fail($"Invalid {HeaderNames.Authorization} header value for {AuthenticationSchemeName} authentication"));
            }

            //the authentication scheme name for HTTP Basic authentication is case insensitive (RFC 7617)
            //and also in general HTTP auth scheme name is case-insensitive (RFC 7235)
            string authenticationSchemeName = authHeaderParts[0];
            if (authenticationSchemeName.EqualsCaseInsensitive(AuthenticationSchemeName) == false)
            {
                AddAuthenticationFailedInfoToResponse(Response);
                return Task.FromResult(AuthenticateResult.Fail($"Invalid {HeaderNames.Authorization} header value for {AuthenticationSchemeName} authentication"));
            }

            var credentialStringBase64 = authHeaderParts[1];
            //UTF-8 is selected because default encoding for this case is undefined and UTF-8 is ASCII-compliant (RFC 7617)
            var credentialString = Encoding.UTF8.GetString(Convert.FromBase64String(credentialStringBase64));
            string[] credentials = credentialString.Split(':');
            if (credentials.Length != 2)
            {
                AddAuthenticationFailedInfoToResponse(Response);
                return Task.FromResult(AuthenticateResult.Fail($"Invalid {HeaderNames.Authorization} header value for {AuthenticationSchemeName} authentication"));
            }

            #endregion

            var username = credentials[0];
            var password = credentials[1];

            //login credentials validity check is skipped, not important for the issue.

            Trace.WriteLine($"HTTP Basic AuthenticationHandler succeeded");

            //create empty user data
            List<Claim> claims = new();
            var claimsPrincipal = new ClaimsPrincipal();
            var identityWithClaims = new ClaimsIdentity(claims, Scheme.Name);
            claimsPrincipal.AddIdentity(identityWithClaims);
            var result = new AuthenticationTicket(claimsPrincipal, Scheme.Name);

            return Task.FromResult(AuthenticateResult.Success(result));
        }

        /// <summary>
        /// Sets <paramref name="response"/> status code to <see cref="HttpStatusCode.Unauthorized"/> (<c>401</c>) which is an indicator of failed <em>authentication</em>.
        /// <br>And adds <c>WWW-Authenticate</c> HTTP header to the <paramref name="response"/> which is a standard for a <see cref="HttpStatusCode.Unauthorized"/> (<c>401</c>) response.</br>
        /// </summary>
        private static void AddAuthenticationFailedInfoToResponse(HttpResponse response)
        {
            response.StatusCode = (int)HttpStatusCode.Unauthorized;
            //note: when multiple AuthenticationHandlers are called, this header might be set repeatedly which fails during runtime
            response.Headers.Add(HeaderNames.WWWAuthenticate, $"{AuthenticationSchemeName} realm=\"{Realm}\"" /* realm is special info added in HTTP Basic auth fail */);
        }
    }
}
