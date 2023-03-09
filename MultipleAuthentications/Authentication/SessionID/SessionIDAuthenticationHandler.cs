using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Net;
using Microsoft.Net.Http.Headers;
using System.Diagnostics;
using MultipleAuthenticatons.Utils;

namespace MultipleAuthenticatons.Authentication.SessionID
{
    /// <summary>
    /// HTTP request interceptor (middleware) which performs authentication and adds info to request on success or returns a response on failed authentication.
    /// <br>This authentication scheme expects a session ID in HTTP request authentication header
    /// (which is called <em>Authorization header</em> in HTTP) after <c>SessionID</c> as scheme name.</br>
    /// <br><em>Session ID authentication scheme is a custom authentication scheme.</em></br>
    /// <br>Authentication scheme name is case insensitive (RFC 7235)</br>
    /// <br>Session ID shall not contain whitespace to prevent parsing errors (defined by this authentication handler)</br>
    /// </summary>
    public class SessionIDAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        /// <summary>
        /// The handler is to be registered under this authentication scheme name in application startup configuration.
        /// <br>Note: HTTP Authentication header scheme name is case insensitive according to RFC 7235</br>
        /// </summary>
        public const string AuthenticationSchemeName = "SessionID";

        public SessionIDAuthenticationHandler(
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
        /// </summary>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            Trace.WriteLine($"Running custom Session ID AuthenticationHandler");


            bool authHeaderPresent = Request.Headers.ContainsKey(HeaderNames.Authorization);
            if (authHeaderPresent == false)
            {
                AddAuthenticationFailedInfoToResponse(Response);
                return Task.FromResult(AuthenticateResult.Fail($"{HeaderNames.Authorization} header not found."));
            }

            var authHeader = Request.Headers[HeaderNames.Authorization].ToString();

            #region not important for the issue, just my custom scheme authentication header parsing

            //expecting "SessionID theSessionID" where SessionID is case insensitive HTTP Authentication scheme name
            string[] authHeaderParts = authHeader.Split();
            if (authHeaderParts.Length != 2)
            {
                AddAuthenticationFailedInfoToResponse(Response);
                return Task.FromResult(AuthenticateResult.Fail($"Invalid {HeaderNames.Authorization} header value for {AuthenticationSchemeName} authentication"));
            }

            string authenticationSchemeName = authHeaderParts[0];
            if (authenticationSchemeName.EqualsCaseInsensitive(AuthenticationSchemeName) == false)
            {
                AddAuthenticationFailedInfoToResponse(Response);
                return Task.FromResult(AuthenticateResult.Fail($"Invalid {HeaderNames.Authorization} header value for {AuthenticationSchemeName} authentication"));
            }

            #endregion


            string sessionID = authHeaderParts[1];

            //session ID validity check is skipped, not important for the issue.

            Trace.WriteLine("Session ID AuthenticationHandler succeeded.");

            //create empty user data
            List<Claim> claims = new();
            var claimsPrincipal = new ClaimsPrincipal();
            var identityWithClaims = new ClaimsIdentity(claims, Scheme.Name);
            claimsPrincipal.AddIdentity(identityWithClaims);
            var result = new AuthenticationTicket(claimsPrincipal, Scheme.Name);

            //no HTTP response is sent
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, Scheme.Name)));
        }

        /// <summary>
        /// Sets <paramref name="response"/> status code to <see cref="HttpStatusCode.Unauthorized"/> (<c>401</c>) which is an indicator of failed <em>authentication</em>.
        /// <br>And adds <c>WWW-Authenticate</c> HTTP header to the <paramref name="response"/> which is a standard for a <see cref="HttpStatusCode.Unauthorized"/> (<c>401</c>) response.</br>
        /// </summary>
        private static void AddAuthenticationFailedInfoToResponse(HttpResponse response)
        {
            response.StatusCode = (int)HttpStatusCode.Unauthorized;
            //note: when multiple AuthenticationHandlers are called, this header might be set repeatedly which fails during runtime
            response.Headers.Add(HeaderNames.WWWAuthenticate, $"{AuthenticationSchemeName}");
        }
    }
}
