using System.Reflection;

using Microsoft.AspNetCore.Authentication;
using Microsoft.OpenApi.Models;

using MultipleAuthenticatons.Authentication.HttpBasic;
using MultipleAuthenticatons.Authentication.SessionID;

namespace MultipleAuthenticatons
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            #region REST API authentication & authorization setup

            //partial source: https://dotnetthoughts.net/implementing-basic-authentication-in-minimal-webapi/

            //authentication can be enabled manually on controllers and their methods by adding the [Authorize] annotation on a method or on a controller
            //putting [Authorize] annotation on a controller will propagate it to all the controller's methods.
            /* .AddAuthentication with authentication scheme name will:
             * 1. "put [Authorize] annotation" on every controller method by default (=> enable AuthenticationHandler trigger on every call)
             * 2. set that authentication scheme's AuthenticationHandler to be run where [Authorize] attribute is used without authentication scheme name parameter.
             */
            //[AllowAnonymous] annotation will ignore authentication result but will still run the AuthenticationHandler for the default authentication schema.
            string defaultAuthenticationScheme = HttpBasicAuthenticationHandler.AuthenticationSchemeName;
            var authenticationBuilder = builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = defaultAuthenticationScheme; //this default one will be used when [Authorize] with no parameters is added to controller/function
            });
            authenticationBuilder.AddScheme<AuthenticationSchemeOptions, HttpBasicAuthenticationHandler>(HttpBasicAuthenticationHandler.AuthenticationSchemeName, null);
            authenticationBuilder.AddScheme<AuthenticationSchemeOptions, SessionIDAuthenticationHandler>(SessionIDAuthenticationHandler.AuthenticationSchemeName, null);

            //what does this exactly do? added because it was in the sample for BasicAuthenticationHandler
            builder.Services.AddAuthorization();

            #endregion

            builder.Services.AddControllers();

            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(options =>
            {
                //xml documentation generating must be enabled in Project -> Properties -> Build
                //when <response> tags are used in functions documentation in controllers,
                //use case description is displayed on each status code
                var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml"; //project name.xml (default)
                options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));

                #region add the ability to pass in HTTP Basic authorization header via Swagger UI
                //note: when multiple inputs for authorization header are added in Swagger UI, only the first filled one is added to the authentication header.
                //this means that if we have HTTP Basic username & password form and session ID input in Swagger UI and we fill HTTP Basic form,
                //only HTTP Basic info will be put into the header by Swagger UI and will be passed to the REST API

                //the name is not important but has to be synchronized with the "Swagger UI security requirement"
                string swaggerUIHttpBasicAuthenticationSchemeSecurityDefinitionName = "HTTP Basic authentication"; //name displayed in Swagger UI

                //source: https://stackoverflow.com/questions/41180615/how-to-send-custom-headers-with-requests-in-swagger-ui
                options.AddSecurityDefinition(swaggerUIHttpBasicAuthenticationSchemeSecurityDefinitionName, new OpenApiSecurityScheme
                {
                    Description = "Enter credentials (login and password) which will be passed in as HTTP Basic authentication header.",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Scheme = "Basic", //case insensitive, this creates username and password form in Swagger UI for HTTP Basic Authentication.
                    Type = SecuritySchemeType.Http
                });

                //this enables sending the authentication header value set in Swagger UI authentication form via the Swagger UI "Authorize" button for this scheme
                //without this, HTTP Authentication header from e.g. HTTP Basic Auth form in Swagger UI is not sent to the controller action when calling the controller via Swagger UI
                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference {
                                Type = ReferenceType.SecurityScheme,
                                Id = swaggerUIHttpBasicAuthenticationSchemeSecurityDefinitionName
                            }
                        },
                        new List<string>()
                    }
                });

                #endregion


                #region add the ability to pass in custom Session ID authorization header via Swagger UI

                //the name is not important but has to be synchronized with the "Swagger UI security requirement"
                string swaggerUISessionIDAuthenticationSchemeSecurityDefinitionName = "Custom Session ID authentication"; //name displayed in Swagger UI

                options.AddSecurityDefinition(swaggerUISessionIDAuthenticationSchemeSecurityDefinitionName, new OpenApiSecurityScheme
                {
                    Description =
                    "Enter authentication header value for Session ID authentication scheme.<br/>" +
                    "Requested format: 'SessionID theSessionID'<br/>" +
                    "The SessionID prefix is authentication schema name and is case insensitive (RFC 7235)",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    //with Type = Http and Scheme = "bearer", the 'Bearer ' prefix will be passed in to the application in the authentication header value
                    //but I could not find a way to use a custom prefix 'SessionID ' so that the user only has to enter the actual session ID.
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "sessionID" //irrelevant
                });

                //this enables sending the authentication header value set in Swagger UI authentication form via the Swagger UI "Authorize" button for this scheme
                //without this, HTTP Authentication header from e.g. HTTP Basic Auth form in Swagger UI is not sent to the controller action when calling the controller via Swagger UI
                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference {
                                Type = ReferenceType.SecurityScheme,
                                Id = swaggerUISessionIDAuthenticationSchemeSecurityDefinitionName
                            }
                        },
                        new List<string>()
                    }
                });

                #endregion

            });

            var app = builder.Build();

            app.UseSwaggerUI(options =>
            {
                options.DisplayOperationId(); //displays friendly function name in the API method description
            });

            app.UseSwagger();

            app.UseHttpsRedirection();
            app.UseAuthorization();
            app.UseAuthentication();
            app.MapControllers();

            app.Run();
        }
    }
}