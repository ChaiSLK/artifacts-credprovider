// Copyright (c) Microsoft. All rights reserved.
//
// Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using NuGetCredentialProvider.Logging;
using NuGetCredentialProvider.Util;

namespace NuGetCredentialProvider.CredentialProviders.Vsts
{
    public interface IAuthUtil
    {
        Task<Uri> GetAadAuthorityUriAsync(Uri uri, CancellationToken cancellationToken);

        Task<bool> IsVstsUriAsync(Uri uri);

        Task<Uri> GetAuthorizationEndpoint(Uri uri, CancellationToken cancellationToken);
    }

    public class AuthUtil : IAuthUtil
    {
        public const string VssResourceTenant = "X-VSS-ResourceTenant";
        public const string VssAuthorizationEndpoint = "X-VSS-AuthorizationEndpoint";
        public const string TfsServiceError = "X-TFS-ServiceError";

        private readonly ILogger logger;
        private readonly bool isOnPremise;

        public AuthUtil(ILogger logger)
        {
            this.logger = logger;
            this.isOnPremise = false;
        }

        public async Task<Uri> GetAadAuthorityUriAsync(Uri uri, CancellationToken cancellationToken)
        {
            var environmentAuthority = EnvUtil.GetAuthorityFromEnvironment(logger);
            if (environmentAuthority != null)
            {
                return environmentAuthority;
            }

            var headers = await GetResponseHeadersAsync(uri, cancellationToken);
            var bearerHeaders = headers.WwwAuthenticate.Where(x => x.Scheme.Equals("Bearer", StringComparison.Ordinal));
            foreach (var param in bearerHeaders)
            {
                if (param.Parameter == null)
                {
                    // MSA-backed accounts don't expose a parameter
                    continue;
                }

                var equalSplit = param.Parameter.Split(new[] { "=" }, StringSplitOptions.RemoveEmptyEntries);
                if (equalSplit.Length == 2)
                {
                    if (equalSplit[0].Equals("authorization_uri", StringComparison.OrdinalIgnoreCase))
                    {
                        if (Uri.TryCreate(equalSplit[1], UriKind.Absolute, out Uri parsedUri))
                        {
                            logger.Verbose(string.Format(Resources.FoundAADAuthorityFromHeaders, parsedUri));
                            return parsedUri;
                        }
                    }
                }
            }

            // Return the common tenant
            var aadBase = UsePpeAadUrl(uri) ? "https://login.windows-ppe.net" : "https://login.microsoftonline.com";
            logger.Verbose(string.Format(Resources.AADAuthorityNotFound, aadBase));
            return new Uri($"{aadBase}/common");
        }

        public async Task<bool> IsVstsUriAsync(Uri uri)
        {
            // Ping the url to see from headers whether it's an Azure Artifacts feed
            var responseHeaders = await GetResponseHeadersAsync(uri, cancellationToken: default);

            if (!IsHttpsScheme(uri))
            {
                // Azure DevOps Server (on prem) expects http vs https.
                // Uri should return 401 (TFS service error) if it's an Azure DevOps Server instance.
                return responseHeaders.Contains(TfsServiceError);
            }

            return responseHeaders.Contains(VssResourceTenant) && responseHeaders.Contains(VssAuthorizationEndpoint);
        }

        public async Task<Uri> GetAuthorizationEndpoint(Uri uri, CancellationToken cancellationToken)
        {
            var headers = await GetResponseHeadersAsync(uri, cancellationToken);

            try
            {
                foreach (var endpoint in headers.GetValues(VssAuthorizationEndpoint))
                {
                    if (Uri.TryCreate(endpoint, UriKind.Absolute, out var parsedEndpoint))
                    {
                        return parsedEndpoint;
                    }
                }
            }
            catch (Exception e)
            {
                logger.Warning(string.Format(Resources.SPSAuthEndpointException, e.Message));
                logger.Warning(e.StackTrace);
            }

            logger.Warning(string.Format(Resources.SPSAuthEndpointNotFound, uri.ToString()));
            return null;
        }

        protected virtual async Task<HttpResponseHeaders> GetResponseHeadersAsync(Uri uri, CancellationToken cancellationToken)
        {
            using (var httpClient = new HttpClient())
            using (var request = new HttpRequestMessage(HttpMethod.Get, uri))
            {
                foreach (var userAgent in Program.UserAgent)
                {
                    httpClient.DefaultRequestHeaders.UserAgent.Add(userAgent);
                }


                logger.Verbose($"GET {uri}");
                using (var response = await httpClient.SendAsync(request, cancellationToken))
                {
                    return response.Headers;
                }
            }
        }

        private bool UsePpeAadUrl(Uri uri)
        {
            var ppeHosts = EnvUtil.GetHostsFromEnvironment(logger, EnvUtil.PpeHostsEnvVar, new[]
            {
                ".vsts.me",
                ".codedev.ms",
                ".devppe.azure.com"
            });

            return ppeHosts.Any(host => uri.Host.EndsWith(host, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsHttpsScheme(Uri uri)
        {
            try
            {
                return uri.Scheme.ToLowerInvariant() == "https";
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }
    }
}
