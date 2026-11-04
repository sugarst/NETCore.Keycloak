using Microsoft.Extensions.Logging;
using NETCore.Keycloak.Client.HttpClients.Abstraction;
using NETCore.Keycloak.Client.Models;
using NETCore.Keycloak.Client.Models.AdminPermissions;
using Newtonsoft.Json.Linq;

namespace NETCore.Keycloak.Client.HttpClients.Implementation;

internal sealed partial class KcAdminPermissions : KcHttpClientBase, IKcAdminPermissions
{
    private static readonly Action<ILogger, string, Exception> RouteLog = LoggerMessage.Define<string>(
        LogLevel.Information, new EventId(2681, "AdminPermissionsRoute"), "Keycloak FGAP route: {Version}");

    internal KcAdminPermissions(string baseUrl, ILogger logger, IHttpClientFactory factory,
        KcAdminPermissionsVersion version) : base(logger, baseUrl, factory)
    {
        if ( !Enum.IsDefined(version) ) throw new ArgumentOutOfRangeException(nameof(version));
        SelectedVersion = version;
        if ( logger != null && version == KcAdminPermissionsVersion.V2 ) RouteLog(logger, version.ToString(), null);
    }

    public KcAdminPermissionsVersion SelectedVersion { get; }

    public async Task<KcResponse<bool>> GetRealmEnabledAsync(string realm, string accessToken,
        CancellationToken cancellationToken = default)
    {
        Guard(realm, accessToken);
        var result = await SendAsync<JObject>(realm, accessToken, "", HttpMethod.Get, null, cancellationToken)
            .ConfigureAwait(false);
        return Map(result, value => value?.Value<bool?>("adminPermissionsEnabled") == true);
    }

    public Task<KcResponse<object>> SetRealmEnabledAsync(string realm, string accessToken, bool enabled,
        CancellationToken cancellationToken = default)
    {
        Guard(realm, accessToken);
        return SendAsync<object>(realm, accessToken, "", HttpMethod.Put,
            new { adminPermissionsEnabled = enabled }, cancellationToken);
    }

    public Task<KcResponse<KcAdminPolicy>> CreatePolicyAsync(string realm, string accessToken, KcAdminPolicy policy,
        CancellationToken cancellationToken = default)
    {
        KcAdminPermissionsValidation.Policy(policy);
        return AuthorizationAsync<KcAdminPolicy>(realm, accessToken, "policy/" + policy.Type,
            HttpMethod.Post, policy, cancellationToken);
    }

    public async Task<KcResponse<KcAdminPolicy>> GetPolicyAsync(string realm, string accessToken,
        string type, string id,
        CancellationToken cancellationToken = default)
    {
        KcAdminPermissionsValidation.PolicyType(type);
        var result = await AuthorizationAsync<KcAdminPolicy>(realm, accessToken,
            "policy/" + type + "/" + KcAdminPermissionsValidation.Segment(id), HttpMethod.Get, null, cancellationToken)
            .ConfigureAwait(false);
        if ( result.IsError || type != "aggregate" ) return result;
        var associated = await AssociationsAsync(realm, accessToken, "policy/" + type + "/" +
            KcAdminPermissionsValidation.Segment(id), "associatedPolicies", cancellationToken).ConfigureAwait(false);
        if ( associated.IsError ) return Failure<KcAdminPolicy, JArray>(associated);
        result.Response.Policies = associated.Response.Select(p => p.Value<string>("id")).ToList();
        return result;
    }

    public Task<KcResponse<IEnumerable<KcAdminPolicy>>> ListPoliciesAsync(string realm, string accessToken,
        int first = 0, int max = 100, string name = null, CancellationToken cancellationToken = default) =>
        AuthorizationAsync<IEnumerable<KcAdminPolicy>>(realm, accessToken, "policy" + Query(first, max, name) +
            "&permission=false",
            HttpMethod.Get, null, cancellationToken);

    public Task<KcResponse<object>> UpdatePolicyAsync(string realm, string accessToken, string id, KcAdminPolicy policy,
        CancellationToken cancellationToken = default)
    {
        KcAdminPermissionsValidation.Policy(policy);
        return AuthorizationAsync<object>(realm, accessToken,
            "policy/" + policy.Type + "/" + KcAdminPermissionsValidation.Segment(id), HttpMethod.Put,
            WithId(JObject.FromObject(policy), id), cancellationToken);
    }

    public Task<KcResponse<object>> DeletePolicyAsync(string realm, string accessToken, string type, string id,
        CancellationToken cancellationToken = default)
    {
        KcAdminPermissionsValidation.PolicyType(type);
        return AuthorizationAsync<object>(realm, accessToken,
            "policy/" + type + "/" + KcAdminPermissionsValidation.Segment(id),
            HttpMethod.Delete, null, cancellationToken);
    }

    public async Task<KcResponse<KcAdminPermission>> CreatePermissionAsync(string realm, string accessToken,
        KcAdminPermission permission, CancellationToken cancellationToken = default)
    {
        KcAdminPermissionsValidation.Permission(permission);
        var result = await AuthorizationAsync<KcAdminPermission>(realm, accessToken, "permission/scope",
            HttpMethod.Post,
            KcAdminPermissionsValidation.PermissionBody(permission), cancellationToken).ConfigureAwait(false);
        if ( result.IsError ) return result;
        if ( string.IsNullOrWhiteSpace(result.Response?.Id) )
            return Error<KcAdminPermission>("The created permission response did not contain an identifier.");
        return await GetPermissionAsync(realm, accessToken, result.Response.Id, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<KcResponse<KcAdminPermission>> GetPermissionAsync(string realm, string accessToken, string id,
        CancellationToken cancellationToken = default)
    {
        var result = await AuthorizationAsync<KcAdminPermission>(realm, accessToken,
            "permission/scope/" + KcAdminPermissionsValidation.Segment(id),
            HttpMethod.Get, null, cancellationToken)
            .ConfigureAwait(false);
        return await NormalizePermissionAsync(realm, accessToken, result, cancellationToken).ConfigureAwait(false);
    }

    public Task<KcResponse<IEnumerable<KcAdminPermission>>> ListPermissionsAsync(string realm, string accessToken,
        int first = 0, int max = 100, string name = null, string resourceType = null, string resourceId = null,
        string scope = null, CancellationToken cancellationToken = default)
    {
        var query = Query(first, max, name);
        if ( resourceType != null || resourceId != null || scope != null )
        {
            KcAdminPermissionsValidation.ResourceScope(resourceType, scope);
            query += "&resourceType=" + Uri.EscapeDataString(resourceType);
            if ( resourceId != null ) query += "&resource=" + KcAdminPermissionsValidation.Segment(resourceId);
            if ( scope != null ) query += "&scope=" + Uri.EscapeDataString(scope);
        }
        return AuthorizationAsync<IEnumerable<KcAdminPermission>>(realm, accessToken,
            "permission/scope" + query, HttpMethod.Get, null, cancellationToken);
    }

    public Task<KcResponse<JObject>> EvaluatePermissionAsync(string realm, string accessToken, string subjectId,
        string resourceType, string resourceId, IEnumerable<string> scopes,
        CancellationToken cancellationToken = default)
    {
        _ = KcAdminPermissionsValidation.Segment(subjectId);
        _ = KcAdminPermissionsValidation.Segment(resourceId);
        var requested = scopes?.ToArray() ?? throw new ArgumentNullException(nameof(scopes));
        ArgumentOutOfRangeException.ThrowIfZero(requested.Length);
        foreach ( var scope in requested )
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(scope);
            KcAdminPermissionsValidation.ResourceScope(resourceType, scope);
        }
        return AuthorizationAsync<JObject>(realm, accessToken, "policy/evaluate", HttpMethod.Post, new
        {
            userId = subjectId,
            resourceType,
            resources = new[] { new { name = resourceId, scopes = requested.Select(s => new { name = s }) } }
        }, cancellationToken);
    }

    public Task<KcResponse<object>> UpdatePermissionAsync(string realm, string accessToken, string id,
        KcAdminPermission permission, CancellationToken cancellationToken = default)
    {
        KcAdminPermissionsValidation.Permission(permission);
        return AuthorizationAsync<object>(realm, accessToken,
            "permission/scope/" + KcAdminPermissionsValidation.Segment(id), HttpMethod.Put,
            WithId(KcAdminPermissionsValidation.PermissionBody(permission), id), cancellationToken);
    }

    public Task<KcResponse<object>> DeletePermissionAsync(string realm, string accessToken, string id,
        CancellationToken cancellationToken = default) =>
        AuthorizationAsync<object>(realm, accessToken,
            "permission/scope/" + KcAdminPermissionsValidation.Segment(id), HttpMethod.Delete, null, cancellationToken);

    public Task<KcResponse<KcAdminPermission>> CreateOrganizationPermissionAsync(string realm, string accessToken,
        string organizationId, KcAdminPermission permission, CancellationToken cancellationToken = default)
    {
        _ = KcAdminPermissionsValidation.Segment(organizationId);
        ArgumentNullException.ThrowIfNull(permission);
        var scoped = JObject.FromObject(permission).ToObject<KcAdminPermission>();
        scoped.ResourceType = "Organizations";
        scoped.Resources = [organizationId];
        return CreatePermissionAsync(realm, accessToken, scoped, cancellationToken);
    }

    private void Guard(string realm, string accessToken)
    {
        if ( SelectedVersion != KcAdminPermissionsVersion.V2 )
            throw new InvalidOperationException("Select FGAP V2 explicitly. " +
                "Existing v1 clients/groups/roles APIs remain available.");
        ValidateAccess(realm, accessToken);
        _ = KcAdminPermissionsValidation.Segment(realm);
    }

    private Task<KcResponse<T>> SendAsync<T>(string realm, string token, string suffix, HttpMethod method,
        object body, CancellationToken cancellationToken) =>
        ProcessRequestAsync<T>($"{BaseUrl}/{KcAdminPermissionsValidation.Segment(realm)}{suffix}", method, token,
            "FGAP v2 management request failed", body, cancellationToken: cancellationToken);

    private async Task<KcResponse<T>> AuthorizationAsync<T>(string realm, string token, string suffix,
        HttpMethod method, object body, CancellationToken cancellationToken)
    {
        Guard(realm, token);
        var enabled = await GetRealmEnabledAsync(realm, token, cancellationToken).ConfigureAwait(false);
        if ( enabled.IsError ) return Failure<T, bool>(enabled);
        if ( !enabled.Response ) return new KcResponse<T>
        {
            IsError = true,
            ErrorMessage = "FGAP v2 is disabled or its realm configuration is not visible to this administrator.",
            MonitoringMetrics = enabled.MonitoringMetrics
        };
        var discovery = await SendAsync<JArray>(realm, token, "/clients?clientId=admin-permissions", HttpMethod.Get,
            null, cancellationToken).ConfigureAwait(false);
        if ( discovery.IsError ) return Failure<T, JArray>(discovery);
        var clients = discovery.Response?.Where(c => c.Value<string>("clientId") == "admin-permissions").ToArray();
        if ( clients?.Length != 1 )
            return Error<T>("The admin-permissions client is unavailable. " +
                "Check the server FGAP v2 feature; no v1 fallback.");
        var id = KcAdminPermissionsValidation.Segment(clients[0].Value<string>("id"));
        return await SendAsync<T>(realm, token, $"/clients/{id}/authz/resource-server/{suffix}", method, body,
            cancellationToken).ConfigureAwait(false);
    }

    private static JObject WithId(JObject body, string id)
    {
        if ( body.Value<string>("id") is { } supplied && supplied != id )
            throw new ArgumentException("Body identifier must match the request identifier.", nameof(id));
        body["id"] = id;
        return body;
    }

    private static string Query(int first, int max, string name)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(first);
        ArgumentOutOfRangeException.ThrowIfLessThan(max, 1);
        return $"?first={first}&max={max}" + (name == null ? "" : "&name=" + Uri.EscapeDataString(name));
    }

    private static KcResponse<T> Error<T>(string message) => new() { IsError = true, ErrorMessage = message };
    private static KcResponse<T> Failure<T, TV>(KcResponse<TV> response) =>
        new()
        {
            IsError = true,
            ErrorMessage = response.ErrorMessage,
            Exception = response.Exception,
            MonitoringMetrics = response.MonitoringMetrics
        };
    private static KcResponse<T> Map<TV, T>(KcResponse<TV> response, Func<TV, T> map) =>
        response.IsError ? Failure<T, TV>(response) :
            new KcResponse<T> { Response = map(response.Response), MonitoringMetrics = response.MonitoringMetrics };
}
