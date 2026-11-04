using NETCore.Keycloak.Client.Models;
using NETCore.Keycloak.Client.Models.AdminPermissions;
using Newtonsoft.Json.Linq;

namespace NETCore.Keycloak.Client.HttpClients.Abstraction;

/// <summary>Explicit FGAP v2 management. V1 selection rejects these calls without HTTP or silent fallback.</summary>
public interface IKcAdminPermissions
{
    /// <summary>Gets the immutable route selected when this client was constructed.</summary>
    KcAdminPermissionsVersion SelectedVersion { get; }

    /// <summary>Reads whether FGAP v2 admin permissions are enabled in the realm.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<bool>> GetRealmEnabledAsync(string realm, string accessToken,
        CancellationToken cancellationToken = default);

    /// <summary>Explicitly enables or disables realm admin permissions without changing other realm settings.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="enabled">Whether to enable realm admin permissions.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<object>> SetRealmEnabledAsync(string realm, string accessToken, bool enabled,
        CancellationToken cancellationToken = default);

    /// <summary>Creates a supported built-in policy using its provider representation.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="policy">Built-in provider representation.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<KcAdminPolicy>> CreatePolicyAsync(string realm, string accessToken, KcAdminPolicy policy,
        CancellationToken cancellationToken = default);

    /// <summary>Reads a complete provider representation suitable for editing and updating.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="type">Supported built-in provider type.</param>
    /// <param name="id">Server policy or permission UUID.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<KcAdminPolicy>> GetPolicyAsync(string realm, string accessToken, string type, string id,
        CancellationToken cancellationToken = default);

    /// <summary>Lists generic server policy summaries; use GetPolicyAsync for editable provider fields.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token.</param>
    /// <param name="first">Zero-based first result.</param>
    /// <param name="max">Maximum number of results; at least one.</param>
    /// <param name="name">Optional server name filter.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<IEnumerable<KcAdminPolicy>>> ListPoliciesAsync(string realm, string accessToken,
        int first = 0, int max = 100, string name = null,
        CancellationToken cancellationToken = default);

    /// <summary>Updates a policy using its complete provider representation and matching identifier.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="id">Server policy or permission UUID.</param>
    /// <param name="policy">Built-in provider representation.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<object>> UpdatePolicyAsync(string realm, string accessToken, string id, KcAdminPolicy policy,
        CancellationToken cancellationToken = default);

    /// <summary>Deletes a policy from the admin-permissions resource server.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="type">Supported built-in provider type.</param>
    /// <param name="id">Server policy or permission UUID.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<object>> DeletePolicyAsync(string realm, string accessToken, string type, string id,
        CancellationToken cancellationToken = default);

    /// <summary>Creates a permission and returns scope names and target entity UUIDs.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="permission">Permission using scope names and entity UUIDs.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<KcAdminPermission>> CreatePermissionAsync(string realm, string accessToken,
        KcAdminPermission permission,
        CancellationToken cancellationToken = default);

    /// <summary>Reads an editable permission, resolving authorization IDs to scope names and entity UUIDs.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="id">Server policy or permission UUID.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<KcAdminPermission>> GetPermissionAsync(string realm, string accessToken, string id,
        CancellationToken cancellationToken = default);

    /// <summary>Lists generic server permission summaries; use GetPermissionAsync for editable scope/resource fields.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token.</param>
    /// <param name="first">Zero-based first result.</param>
    /// <param name="max">Maximum number of results; at least one.</param>
    /// <param name="name">Optional server name filter.</param>
    /// <param name="resourceType">Optional supported resource type; required with resourceId or scope.</param>
    /// <param name="resourceId">Optional entity UUID filter.</param>
    /// <param name="scope">Optional supported scope name filter.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<IEnumerable<KcAdminPermission>>> ListPermissionsAsync(string realm, string accessToken,
        int first = 0, int max = 100, string name = null, string resourceType = null, string resourceId = null,
        string scope = null,
        CancellationToken cancellationToken = default);

    /// <summary>Evaluates the selected subject's permission on one entity using Keycloak's supported
    /// evaluator.</summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Token authorized to evaluate admin permissions.</param>
    /// <param name="subjectId">User UUID to evaluate.</param>
    /// <param name="resourceType">Supported FGAP v2 resource type.</param>
    /// <param name="resourceId">Target entity UUID.</param>
    /// <param name="scopes">One or more explicit supported scope names; Preview scopes are rejected.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>Server decision and detailed policy results. Evaluation does not grant permissions.</returns>
    Task<KcResponse<JObject>> EvaluatePermissionAsync(string realm, string accessToken, string subjectId,
        string resourceType, string resourceId, IEnumerable<string> scopes,
        CancellationToken cancellationToken = default);

    /// <summary>Updates a permission using scope names and entity UUIDs; empty Resources selects the entire type.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token.</param>
    /// <param name="id">Server permission UUID.</param>
    /// <param name="permission">Permission using scope names and entity UUIDs.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<object>> UpdatePermissionAsync(string realm, string accessToken, string id,
        KcAdminPermission permission,
        CancellationToken cancellationToken = default);

    /// <summary>Deletes a scope-based FGAP v2 permission.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="id">Server policy or permission UUID.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<object>> DeletePermissionAsync(string realm, string accessToken, string id,
        CancellationToken cancellationToken = default);

    /// <summary>Creates a permission restricted to exactly one organization UUID.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token; never written to logs.</param>
    /// <param name="organizationId">Target organization UUID.</param>
    /// <param name="permission">Permission using scope names and entity UUIDs.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<KcAdminPermission>> CreateOrganizationPermissionAsync(string realm, string accessToken,
        string organizationId, KcAdminPermission permission,
        CancellationToken cancellationToken = default);

    /// <summary>Applies explicit V2 declarations by stable name; preserves omitted server objects.
    /// Merge by name; retain omitted objects. Stop on first server error; no transaction or rollback is provided.
    /// </summary>
    /// <param name="realm">Realm name.</param>
    /// <param name="accessToken">Administrator access token.</param>
    /// <param name="configuration">Explicit V2 merge-only declaration.</param>
    /// <param name="cancellationToken">Token that cancels the request.</param>
    /// <returns>The server result, including structured errors and request metrics.</returns>
    Task<KcResponse<KcAdminPermissionsApplyResult>> ApplyConfigurationAsync(string realm, string accessToken,
        KcAdminPermissionsConfiguration configuration,
        CancellationToken cancellationToken = default);
}
