using NETCore.Keycloak.Client.Models;
using NETCore.Keycloak.Client.Models.AdminPermissions;
using Newtonsoft.Json.Linq;

namespace NETCore.Keycloak.Client.HttpClients.Implementation;

internal sealed partial class KcAdminPermissions
{
    // Provider representations omit associations. Fetch dedicated associations so read-modify-write
    // does not broaden resource selection or erase policy links.
    private async Task<KcResponse<KcAdminPermission>> NormalizePermissionAsync(string realm, string token,
        KcResponse<KcAdminPermission> result, CancellationToken cancellationToken)
    {
        if ( result.IsError || result.Response == null ) return result;
        var permission = result.Response;
        var path = "permission/scope/" + KcAdminPermissionsValidation.Segment(permission.Id);
        var scopes = await AssociationsAsync(realm, token, path, "scopes", cancellationToken).ConfigureAwait(false);
        if ( scopes.IsError ) return Failure<KcAdminPermission, JArray>(scopes);
        var resources = await AssociationsAsync(realm, token, path, "resources", cancellationToken)
            .ConfigureAwait(false);
        if ( resources.IsError ) return Failure<KcAdminPermission, JArray>(resources);
        var policies = await AssociationsAsync(realm, token, path, "associatedPolicies", cancellationToken)
            .ConfigureAwait(false);
        if ( policies.IsError ) return Failure<KcAdminPermission, JArray>(policies);
        permission.Scopes = scopes.Response.Select(s => s.Value<string>("name")).ToList();
        var names = resources.Response.Select(r => r.Value<string>("name")).ToList();
        if ( names.Any(string.IsNullOrWhiteSpace) || permission.Scopes.Any(string.IsNullOrWhiteSpace) )
            return Error<KcAdminPermission>("The permission associations contain unresolved names.");
        if ( names.Contains(permission.ResourceType, StringComparer.Ordinal) && names.Count != 1 )
            return Error<KcAdminPermission>("The permission mixes global and specific resource selectors.");
        permission.Resources = names.Contains(permission.ResourceType, StringComparer.Ordinal) ? [] : names;
        permission.Policies = policies.Response.Select(p => p.Value<string>("id")).ToList();
        return result;
    }

    private Task<KcResponse<JArray>> AssociationsAsync(string realm, string token, string path, string association,
        CancellationToken cancellationToken) =>
        AuthorizationAsync<JArray>(realm, token, path + "/" + association, HttpMethod.Get, null, cancellationToken);
}
