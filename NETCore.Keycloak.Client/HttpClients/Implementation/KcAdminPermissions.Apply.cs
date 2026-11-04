using NETCore.Keycloak.Client.Models;
using NETCore.Keycloak.Client.Models.AdminPermissions;
using Newtonsoft.Json.Linq;

namespace NETCore.Keycloak.Client.HttpClients.Implementation;

internal sealed partial class KcAdminPermissions
{
    public async Task<KcResponse<KcAdminPermissionsApplyResult>> ApplyConfigurationAsync(string realm,
        string accessToken, KcAdminPermissionsConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        Guard(realm, accessToken);
        var ordered = KcAdminPermissionsValidation.Order(configuration);
        var enabled = await SetRealmEnabledAsync(realm, accessToken, configuration.Enabled, cancellationToken)
            .ConfigureAwait(false);
        if ( enabled.IsError ) return Failure<KcAdminPermissionsApplyResult, object>(enabled);
        var progress = new KcAdminPermissionsApplyResult();
        if ( !configuration.Enabled ) return Map(enabled, _ => progress);
        var policies = await ReadAllPoliciesAsync(realm, accessToken, cancellationToken).ConfigureAwait(false);
        if ( policies.IsError ) return Failure<KcAdminPermissionsApplyResult, IList<KcAdminPolicy>>(policies);
        var permissions = await ReadAllPermissionsAsync(realm, accessToken, cancellationToken).ConfigureAwait(false);
        if ( permissions.IsError ) return Failure<KcAdminPermissionsApplyResult, IList<KcAdminPermission>>(permissions);
        var policyIndex = policies.Response.ToDictionary(p => p.Name, StringComparer.Ordinal);
        ValidateReferences(configuration, policyIndex);
        foreach ( var policy in ordered )
        {
            cancellationToken.ThrowIfCancellationRequested();
            var desired = JObject.FromObject(policy).ToObject<KcAdminPolicy>();
            if ( desired.Policies != null ) desired.Policies = Resolve(desired.Policies, policyIndex);
            var saved = await SavePolicyAsync(realm, accessToken, desired, policyIndex, cancellationToken)
                .ConfigureAwait(false);
            if ( saved.IsError ) return Failure<KcAdminPermissionsApplyResult, KcAdminPolicy>(saved);
            policyIndex[desired.Name] = saved.Response;
            progress.PoliciesApplied++;
        }
        return await ApplyPermissionsAsync(realm, accessToken, configuration.Permissions, permissions.Response,
            policyIndex, progress, cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateReferences(KcAdminPermissionsConfiguration configuration,
        IDictionary<string, KcAdminPolicy> existing)
    {
        var declared = configuration.Policies.ToDictionary(p => p.Name, StringComparer.Ordinal);
        foreach ( var policy in configuration.Policies )
            if ( existing.TryGetValue(policy.Name, out var old) && old.Type != policy.Type )
                throw new ArgumentException("An existing policy has a different type: " + policy.Name);
        var references = configuration.Policies.SelectMany(p => p.Policies ?? Array.Empty<string>())
            .Concat(configuration.Permissions.SelectMany(p => p.Policies));
        var ids = existing.Values.Select(p => p.Id).ToHashSet(StringComparer.Ordinal);
        foreach ( var reference in references )
            if ( !declared.ContainsKey(reference) && !existing.ContainsKey(reference) && !ids.Contains(reference) )
                throw new ArgumentException("Unknown policy reference: " + reference);
    }

    private static List<string> Resolve(IEnumerable<string> references, IDictionary<string, KcAdminPolicy> index) =>
        references.Select(reference => index.TryGetValue(reference, out var policy) ? policy.Id : reference).ToList();

    private async Task<KcResponse<KcAdminPolicy>> SavePolicyAsync(string realm, string token, KcAdminPolicy policy,
        Dictionary<string, KcAdminPolicy> existing, CancellationToken cancellationToken)
    {
        if ( !existing.TryGetValue(policy.Name, out var old) )
            return await CreatePolicyAsync(realm, token, policy, cancellationToken).ConfigureAwait(false);
        var updated = await UpdatePolicyAsync(realm, token, old.Id, policy, cancellationToken).ConfigureAwait(false);
        policy.Id = old.Id;
        return Map(updated, _ => policy);
    }

    private async Task<KcResponse<KcAdminPermissionsApplyResult>> ApplyPermissionsAsync(string realm, string token,
        IEnumerable<KcAdminPermission> desired, IList<KcAdminPermission> existing,
        IDictionary<string, KcAdminPolicy> policies, KcAdminPermissionsApplyResult progress,
        CancellationToken cancellationToken)
    {
        var index = existing.ToDictionary(p => p.Name, StringComparer.Ordinal);
        foreach ( var permission in desired )
        {
            cancellationToken.ThrowIfCancellationRequested();
            var copy = JObject.FromObject(permission).ToObject<KcAdminPermission>();
            copy.Policies = Resolve(copy.Policies, policies);
            if ( index.TryGetValue(copy.Name, out var old) )
            {
                var updated = await UpdatePermissionAsync(realm, token, old.Id, copy, cancellationToken)
                    .ConfigureAwait(false);
                if ( updated.IsError ) return Failure<KcAdminPermissionsApplyResult, object>(updated);
            }
            else
            {
                var created = await CreatePermissionAsync(realm, token, copy, cancellationToken).ConfigureAwait(false);
                if ( created.IsError ) return Failure<KcAdminPermissionsApplyResult, KcAdminPermission>(created);
            }
            progress.PermissionsApplied++;
        }
        return new KcResponse<KcAdminPermissionsApplyResult> { Response = progress };
    }

    private async Task<KcResponse<IList<KcAdminPolicy>>> ReadAllPoliciesAsync(string realm, string token,
        CancellationToken cancellationToken)
    {
        var all = new List<KcAdminPolicy>();
        while ( true )
        {
            var page = await ListPoliciesAsync(realm, token, all.Count, 100,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if ( page.IsError ) return Failure<IList<KcAdminPolicy>, IEnumerable<KcAdminPolicy>>(page);
            var items = page.Response?.ToArray() ?? [];
            if ( items.Any(item => all.Any(old => old.Id == item.Id)) )
                return Error<IList<KcAdminPolicy>>("Policy pagination repeated identifiers; application stopped.");
            all.AddRange(items);
            if ( items.Length < 100 ) return Map(page, _ => ( IList<KcAdminPolicy> ) all);
        }
    }

    private async Task<KcResponse<IList<KcAdminPermission>>> ReadAllPermissionsAsync(string realm, string token,
        CancellationToken cancellationToken)
    {
        var all = new List<KcAdminPermission>();
        while ( true )
        {
            var page = await ListPermissionsAsync(realm, token, all.Count, 100,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if ( page.IsError ) return Failure<IList<KcAdminPermission>, IEnumerable<KcAdminPermission>>(page);
            var items = page.Response?.ToArray() ?? [];
            if ( items.Any(item => all.Any(old => old.Id == item.Id)) )
                return Error<IList<KcAdminPermission>>(
                    "Permission pagination repeated identifiers; application stopped.");
            all.AddRange(items);
            if ( items.Length < 100 ) return Map(page, _ => ( IList<KcAdminPermission> ) all);
        }
    }
}
