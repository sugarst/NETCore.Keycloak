using NETCore.Keycloak.Client.Models.AdminPermissions;
using Newtonsoft.Json.Linq;

namespace NETCore.Keycloak.Client.HttpClients.Implementation;

internal static class KcAdminPermissionsValidation
{
    private static readonly HashSet<string> PolicyTypes =
        new(StringComparer.Ordinal) { "user", "group", "role", "aggregate", "client", "time", "regex" };
    private static readonly Dictionary<string, string[]> Scopes = new(StringComparer.Ordinal)
    {
        ["Users"] = ["view", "manage", "map-roles", "manage-group-membership", "impersonate", "reset-password"],
        ["Groups"] = ["view", "manage", "view-members", "manage-members", "manage-membership",
            "manage-membership-of-members", "impersonate-members"],
        ["Clients"] = ["view", "manage", "map-roles", "map-roles-composite", "map-roles-client-scope"],
        ["Roles"] = ["map-role", "map-role-composite", "map-role-client-scope"],
        ["Organizations"] = ["view", "manage"]
    };
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "id", "name", "description", "type", "logic", "decisionStrategy", "users", "groups", "roles", "clients",
        "policies", "fetchRoles", "config", "resources", "resourceType", "scopes", "notBefore", "notOnOrAfter",
        "targetClaim", "pattern", "dayMonth", "dayMonthEnd", "month", "monthEnd", "year", "yearEnd",
        "hour", "hourEnd", "minute", "minuteEnd"
    };

    internal static string Segment(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if ( value is "." or ".." || value.Contains('/', StringComparison.Ordinal) ||
             value.Contains('\\', StringComparison.Ordinal) )
            throw new ArgumentException("A realm, type or identifier must be a single path segment.", nameof(value));
        return Uri.EscapeDataString(value);
    }

    internal static void PolicyType(string type)
    {
        if ( !PolicyTypes.Contains(type ?? "") )
            throw new ArgumentException("Unsupported policy type. Scripts and Preview providers are excluded.",
                nameof(type));
    }

    internal static void Policy(KcAdminPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(policy.Name);
        PolicyType(policy.Type);
        if ( policy.Logic != null && policy.Logic is not ("POSITIVE" or "NEGATIVE") )
            throw new ArgumentException("Policy logic must be POSITIVE or NEGATIVE.", nameof(policy));
        if ( policy.DecisionStrategy != null &&
            policy.DecisionStrategy is not ("UNANIMOUS" or "AFFIRMATIVE" or "CONSENSUS") )
            throw new ArgumentException("Unsupported policy decision strategy.", nameof(policy));
        if ( policy.AdditionalProperties?.Keys.Any(Reserved.Contains) == true )
            throw new ArgumentException("Provider fields cannot shadow reserved fields.", nameof(policy));
    }

    internal static void Permission(KcAdminPermission permission)
    {
        ArgumentNullException.ThrowIfNull(permission);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission.Name);
        if ( !Scopes.TryGetValue(permission.ResourceType ?? "", out var valid) )
            throw new ArgumentException("Unknown FGAP v2 resource type.", nameof(permission));
        if ( permission.Scopes == null || permission.Scopes.Count == 0 ||
             permission.Scopes.Any(scope => !valid.Contains(scope, StringComparer.Ordinal)) )
            throw new ArgumentException("Invalid scope; Preview delegation scopes are not supported.",
                nameof(permission));
        if ( permission.Policies == null || permission.Policies.Count == 0 ||
             permission.Policies.Any(string.IsNullOrWhiteSpace) )
            throw new ArgumentException("At least one policy reference is required.", nameof(permission));
        if ( permission.Resources?.Any(string.IsNullOrWhiteSpace) == true )
            throw new ArgumentException("Resource identifiers cannot be empty.", nameof(permission));
        if ( permission.DecisionStrategy != null && permission.DecisionStrategy != "UNANIMOUS" )
            throw new ArgumentException("FGAP v2 permissions require UNANIMOUS.", nameof(permission));
    }

    internal static void ResourceScope(string type, string scope = null)
    {
        if ( !Scopes.TryGetValue(type ?? "", out var valid) )
            throw new ArgumentException("Unknown FGAP v2 resource type.", nameof(type));
        if ( scope != null && !valid.Contains(scope, StringComparer.Ordinal) )
            throw new ArgumentException("Unsupported scope; Preview scopes are excluded.", nameof(scope));
    }

    internal static JObject PermissionBody(KcAdminPermission permission)
    {
        var body = JObject.FromObject(permission);
        body["decisionStrategy"] = "UNANIMOUS";
        return body;
    }

    internal static IList<KcAdminPolicy> Order(KcAdminPermissionsConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if ( configuration.Version != KcAdminPermissionsVersion.V2 )
            throw new InvalidOperationException("Declarative application requires explicit V2 selection.");
        var policies = configuration.Policies ?? throw new ArgumentException("Policies cannot be null.");
        var permissions = configuration.Permissions ?? throw new ArgumentException("Permissions cannot be null.");
        foreach ( var policy in policies ) Policy(policy);
        foreach ( var permission in permissions ) Permission(permission);
        var names = policies.Select(p => p.Name).Concat(permissions.Select(p => p.Name)).ToList();
        if ( names.Distinct(StringComparer.Ordinal).Count() != names.Count )
            throw new ArgumentException("Policy and permission names must be unique.", nameof(configuration));
        if ( !configuration.Enabled && names.Count > 0 )
            throw new ArgumentException("A disabled configuration cannot also apply policies or permissions.");
        var ordered = new List<KcAdminPolicy>();
        var remaining = policies.ToList();
        while ( remaining.Count > 0 )
        {
            var next = remaining.FirstOrDefault(p => p.Type != "aggregate" ||
                p.Policies?.Any(reference => remaining.Any(other => other.Name == reference)) != true);
            if ( next == null ) throw new ArgumentException("Cyclic aggregate-policy references.");
            ordered.Add(next);
            _ = remaining.Remove(next);
        }
        return ordered;
    }
}
