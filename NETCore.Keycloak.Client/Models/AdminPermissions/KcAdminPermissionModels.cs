using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace NETCore.Keycloak.Client.Models.AdminPermissions;

/// <summary>A built-in authorization policy. Typed fields serve provider endpoints; Config preserves generic
/// responses.</summary>
[JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
public sealed class KcAdminPolicy
{
    /// <summary>Gets or sets the server policy identifier.</summary>
    [JsonProperty("id")]
    public string Id { get; set; }

    /// <summary>Gets or sets the stable policy name.</summary>
    [JsonProperty("name")]
    public string Name { get; set; }

    /// <summary>Gets or sets the optional description.</summary>
    [JsonProperty("description")]
    public string Description { get; set; }

    /// <summary>Gets or sets the built-in user, group, role, aggregate, client, time or regex type. Preview scripts
    /// are excluded.</summary>
    [JsonProperty("type")]
    public string Type { get; set; }

    /// <summary>Gets or sets the POSITIVE or NEGATIVE logic.</summary>
    [JsonProperty("logic")]
    public string Logic { get; set; }

    /// <summary>Gets or sets the aggregated policy decision strategy.</summary>
    [JsonProperty("decisionStrategy")]
    public string DecisionStrategy { get; set; }

    /// <summary>Gets or sets the user identifiers.</summary>
    [JsonProperty("users")]
    public IList<string> Users { get; set; }

    /// <summary>Gets or sets the group selectors.</summary>
    [JsonProperty("groups")]
    public IList<KcAdminGroupDefinition> Groups { get; set; }

    /// <summary>Gets or sets the role selectors.</summary>
    [JsonProperty("roles")]
    public IList<KcAdminRoleDefinition> Roles { get; set; }

    /// <summary>Gets or sets the client identifiers.</summary>
    [JsonProperty("clients")]
    public IList<string> Clients { get; set; }

    /// <summary>Gets or sets the policy identifiers, or declared names during application.</summary>
    [JsonProperty("policies")]
    public IList<string> Policies { get; set; }

    /// <summary>Gets or sets whether roles are resolved from stored assignments.</summary>
    [JsonProperty("fetchRoles")]
    public bool? FetchRoles { get; set; }

    /// <summary>Gets or sets the generic configuration returned by policy listing.</summary>
    [JsonProperty("config")]
    public IDictionary<string, string> Config { get; set; }

    /// <summary>Gets or sets the built-in provider field notBefore.</summary>
    [JsonProperty("notBefore")]
    public string NotBefore { get; set; }

    /// <summary>Gets or sets the built-in provider field notOnOrAfter.</summary>
    [JsonProperty("notOnOrAfter")]
    public string NotOnOrAfter { get; set; }

    /// <summary>Gets or sets the built-in provider field targetClaim.</summary>
    [JsonProperty("targetClaim")]
    public string TargetClaim { get; set; }

    /// <summary>Gets or sets the built-in provider field pattern.</summary>
    [JsonProperty("pattern")]
    public string Pattern { get; set; }

    /// <summary>Gets or sets the built-in provider field dayMonth.</summary>
    [JsonProperty("dayMonth")]
    public int? DayMonth { get; set; }

    /// <summary>Gets or sets the built-in provider field dayMonthEnd.</summary>
    [JsonProperty("dayMonthEnd")]
    public int? DayMonthEnd { get; set; }

    /// <summary>Gets or sets the built-in provider field month.</summary>
    [JsonProperty("month")]
    public int? Month { get; set; }

    /// <summary>Gets or sets the built-in provider field monthEnd.</summary>
    [JsonProperty("monthEnd")]
    public int? MonthEnd { get; set; }

    /// <summary>Gets or sets the built-in provider field year.</summary>
    [JsonProperty("year")]
    public int? Year { get; set; }

    /// <summary>Gets or sets the built-in provider field yearEnd.</summary>
    [JsonProperty("yearEnd")]
    public int? YearEnd { get; set; }

    /// <summary>Gets or sets the built-in provider field hour.</summary>
    [JsonProperty("hour")]
    public int? Hour { get; set; }

    /// <summary>Gets or sets the built-in provider field hourEnd.</summary>
    [JsonProperty("hourEnd")]
    public int? HourEnd { get; set; }

    /// <summary>Gets or sets the built-in provider field minute.</summary>
    [JsonProperty("minute")]
    public int? Minute { get; set; }

    /// <summary>Gets or sets the built-in provider field minuteEnd.</summary>
    [JsonProperty("minuteEnd")]
    public int? MinuteEnd { get; set; }

    /// <summary>Gets or sets built-in provider fields, such as time constraints. Reserved fields cannot be shadowed.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, JToken> AdditionalProperties { get; set; }
}

/// <summary>A group-policy selector.</summary>
[JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
public sealed class KcAdminGroupDefinition
{
    /// <summary>Gets or sets the group identifier.</summary>
    [JsonProperty("id")]
    public string Id { get; set; }

    /// <summary>Gets or sets the optional group path.</summary>
    [JsonProperty("path")]
    public string Path { get; set; }

    /// <summary>Gets or sets whether descendants are included.</summary>
    [JsonProperty("extendChildren")]
    public bool ExtendChildren { get; set; }

}

/// <summary>A role-policy selector.</summary>
[JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
public sealed class KcAdminRoleDefinition
{
    /// <summary>Gets or sets the role identifier.</summary>
    [JsonProperty("id")]
    public string Id { get; set; }

    /// <summary>Gets or sets whether the role is required.</summary>
    [JsonProperty("required")]
    public bool Required { get; set; }

}

/// <summary>A scope-based FGAP v2 permission. Writes use entity UUIDs; omit Resources for the entire type.</summary>
[JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
public sealed class KcAdminPermission
{
    /// <summary>Gets or sets the server permission identifier.</summary>
    [JsonProperty("id")]
    public string Id { get; set; }

    /// <summary>Gets or sets the stable permission name.</summary>
    [JsonProperty("name")]
    public string Name { get; set; }

    /// <summary>Gets or sets the optional description.</summary>
    [JsonProperty("description")]
    public string Description { get; set; }

    /// <summary>Gets or sets the users, Groups, Clients, Roles or Organizations.</summary>
    [JsonProperty("resourceType")]
    public string ResourceType { get; set; }

    /// <summary>Gets or sets the target resource identifiers; null or empty selects all resources of this
    /// type.</summary>
    [JsonProperty("resources")]
    public IList<string> Resources { get; set; }

    /// <summary>Gets or sets the supported non-Preview scopes for this type.</summary>
    [JsonProperty("scopes")]
    public IList<string> Scopes { get; set; }

    /// <summary>Gets or sets the policy identifiers, or declared names during application.</summary>
    [JsonProperty("policies")]
    public IList<string> Policies { get; set; }

    /// <summary>Gets or sets the decision strategy; only UNANIMOUS is accepted.</summary>
    [JsonProperty("decisionStrategy")]
    public string DecisionStrategy { get; set; }

}

/// <summary>Completed merge-only operations. Application is sequential and is not transactional.</summary>
[JsonObject(ItemNullValueHandling = NullValueHandling.Ignore)]
public sealed class KcAdminPermissionsApplyResult
{
    /// <summary>Gets or sets the number of applied policies.</summary>
    [JsonProperty("policiesApplied")]
    public int PoliciesApplied { get; set; }

    /// <summary>Gets or sets the number of applied permissions.</summary>
    [JsonProperty("permissionsApplied")]
    public int PermissionsApplied { get; set; }

}
