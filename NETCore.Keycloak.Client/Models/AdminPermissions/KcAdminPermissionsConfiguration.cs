using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace NETCore.Keycloak.Client.Models.AdminPermissions;

/// <summary>Selects the administrative permission model explicitly; existing clients default to V1.</summary>
public enum KcAdminPermissionsVersion
{
    /// <summary>Preserve existing per-resource management-permission APIs.</summary>
    V1,
    /// <summary>Use the Keycloak 26.8.1 admin-permissions authorization model.</summary>
    V2
}

/// <summary>
/// Declarative, merge-only FGAP configuration. Loading configuration never changes a server.
/// Apply explicitly through the AdminPermissions client; omitted server objects are retained.
/// </summary>
public sealed class KcAdminPermissionsConfiguration
{
    /// <summary>Gets or sets the model. V1 preserves existing behavior.</summary>
    public KcAdminPermissionsVersion Version { get; set; } = KcAdminPermissionsVersion.V1;

    /// <summary>Gets or sets whether explicit application enables realm admin permissions.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Gets or sets policies, identified by stable names. Aggregates may reference declared policy
    /// names.</summary>
    public IList<KcAdminPolicy> Policies { get; set; } = new List<KcAdminPolicy>();

    /// <summary>Gets or sets permissions. Policy references may be declared names or existing server policy
    /// IDs.</summary>
    public IList<KcAdminPermission> Permissions { get; set; } = new List<KcAdminPermission>();

    /// <summary>
    /// Loads JSON and overlays VERSION/ENABLED under the supplied environment prefix.
    /// Unknown properties, numeric versions, and invalid environment values are rejected.
    /// Environment variables never silently select a different server feature version.
    /// </summary>
    /// <param name="json">The declarative JSON document.</param>
    /// <param name="environmentPrefix">Prefix, default KEYCLOAK_FGAP_.</param>
    /// <returns>The loaded configuration; no HTTP requests are made.</returns>
    public static KcAdminPermissionsConfiguration FromJson(string json,
        string environmentPrefix = "KEYCLOAK_FGAP_")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        var settings = new JsonSerializerSettings { MissingMemberHandling = MissingMemberHandling.Error };
        settings.Converters.Add(new StringEnumConverter { AllowIntegerValues = false });
        var configuration = JsonConvert.DeserializeObject<KcAdminPermissionsConfiguration>(json, settings)
            ?? throw new ArgumentException("FGAP configuration must be an object.", nameof(json));
        configuration.ApplyEnvironment(environmentPrefix);
        return configuration;
    }

    /// <summary>Loads explicit route selection from environment variables, defaulting to V1.</summary>
    /// <param name="environmentPrefix">Prefix, default KEYCLOAK_FGAP_.</param>
    /// <returns>The selected configuration without changing the server.</returns>
    public static KcAdminPermissionsConfiguration FromEnvironment(string environmentPrefix = "KEYCLOAK_FGAP_")
    {
        var configuration = new KcAdminPermissionsConfiguration();
        configuration.ApplyEnvironment(environmentPrefix);
        return configuration;
    }

    private void ApplyEnvironment(string prefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        var version = Environment.GetEnvironmentVariable(prefix + "VERSION");
        if ( version != null )
        {
            if ( !string.Equals(version, "V1", StringComparison.OrdinalIgnoreCase) &&
                 !string.Equals(version, "V2", StringComparison.OrdinalIgnoreCase) )
            {
                throw new ArgumentException("FGAP VERSION must be V1 or V2.", nameof(prefix));
            }
            Version = Enum.Parse<KcAdminPermissionsVersion>(version, true);
        }
        var enabled = Environment.GetEnvironmentVariable(prefix + "ENABLED");
        if ( enabled == null ) return;
        if ( !bool.TryParse(enabled, out var value) )
        {
            throw new ArgumentException("FGAP ENABLED must be true or false.", nameof(prefix));
        }
        Enabled = value;
    }
}
