using System.Net;
using NETCore.Keycloak.Client.HttpClients.Implementation;
using NETCore.Keycloak.Client.Models.AdminPermissions;
using NETCore.Keycloak.Client.Models.Common;
using NETCore.Keycloak.Client.Tests.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace NETCore.Keycloak.Client.Tests.Modules.KcCompatibilityTests;

/// <summary>Protects explicit routing, configuration validation and fail-closed request boundaries without
/// Docker.</summary>
[TestClass]
[TestCategory("CoverageUnit")]
public sealed class KcFgapConfigurationUnitTests
{
    /// <summary>Environment overrides are explicit and invalid values never fall back to V1.</summary>
    [TestMethod]
    public void ShouldLoadJsonWithEnvironmentOverrides()
    {
        var prefix = "FGAP_UNIT_" + Guid.NewGuid().ToString("N") + "_";
        try
        {
            var json = "{\"version\":\"V2\",\"enabled\":true}";
            Assert.AreEqual(KcAdminPermissionsVersion.V2,
                KcAdminPermissionsConfiguration.FromJson(json, prefix).Version);
            Environment.SetEnvironmentVariable(prefix + "VERSION", "V1");
            Environment.SetEnvironmentVariable(prefix + "ENABLED", "false");
            var configuration = KcAdminPermissionsConfiguration.FromJson(json, prefix);
            Assert.AreEqual(KcAdminPermissionsVersion.V1, configuration.Version);
            Assert.IsFalse(configuration.Enabled);
            Assert.AreEqual(KcAdminPermissionsVersion.V1,
                KcAdminPermissionsConfiguration.FromEnvironment(prefix).Version);
            Environment.SetEnvironmentVariable(prefix + "VERSION", "preview");
            _ = Assert.ThrowsExactly<ArgumentException>(() => KcAdminPermissionsConfiguration.FromEnvironment(prefix));
            Environment.SetEnvironmentVariable(prefix + "VERSION", "V2");
            Environment.SetEnvironmentVariable(prefix + "ENABLED", "perhaps");
            _ = Assert.ThrowsExactly<ArgumentException>(() => KcAdminPermissionsConfiguration.FromEnvironment(prefix));
        }
        finally
        {
            Environment.SetEnvironmentVariable(prefix + "VERSION", null);
            Environment.SetEnvironmentVariable(prefix + "ENABLED", null);
        }
    }

    /// <summary>Rejects malformed/unknown configuration rather than silently accepting a misspelled route.</summary>
    /// <param name="json">Invalid input.</param>
    [TestMethod]
    [DataRow("{\"version\":1}")]
    [DataRow("{\"version\":\"V3\"}")]
    [DataRow("{\"versoin\":\"V2\"}")]
    public void ShouldRejectInvalidConfiguration(string json) =>
        _ = Assert.ThrowsExactly<JsonSerializationException>(() =>
            KcAdminPermissionsConfiguration.FromJson(json, "FGAP_UNIT_UNUSED_"));

    /// <summary>Legacy construction and APIs remain available; V2 is immutable and cannot silently fall back.</summary>
    [TestMethod]
    public async Task ShouldPreserveLegacyRouteAsync()
    {
        var paths = new List<string>();
        using var transport = new StubHttpTransport(request =>
        {
            paths.Add(request.RequestUri.AbsolutePath);
            return Task.FromResult(StubHttpTransport.Json("{\"enabled\":true}"));
        });
        var client = new KeycloakClient("https://keycloak.test", null, transport);
        Assert.AreEqual(KcAdminPermissionsVersion.V1, client.AdminPermissions.SelectedVersion);
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            client.AdminPermissions.GetRealmEnabledAsync("test", "token")).ConfigureAwait(false);
        Assert.AreEqual(0, paths.Count);
        _ = await client.Groups.SetAuthorizationManagementPermissionAsync("test", "token", "group",
            new KcPermissionManagement { Enabled = true }).ConfigureAwait(false);
        Assert.AreEqual("/admin/realms/test/groups/group/management/permissions", paths.Single());
        var configuration = new KcAdminPermissionsConfiguration { Version = KcAdminPermissionsVersion.V2 };
        var selected = new KeycloakClient("https://keycloak.test", null, transport, configuration);
        configuration.Version = KcAdminPermissionsVersion.V1;
        Assert.AreEqual(KcAdminPermissionsVersion.V2, selected.AdminPermissions.SelectedVersion);
    }

    /// <summary>Preview scopes, invalid operation/type combinations and non-unanimous permissions never reach
    /// HTTP.</summary>
    /// <param name="type">Resource type.</param>
    /// <param name="scope">Unsupported scope.</param>
    [TestMethod]
    [DataRow("Users", "delegate")]
    [DataRow("Groups", "delegate-members")]
    [DataRow("Roles", "manage")]
    [DataRow("Realms", "view")]
    public async Task ShouldRejectUnsupportedScopesAsync(string type, string scope)
    {
        using var transport = new StubHttpTransport(_ => throw new AssertFailedException("No HTTP expected."));
        var client = V2(transport);
        _ = Assert.ThrowsExactly<ArgumentException>(() => client.AdminPermissions.ListPermissionsAsync(
            "test", "token", resourceType: type, scope: scope));
        _ = Assert.ThrowsExactly<ArgumentException>(() => client.AdminPermissions.EvaluatePermissionAsync(
            "test", "token", "actor", type, "target", [scope]));
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(() => client.AdminPermissions.CreatePermissionAsync(
            "test", "token", new KcAdminPermission
            { Name = "invalid", ResourceType = type, Scopes = [scope], Policies = ["policy"] })).ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(() => client.AdminPermissions.CreatePermissionAsync(
            "test", "token",
            new KcAdminPermission
            {
                Name = "invalid",
                ResourceType = "Users",
                Scopes = ["view"],
                Policies = ["policy"],
                DecisionStrategy = "AFFIRMATIVE"
            })).ConfigureAwait(false);
    }

    /// <summary>Rejects scripts, provider field shadowing, traversal IDs, and cyclic declarations before
    /// writes.</summary>
    [TestMethod]
    public async Task ShouldRejectUnsafeDeclarationsAsync()
    {
        using var transport = new StubHttpTransport(_ => throw new AssertFailedException("No HTTP expected."));
        var client = V2(transport);
        _ = Assert.ThrowsExactly<ArgumentException>(() => client.AdminPermissions.CreatePolicyAsync("test", "token",
            new KcAdminPolicy { Name = "script", Type = "js" }));
        _ = Assert.ThrowsExactly<ArgumentException>(() => client.AdminPermissions.CreatePolicyAsync("test", "token",
            new KcAdminPolicy
            {
                Name = "shadow",
                Type = "user",
                AdditionalProperties = new Dictionary<string, JToken> { ["type"] = "js" }
            }));
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            client.AdminPermissions.GetPermissionAsync("test", "token", "../x")).ConfigureAwait(false);
        var configuration = new KcAdminPermissionsConfiguration
        {
            Version = KcAdminPermissionsVersion.V2,
            Policies = [new KcAdminPolicy { Name = "cycle", Type = "aggregate", Policies = ["cycle"] }]
        };
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            client.AdminPermissions.ApplyConfigurationAsync("test", "token", configuration)).ConfigureAwait(false);
    }

    /// <summary>Rejects disabled/missing V2 servers and forwards authorization failures without falling back.</summary>
    /// <param name="kind">Failure stage.</param>
    [TestMethod]
    [DataRow("disabled")]
    [DataRow("missing")]
    [DataRow("denied")]
    public async Task ShouldFailClosedAsync(string kind)
    {
        var requests = new List<string>();
        using var transport = new StubHttpTransport(request =>
        {
            requests.Add(request.RequestUri.PathAndQuery);
            if ( kind == "denied" )
                return Task.FromResult(StubHttpTransport.Json("{}", HttpStatusCode.Forbidden));
            return Task.FromResult(StubHttpTransport.Json(request.RequestUri.AbsolutePath.EndsWith("/clients",
                StringComparison.Ordinal) ? "[]" : "{\"adminPermissionsEnabled\":" +
                (kind == "disabled" ? "false" : "true") + "}"));
        });
        var result = await V2(transport).AdminPermissions.ListPoliciesAsync("test", "token").ConfigureAwait(false);
        Assert.IsTrue(result.IsError);
        Assert.IsFalse(requests.Any(path => path.Contains("realm-management", StringComparison.Ordinal)));
        Assert.IsFalse(requests.Any(path => path.Contains("authz", StringComparison.Ordinal)));
    }

    private static KeycloakClient V2(IHttpClientFactory transport) => new("https://keycloak.test", null, transport,
        new KcAdminPermissionsConfiguration { Version = KcAdminPermissionsVersion.V2 });
}
