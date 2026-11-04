using System.Net;
using System.Net.Http.Headers;
using System.Text;
using NETCore.Keycloak.Client.HttpClients.Implementation;
using NETCore.Keycloak.Client.Models;
using NETCore.Keycloak.Client.Models.AdminPermissions;
using NETCore.Keycloak.Client.Models.Auth;
using NETCore.Keycloak.Client.Models.Organizations;
using NETCore.Keycloak.Client.Tests.Abstraction;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace NETCore.Keycloak.Client.Tests.Modules.KcCompatibilityTests;

/// <summary>Real Keycloak 26.8.1 FGAP v2 CRUD, declarative application and delegated organization boundaries.</summary>
[TestClass]
[TestCategory("FGAPV2")]
public sealed class KcFgapV2Tests : KcTestingModule, IDisposable
{
    private readonly HttpClient _setup = new();
    private KeycloakClient _client;
    private string _token;
    private string _realm;
    private string _user;
    private string _actor;
    private string _group;
    private string _role;
    private string _oidcClient;
    private string _organization;
    private const string Password = "Fgap-Tests_2681!Password";

    /// <summary>Creates an isolated realm. FGAP setup operations under test use the new public client.</summary>
    [TestInitialize]
    public async Task InitializeAsync()
    {
        _client = new KeycloakClient(TestEnvironment.BaseUrl, null, null,
            new KcAdminPermissionsConfiguration { Version = KcAdminPermissionsVersion.V2 });
        _token = Success(await _client.Auth.GetResourceOwnerPasswordTokenAsync(TestEnvironment.AuthRealm,
            new KcClientCredentials { ClientId = TestEnvironment.ClientId }, TestEnvironment.Admin)
            .ConfigureAwait(false)).AccessToken;
        var server = await SetupAsync(HttpMethod.Get, "admin/serverinfo").ConfigureAwait(false);
        Assert.AreEqual("26.8.1", server["systemInfo"]?["version"]?.Value<string>());
        Assert.IsTrue(server["profileInfo"]?["disabledFeatures"]?.Values<string>()
            .Contains("ADMIN_FINE_GRAINED_AUTHZ") == true, "This category requires the FGAP v2 test profile.");
        _realm = "netcore_fgap_" + Guid.NewGuid().ToString("N");
        _ = await SetupAsync(HttpMethod.Post, "admin/realms", new
        {
            realm = _realm,
            enabled = true,
            organizationsEnabled = true
        }).ConfigureAwait(false);
        Assert.IsFalse(Success(await _client.AdminPermissions.GetRealmEnabledAsync(_realm, _token)
            .ConfigureAwait(false)));
        _ = Success(await _client.AdminPermissions.SetRealmEnabledAsync(_realm, _token, true).ConfigureAwait(false));
        var root = "admin/realms/" + _realm;
        _user = await CreateUserAsync("target").ConfigureAwait(false);
        _actor = await CreateUserAsync("operator").ConfigureAwait(false);
        _ = await SetupAsync(HttpMethod.Post, root + "/groups", new { name = "operators" }).ConfigureAwait(false);
        _group = (await SetupAsync(HttpMethod.Get, root + "/groups")
            .ConfigureAwait(false)).Single()["id"].Value<string>();
        _ = await SetupAsync(HttpMethod.Post, root + "/roles", new { name = "business-role" }).ConfigureAwait(false);
        _role = (await SetupAsync(HttpMethod.Get, root + "/roles/business-role")
            .ConfigureAwait(false))["id"].Value<string>();
        _ = await SetupAsync(HttpMethod.Post, root + "/clients", new
        {
            clientId = "fgap-app",
            protocol = "openid-connect",
            publicClient = true,
            directAccessGrantsEnabled = true,
            standardFlowEnabled = false
        }).ConfigureAwait(false);
        _oidcClient = (await SetupAsync(HttpMethod.Get, root + "/clients?clientId=fgap-app")
            .ConfigureAwait(false)).Single()["id"].Value<string>();
        _ = Success(await _client.Organizations.CreateAsync(_realm, _token,
            new KcOrganization { Name = "Org A", Alias = "org-a", Enabled = true }).ConfigureAwait(false));
        _organization = Success(await _client.Organizations.ListAsync(_realm, _token).ConfigureAwait(false))
            .Single().Id;
    }

    /// <summary>Removes only the realm created by this test.</summary>
    [TestCleanup]
    public async Task CleanupAsync()
    {
        if ( _realm != null ) _ = await SetupAsync(HttpMethod.Delete, "admin/realms/" + _realm).ConfigureAwait(false);
    }

    /// <summary>Disposes fixture HTTP resources.</summary>
    public void Dispose() => _setup.Dispose();

    /// <summary>Round-trips the supported non-script built-in policy providers through their typed endpoints.</summary>
    /// <param name="type">The built-in provider.</param>
    [TestMethod]
    [DataRow("user")]
    [DataRow("group")]
    [DataRow("role")]
    [DataRow("aggregate")]
    [DataRow("client")]
    [DataRow("time")]
    [DataRow("regex")]
    public async Task ShouldRoundTripPolicyAsync(string type)
    {
        var dependency = Success(await _client.AdminPermissions.CreatePolicyAsync(_realm, _token,
            new KcAdminPolicy { Name = "base-user", Type = "user", Users = [_actor] }).ConfigureAwait(false));
        var body = new JObject { ["name"] = "policy & " + type, ["type"] = type, ["logic"] = "POSITIVE" };
        switch ( type )
        {
            case "user": body["users"] = new JArray(_actor); break;
            case "group": body["groups"] = new JArray(new JObject { ["id"] = _group }); break;
            case "role": body["roles"] = new JArray(new JObject { ["id"] = _role, ["required"] = false }); break;
            case "aggregate": body["policies"] = new JArray(dependency.Id); break;
            case "client": body["clients"] = new JArray(_oidcClient); break;
            case "time": body["notBefore"] = "2020-01-01 00:00:00"; break;
            case "regex": body["targetClaim"] = "sub"; body["pattern"] = ".*"; break;
        }
        var policy = body.ToObject<KcAdminPolicy>();
        policy = Success(await _client.AdminPermissions.CreatePolicyAsync(_realm, _token, policy)
            .ConfigureAwait(false));
        var read = Success(await _client.AdminPermissions.GetPolicyAsync(_realm, _token, type, policy.Id)
            .ConfigureAwait(false));
        Assert.AreEqual(body.Value<string>("name"), read.Name);
        Assert.IsTrue(type switch
        {
            "user" => read.Users?.Contains(_actor) == true,
            "group" => read.Groups?.Any(g => g.Id == _group) == true,
            "role" => read.Roles?.Any(r => r.Id == _role) == true,
            "aggregate" => read.Policies?.Contains(dependency.Id) == true,
            "client" => read.Clients?.Contains(_oidcClient) == true,
            "time" => read.NotBefore?.StartsWith("2020", StringComparison.Ordinal) == true,
            _ => read.TargetClaim == "sub" && read.Pattern == ".*"
        }, "Provider fields must survive reading before an update.");
        read.Description = "updated";
        _ = Success(await _client.AdminPermissions.UpdatePolicyAsync(_realm, _token, read.Id, read)
            .ConfigureAwait(false));
        var list = Success(await _client.AdminPermissions.ListPoliciesAsync(_realm, _token, name: read.Name)
            .ConfigureAwait(false));
        Assert.AreEqual(1, list.Count(p => p.Id == read.Id));
        _ = Success(await _client.AdminPermissions.DeletePolicyAsync(_realm, _token, type, read.Id)
            .ConfigureAwait(false));
        Assert.AreEqual(HttpStatusCode.NotFound, (await _client.AdminPermissions
            .GetPolicyAsync(_realm, _token, type, read.Id).ConfigureAwait(false)).MonitoringMetrics.StatusCode);
    }

    /// <summary>Round-trips permissions for all five supported resource types, without Preview scopes.</summary>
    /// <param name="type">The resource type.</param>
    [TestMethod]
    [DataRow("Users")]
    [DataRow("Groups")]
    [DataRow("Clients")]
    [DataRow("Roles")]
    [DataRow("Organizations")]
    public async Task ShouldRoundTripPermissionAsync(string type)
    {
        var policy = Success(await _client.AdminPermissions.CreatePolicyAsync(_realm, _token,
            new KcAdminPolicy { Name = "actor", Type = "user", Users = [_actor] }).ConfigureAwait(false));
        var resource = type switch
        {
            "Users" => _user,
            "Groups" => _group,
            "Clients" => _oidcClient,
            "Roles" => _role,
            _ => _organization
        };
        var desired = new KcAdminPermission
        {
            Name = "permission & " + type,
            ResourceType = type,
            Resources = [resource],
            Scopes = type switch
            {
                "Users" => ["view", "manage", "map-roles", "manage-group-membership", "impersonate", "reset-password"],
                "Groups" => ["view", "manage", "view-members", "manage-members", "manage-membership",
                    "manage-membership-of-members", "impersonate-members"],
                "Clients" => ["view", "manage", "map-roles", "map-roles-composite", "map-roles-client-scope"],
                "Roles" => ["map-role", "map-role-composite", "map-role-client-scope"],
                _ => ["view", "manage"]
            },
            Policies = [policy.Id]
        };
        var created = type == "Organizations"
            ? Success(await _client.AdminPermissions.CreateOrganizationPermissionAsync(_realm, _token,
                resource, desired).ConfigureAwait(false))
            : Success(await _client.AdminPermissions.CreatePermissionAsync(_realm, _token, desired)
                .ConfigureAwait(false));
        var read = Success(await _client.AdminPermissions.GetPermissionAsync(_realm, _token, created.Id)
            .ConfigureAwait(false));
        Assert.AreEqual(type, read.ResourceType);
        CollectionAssert.AreEquivalent(desired.Scopes.ToArray(), read.Scopes.ToArray());
        CollectionAssert.AreEqual(new[] { resource }, read.Resources.ToArray());
        read.Description = "updated";
        _ = Success(await _client.AdminPermissions.UpdatePermissionAsync(_realm, _token, created.Id, read)
            .ConfigureAwait(false));
        var list = Success(await _client.AdminPermissions.ListPermissionsAsync(_realm, _token, name: desired.Name,
            resourceType: type, resourceId: resource, scope: desired.Scopes[0])
            .ConfigureAwait(false));
        Assert.AreEqual(1, list.Count(p => p.Id == created.Id));
        var allowed = Success(await _client.AdminPermissions.EvaluatePermissionAsync(_realm, _token, _actor,
            type, resource, desired.Scopes).ConfigureAwait(false));
        Assert.AreEqual("PERMIT", allowed.Value<string>("status"));
        var denied = Success(await _client.AdminPermissions.EvaluatePermissionAsync(_realm, _token, _user,
            type, resource, desired.Scopes).ConfigureAwait(false));
        Assert.AreEqual("DENY", denied.Value<string>("status"));
        _ = Success(await _client.AdminPermissions.DeletePermissionAsync(_realm, _token, created.Id)
            .ConfigureAwait(false));
    }

    /// <summary>Repeated declarative application preserves IDs and unrelated objects and resolves forward policy
    /// names.</summary>
    [TestMethod]
    public async Task ShouldApplyDeclarationIdempotentlyAsync()
    {
        var configuration = KcAdminPermissionsConfiguration.FromJson("""
            {"version":"V2","policies":[
              {"name":"aggregate","type":"aggregate","policies":["operator"]},
              {"name":"operator","type":"user","users":[]}],
             "permissions":[{"name":"org-view","resourceType":"Organizations","scopes":["view"],
               "policies":["aggregate"]}]}
            """, "FGAP_TEST_UNUSED_");
        configuration.Policies.Single(p => p.Name == "operator").Users = [_actor];
        var unrelated = Success(await _client.AdminPermissions.CreatePolicyAsync(_realm, _token,
            new KcAdminPolicy { Name = "unrelated", Type = "user", Users = [_user] }).ConfigureAwait(false));
        var first = Success(await _client.AdminPermissions.ApplyConfigurationAsync(_realm, _token, configuration)
            .ConfigureAwait(false));
        Assert.AreEqual(2, first.PoliciesApplied);
        var id = Success(await _client.AdminPermissions.ListPermissionsAsync(_realm, _token, name: "org-view")
            .ConfigureAwait(false)).Single().Id;
        configuration.Permissions[0].Description = "changed";
        _ = Success(await _client.AdminPermissions.ApplyConfigurationAsync(_realm, _token, configuration)
            .ConfigureAwait(false));
        var updated = Success(await _client.AdminPermissions.GetPermissionAsync(_realm, _token, id)
            .ConfigureAwait(false));
        Assert.AreEqual("changed", updated.Description);
        Assert.AreEqual(0, updated.Resources.Count, "A type-level permission must remain type-level after reading.");
        Assert.IsNotNull(Success(await _client.AdminPermissions.GetPolicyAsync(_realm, _token, "user", unrelated.Id)
            .ConfigureAwait(false)));
        _ = Success(await _client.AdminPermissions.SetRealmEnabledAsync(_realm, _token, false).ConfigureAwait(false));
        Assert.IsTrue((await _client.AdminPermissions.ListPoliciesAsync(_realm, _token).ConfigureAwait(false)).IsError);
    }

    /// <summary>Checks organization visibility, read-only denial, scoped management and type-level create
    /// permissions.</summary>
    [TestMethod]
    public async Task ShouldEnforceOrganizationBoundariesAsync()
    {
        _ = Success(await _client.Organizations.CreateAsync(_realm, _token,
            new KcOrganization { Name = "Org B", Alias = "org-b", Enabled = true }).ConfigureAwait(false));
        var hidden = Success(await _client.Organizations.ListAsync(_realm, _token).ConfigureAwait(false))
            .Single(o => o.Alias == "org-b").Id;
        await GrantAdminRoleAsync("query-organizations").ConfigureAwait(false);
        var policy = Success(await _client.AdminPermissions.CreatePolicyAsync(_realm, _token,
            new KcAdminPolicy { Name = "operator", Type = "user", Users = [_actor] }).ConfigureAwait(false));
        var desired = new KcAdminPermission { Name = "org-a", Scopes = ["view"], Policies = [policy.Id] };
        var permission = Success(await _client.AdminPermissions.CreateOrganizationPermissionAsync(
            _realm, _token, _organization, desired).ConfigureAwait(false));
        var actor = Success(await _client.Auth.GetResourceOwnerPasswordTokenAsync(_realm,
            new KcClientCredentials { ClientId = "fgap-app" },
            new KcUserLogin { Username = "operator", Password = Password }).ConfigureAwait(false)).AccessToken;
        Assert.AreEqual(1, Success(await _client.Organizations.ListAsync(_realm, actor).ConfigureAwait(false)).Count());
        Assert.IsTrue((await _client.Organizations.GetAsync(_realm, actor, hidden).ConfigureAwait(false)).IsError);
        var update = new KcOrganization { Name = "Org A", Alias = "org-a", Description = "updated" };
        Assert.AreEqual(HttpStatusCode.Forbidden, (await _client.Organizations.UpdateAsync(
            _realm, actor, _organization, update).ConfigureAwait(false)).MonitoringMetrics.StatusCode);
        desired.ResourceType = "Organizations";
        desired.Resources = [_organization];
        desired.Scopes = ["view", "manage"];
        _ = Success(await _client.AdminPermissions.UpdatePermissionAsync(_realm, _token, permission.Id, desired)
            .ConfigureAwait(false));
        _ = Success(await _client.Organizations.UpdateAsync(_realm, actor, _organization, update)
            .ConfigureAwait(false));
        Assert.AreEqual(HttpStatusCode.Forbidden, (await _client.Organizations.CreateAsync(_realm, actor,
            new KcOrganization { Name = "Org C", Alias = "org-c" })
                .ConfigureAwait(false)).MonitoringMetrics.StatusCode);
        Assert.IsTrue((await _client.AdminPermissions.ListPoliciesAsync(_realm, actor)
            .ConfigureAwait(false)).IsError);
        _ = Success(await _client.AdminPermissions.DeletePermissionAsync(_realm, _token, permission.Id)
            .ConfigureAwait(false));
        Assert.IsTrue((await _client.Organizations.GetAsync(_realm, actor, _organization)
            .ConfigureAwait(false)).IsError);
        _ = Success(await _client.AdminPermissions.CreatePermissionAsync(_realm, _token,
            new KcAdminPermission
            {
                Name = "all-organizations",
                ResourceType = "Organizations",
                Scopes = ["view", "manage"],
                Policies = [policy.Id]
            }).ConfigureAwait(false));
        _ = Success(await _client.Organizations.CreateAsync(_realm, actor,
            new KcOrganization { Name = "Org C", Alias = "org-c" }).ConfigureAwait(false));
        var created = Success(await _client.Organizations.ListAsync(_realm, actor).ConfigureAwait(false))
            .Single(o => o.Alias == "org-c");
        _ = Success(await _client.Organizations.DeleteAsync(_realm, actor, created.Id).ConfigureAwait(false));
        var deny = Success(await _client.AdminPermissions.CreatePolicyAsync(_realm, _token,
            new KcAdminPolicy { Name = "deny-operator", Type = "user", Users = [_actor], Logic = "NEGATIVE" })
            .ConfigureAwait(false));
        _ = Success(await _client.AdminPermissions.CreateOrganizationPermissionAsync(_realm, _token, hidden,
            new KcAdminPermission { Name = "deny-org-b", Scopes = ["view", "manage"], Policies = [deny.Id] })
            .ConfigureAwait(false));
        Assert.IsTrue((await _client.Organizations.GetAsync(_realm, actor, hidden).ConfigureAwait(false)).IsError);
        Assert.AreEqual(HttpStatusCode.Forbidden, (await _client.Organizations.UpdateAsync(_realm, actor, hidden,
            new KcOrganization { Name = "Org B", Alias = "org-b" })
                .ConfigureAwait(false)).MonitoringMetrics.StatusCode);
        Assert.AreEqual(HttpStatusCode.Forbidden, (await _client.Organizations.DeleteAsync(_realm, actor, hidden)
            .ConfigureAwait(false)).MonitoringMetrics.StatusCode);
        Assert.IsFalse((await _client.Organizations.GetAsync(_realm, actor, _organization)
            .ConfigureAwait(false)).IsError, "The specific deny must not revoke access to unrelated organizations.");
    }

    private static T Success<T>(KcResponse<T> response)
    {
        Assert.IsFalse(response.IsError, response.ErrorMessage);
        return response.Response;
    }

    private async Task<string> CreateUserAsync(string name)
    {
        var root = "admin/realms/" + _realm;
        _ = await SetupAsync(HttpMethod.Post, root + "/users", new
        {
            username = name,
            enabled = true,
            email = name + "@example.com",
            firstName = "Test",
            lastName = "Operator",
            credentials = new[] { new { type = "password", value = Password, temporary = false } }
        }).ConfigureAwait(false);
        return (await SetupAsync(HttpMethod.Get, root + "/users?exact=true&username=" + name)
            .ConfigureAwait(false)).Single()["id"].Value<string>();
    }

    private async Task GrantAdminRoleAsync(string role)
    {
        var root = "admin/realms/" + _realm;
        var management = (await SetupAsync(HttpMethod.Get, root + "/clients?clientId=realm-management")
            .ConfigureAwait(false)).Single()["id"].Value<string>();
        var representation = await SetupAsync(HttpMethod.Get, root + $"/clients/{management}/roles/{role}")
            .ConfigureAwait(false);
        _ = await SetupAsync(HttpMethod.Post, root + $"/users/{_actor}/role-mappings/clients/{management}",
            new[] { representation }).ConfigureAwait(false);
    }

    private async Task<JToken> SetupAsync(HttpMethod method, string path, object body = null)
    {
        using var request = new HttpRequestMessage(method, TestEnvironment.BaseUrl.TrimEnd('/') + "/" + path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        if ( body != null ) request.Content = new StringContent(JsonConvert.SerializeObject(body),
            Encoding.UTF8, "application/json");
        using var response = await _setup.SendAsync(request).ConfigureAwait(false);
        Assert.IsTrue(response.IsSuccessStatusCode, $"Fixture {method} {path} failed: {response.StatusCode}");
        var text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(text) ? null : JToken.Parse(text);
    }
}
