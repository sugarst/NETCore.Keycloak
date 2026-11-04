using System.Net;
using NETCore.Keycloak.Client.HttpClients.Implementation;
using NETCore.Keycloak.Client.Models.AdminPermissions;
using NETCore.Keycloak.Client.Tests.Infrastructure;
using Newtonsoft.Json;

namespace NETCore.Keycloak.Client.Tests.Modules.KcCompatibilityTests;

/// <summary>Exercises declarative failure and pagination boundaries without a server.</summary>
[TestClass]
[TestCategory("CoverageUnit")]
public sealed class KcFgapApplyUnitTests
{
    private static readonly string[] ExpectedFailureWrites =
        ["PUT /admin/realms/test", "POST /admin/realms/test/clients/internal/authz/resource-server/policy/user"];

    /// <summary>A rejected policy stops application without creating later objects or deleting existing ones.</summary>
    [TestMethod]
    public async Task ShouldStopOnPolicyFailureAsync()
    {
        var writes = new List<string>();
        using var transport = new StubHttpTransport(request =>
        {
            if ( request.Method != HttpMethod.Get ) writes.Add(request.Method + " " + request.RequestUri.AbsolutePath);
            return Task.FromResult(request.Method == HttpMethod.Post
                ? StubHttpTransport.Json("{}", HttpStatusCode.Forbidden)
                : Discovery(request) ?? StubHttpTransport.Json("[]"));
        });
        var result = await Client(transport).AdminPermissions.ApplyConfigurationAsync("test", "token",
            new KcAdminPermissionsConfiguration
            {
                Version = KcAdminPermissionsVersion.V2,
                Policies = [User("first"), User("second")],
                Permissions = [new KcAdminPermission
                { Name = "org", ResourceType = "Organizations", Scopes = ["view"], Policies = ["first"] }]
            }).ConfigureAwait(false);
        Assert.IsTrue(result.IsError);
        Assert.AreEqual(HttpStatusCode.Forbidden, result.MonitoringMetrics.StatusCode);
        CollectionAssert.AreEqual(ExpectedFailureWrites, writes.ToArray());
    }

    /// <summary>References to absent policies fail before applying any policy or permission.</summary>
    [TestMethod]
    public async Task ShouldRejectUnknownReferencesAsync()
    {
        var posts = 0;
        using var transport = new StubHttpTransport(request =>
        {
            if ( request.Method == HttpMethod.Post ) posts++;
            return Task.FromResult(Discovery(request) ?? StubHttpTransport.Json("[]"));
        });
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(() => Client(transport).AdminPermissions
            .ApplyConfigurationAsync("test", "token", new KcAdminPermissionsConfiguration
            {
                Version = KcAdminPermissionsVersion.V2,
                Policies = [User("valid")],
                Permissions = [new KcAdminPermission
                { Name = "org", ResourceType = "Organizations", Scopes = ["view"], Policies = ["missing"] }]
            })).ConfigureAwait(false);
        Assert.AreEqual(0, posts);
    }

    /// <summary>Finds policies beyond page one and rejects a server that repeats a page, preventing duplicate
    /// grants.</summary>
    /// <param name="repeated">Whether the second page repeats the first page.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ShouldValidatePaginationAsync(bool repeated)
    {
        var first = Enumerable.Range(0, 100).Select(i => new KcAdminPolicy
        { Id = "p" + i, Name = "policy" + i, Type = "user" }).ToArray();
        var writes = new List<string>();
        using var transport = new StubHttpTransport(request =>
        {
            if ( request.RequestUri.AbsolutePath is "/admin/realms/test" or "/admin/realms/test/clients" )
                return Task.FromResult(Discovery(request));
            var path = request.RequestUri.AbsolutePath;
            if ( request.Method != HttpMethod.Get )
            {
                writes.Add(request.Method + " " + path);
                return Task.FromResult(StubHttpTransport.Json("{}"));
            }
            if ( !path.EndsWith("/policy", StringComparison.Ordinal) )
                return Task.FromResult(StubHttpTransport.Json("[]"));
            var page = request.RequestUri.Query.Contains("first=0&", StringComparison.Ordinal) || repeated
                ? first : [new KcAdminPolicy { Id = "target-id", Name = "target", Type = "user" }];
            return Task.FromResult(StubHttpTransport.Json(JsonConvert.SerializeObject(page)));
        });
        var result = await Client(transport).AdminPermissions.ApplyConfigurationAsync("test", "token",
            new KcAdminPermissionsConfiguration
            { Version = KcAdminPermissionsVersion.V2, Policies = [User("target")] }).ConfigureAwait(false);
        Assert.AreEqual(repeated, result.IsError);
        Assert.AreEqual(repeated ? 0 : 1, writes.Count);
        if ( !repeated ) StringAssert.EndsWith(writes.Single(), "/policy/user/target-id", StringComparison.Ordinal);
    }

    /// <summary>Provider-specific fields can be declared through strict JSON configuration.</summary>
    [TestMethod]
    public void ShouldLoadTimeAndRegexDeclarations()
    {
        var configuration = KcAdminPermissionsConfiguration.FromJson("""
            {"version":"V2","policies":[
              {"name":"hours","type":"time","hour":9,"hourEnd":17,"notBefore":"2020-01-01 00:00:00"},
              {"name":"claim","type":"regex","targetClaim":"sub","pattern":".*"}]}
            """, "FGAP_UNIT_UNUSED_");
        Assert.AreEqual(9, configuration.Policies[0].Hour);
        Assert.AreEqual("sub", configuration.Policies[1].TargetClaim);
    }

    private static HttpResponseMessage Discovery(HttpRequestMessage request)
    {
        if ( request.RequestUri.AbsolutePath == "/admin/realms/test" )
            return StubHttpTransport.Json("{\"adminPermissionsEnabled\":true}");
        return request.RequestUri.AbsolutePath.EndsWith("/clients", StringComparison.Ordinal)
            ? StubHttpTransport.Json("[{\"id\":\"internal\",\"clientId\":\"admin-permissions\"}]") : null;
    }

    private static KcAdminPolicy User(string name) => new() { Name = name, Type = "user", Users = ["actor"] };
    private static KeycloakClient Client(IHttpClientFactory transport) => new("https://keycloak.test", null, transport,
        new KcAdminPermissionsConfiguration { Version = KcAdminPermissionsVersion.V2 });
}
