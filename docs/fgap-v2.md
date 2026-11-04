# Keycloak 26.8.1 FGAP v2 / 细粒度管理员权限 v2

The `AdminPermissions` module explicitly manages FGAP v2. Existing constructors select V1,
and the existing clients/groups/roles `/management/permissions` methods retain their behavior.
No automatic migration or fallback between permission models is performed.

`AdminPermissions` 是显式的 FGAP v2 管理入口。原有构造方式默认 V1，已有 v1 接口保留；
切换客户端配置不会迁移旧权限，也不会改变 Keycloak 服务器启动时选择的功能版本。

## Configuration / 配置

Use the complete [organization declaration](../examples/fgap-v2.json), replacing group and
organization placeholders with real **entity UUIDs**. Policy references in a declaration may
use declared policy names or existing policy UUIDs. Direct CRUD methods require policy UUIDs.

```csharp
using NETCore.Keycloak.Client.HttpClients.Implementation;
using NETCore.Keycloak.Client.Models.AdminPermissions;

var configuration = KcAdminPermissionsConfiguration.FromJson(
    await File.ReadAllTextAsync("fgap-v2.json"));
var client = new KeycloakClient(baseUrl, logger, httpClientFactory, configuration);

// Observable route selection; constructing/loading configuration makes no HTTP requests.
Console.WriteLine(client.AdminPermissions.SelectedVersion); // V2
var result = await client.AdminPermissions.ApplyConfigurationAsync(
    realm, adminAccessToken, configuration, cancellationToken);
if (result.IsError) throw new InvalidOperationException(result.ErrorMessage);
```

Minimal JSON explicitly selects the model; applying it enables admin permissions in that realm:

```json
{"version":"V2","enabled":true,"policies":[],"permissions":[]}
```

The optional environment variables `KEYCLOAK_FGAP_VERSION=V2` and
`KEYCLOAK_FGAP_ENABLED=true` override JSON when `FromJson` is used. `FromEnvironment()` loads
just these settings. Supported version values are V1/V2; enabled values are true/false.
Invalid values, unknown configuration properties and numeric version values are rejected.
The environment prefix can be customized. Existing constructors do not implicitly read variables.

```powershell
$env:KEYCLOAK_FGAP_VERSION = "V2"
$env:KEYCLOAK_FGAP_ENABLED = "true"
```

JSON 和环境变量均须通过上述加载方法显式传入客户端。环境变量优先于 JSON；
`SelectedVersion` 和可选日志 `Keycloak FGAP route: V2` 可确认所选路线。
构造客户端不写入服务器，只有显式调用应用配置或 CRUD 才会修改权限。

The server must separately run the supported `admin-fine-grained-authz:v2` feature.
The test fixture selects it with `--fgap v2` or `KC_FGAP_VERSION=v2`; these fixture options
are distinct from the SDK's `KEYCLOAK_FGAP_*` settings. V1 and V2 server feature versions
cannot be enabled together. Preserve V1 on the appropriate server profile when using legacy APIs.

Management calls require credentials allowed to read realm settings and discover the
`admin-permissions` client through the clients query API. Policy/permission reads and evaluation
require `view-realm` or `manage-realm`; writes and applying declarations require `manage-realm`.
Client discovery additionally requires permission to query clients. These management credentials
are separate from the ordinary organization operator whose view/manage grants are being configured.

## Supported operations / 支持范围

| Area | Operations |
| --- | --- |
| Realm | Read/enable/disable `adminPermissionsEnabled`, preserving other realm settings |
| Policies | Create/read/update/delete, paginated name search; user, group, role, aggregate, client, time, regex |
| Permissions | Create/read/update/delete, paginated name search; scope-based permissions with UNANIMOUS strategy |
| Search/evaluation | Filter by resource type, entity UUID and scope; evaluate a subject's explicit scopes and inspect server decisions |
| Organization | Permission restricted to one organization UUID; view/manage, including specific deny over global allow |
| Declaration | Merge by stable name, resolve aggregate dependencies and policy names, preserve server IDs and omitted objects |

| Resource type | Supported scopes (23 total) |
| --- | --- |
| Users | view, manage, map-roles, manage-group-membership, impersonate, reset-password |
| Groups | view, manage, view-members, manage-members, manage-membership, manage-membership-of-members, impersonate-members |
| Clients | view, manage, map-roles, map-roles-composite, map-roles-client-scope |
| Roles | map-role, map-role-composite, map-role-client-scope |
| Organizations | view, manage |

Permission writes use scope **names** and target entity UUIDs. An empty/omitted `resources`
array selects **all resources of the type**, so a scoped organization declaration must include
the organization UUID. Creating organizations requires type-level manage; manage on a single
organization permits its updates/deletion. Manage does not imply view.

`GetPolicyAsync` returns editable provider fields. `GetPermissionAsync` loads the dedicated
scope/resource/policy associations and returns scope names, entity UUIDs and policy UUIDs,
so read-modify-write preserves the grant. List methods return generic server summaries;
read each item through its get method before editing. Creating an organization permission
always restricts it to the supplied UUID, without mutating the caller's object.

```csharp
var matching = await client.AdminPermissions.ListPermissionsAsync(realm, adminAccessToken,
    resourceType: "Organizations", resourceId: organizationId, scope: "view");
var decision = await client.AdminPermissions.EvaluatePermissionAsync(realm, adminAccessToken,
    operatorUserId, "Organizations", organizationId, ["view", "manage"]);
// Check IsError first, then decision.Response["status"] and detailed ["results"].
```

Filtering by an entity or scope requires its resource type. The evaluator accepts an entity UUID
and explicit scope names; it uses the subject's stored identity and grants no additional roles.
It is a diagnostic operation, not a replacement for authorization checks on the protected API.

`ApplyConfigurationAsync` validates types/scopes/names/dependency cycles before writes, then
updates the realm switch, reads all existing pages and validates policy references. Unknown
references can therefore fail after the realm switch has been applied. Policies are applied in
dependency order, followed by permissions. Application is **sequential, not transactional**:
the first error stops subsequent operations; completed changes remain. Omitted objects are
retained; no automatic pruning, rollback or V1 migration occurs. To disable, supply an empty
declaration with `enabled:false`, or call `SetRealmEnabledAsync` explicitly.

声明式应用按名称更新或创建，可重复执行，保留未声明对象。它不是事务：失败后已完成的修改
不会回滚，应检查结果并修正后重试。全局授权应显式审查 `resources`；日常组织委派建议使用
带具体组织 UUID 的配置。普通委派管理员不应持有绕过细粒度权限的广泛管理角色。

Preview delegation scopes (`delegate`, `delegate-members`), script/custom policy providers,
organization-group Preview APIs and other Preview features are rejected or not exposed.
This module does not add organization invitations, members or identity-provider-link APIs.
Authorization enforcement remains on Keycloak.

## Verification / 验证

The CI matrix runs the legacy full suite on V1 and the `FGAPV2` management tests plus applicable
`Keycloak2681` security regressions on V2. Each new management test creates and removes its own
realm. Tests use real Keycloak 26.8.1 and PostgreSQL, and cover all seven policy providers,
all five resource types/23 scopes, editable read/write, repeated declarations, organization
visibility, view/manage independence, global create, scoped deny and revocation.
Independent unit tests cover JSON/environment selection, Preview rejection, legacy routing,
dependency/reference errors, pagination and failure stopping. See the
[test guide](../NETCore.Keycloak.Client.Tests/README.md#keycloak-2681-compatibility--兼容性验证).

Official sources / 官方依据:

- [26.8.1 FGAP v2 administration guide](https://www.keycloak.org/docs/26.8.1/server_admin/#_fine_grained_permissions)
- [Resource types and scopes](https://www.keycloak.org/docs/26.8.1/server_admin/#_understanding_realm_resource_types)
- [Managing permissions with the REST API](https://www.keycloak.org/docs/26.8.1/server_admin/#_managing-permissions-rest-api)
- [26.8.1 release notes and security fixes](https://www.keycloak.org/2026/10/keycloak-2681-released)
