// Permission matching for the rbac module, mirroring the server.
//
// GET /me/permissions returns the grants a user holds as patterns such as
// "invoice:*". `can` answers whether those grants allow one permission, so a
// UI can hide what the user cannot do. It is a convenience only: rules the
// application attaches to single routes are not part of the grants, and the
// server stays the authority.

const RESERVED_NAMESPACE = 'goauth';

function isReserved(resource: string): boolean {
  return resource === RESERVED_NAMESPACE || resource.startsWith(RESERVED_NAMESPACE + '.');
}

function split(value: string): [string, string] | null {
  const parts = value.split(':');
  if (parts.length !== 2 || parts[0] === '' || parts[1] === '') {
    return null;
  }
  return [parts[0], parts[1]];
}

/**
 * Reports whether `grants` allow `permission`.
 *
 * A grant is a permission ("invoice:read") or a pattern: "invoice:*" (every
 * action on a resource), "*:read" (one action on every resource),
 * "billing.*:read" (every resource under a prefix) or "*" (everything). A
 * bare "*" never reaches GoAuth's own permissions under "goauth.".
 *
 * @example
 * const { data } = await rbacMePermissions();
 * if (can(data?.data?.permissions ?? [], 'invoice:approve')) { ... }
 */
export function can(grants: readonly string[], permission: string): boolean {
  const wanted = split(permission);
  if (wanted === null) {
    return false;
  }
  const [resource, action] = wanted;
  return grants.some((grant) => {
    const parsed = grant === '*' ? (['*', '*'] as [string, string]) : split(grant);
    if (parsed === null) {
      return false;
    }
    const [grantResource, grantAction] = parsed;
    if (grantAction !== '*' && grantAction !== action) {
      return false;
    }
    if (grantResource === '*') {
      return !isReserved(resource);
    }
    if (grantResource.endsWith('.*')) {
      return resource.startsWith(grantResource.slice(0, -1));
    }
    return grantResource === resource;
  });
}
