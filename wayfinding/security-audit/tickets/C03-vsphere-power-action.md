# Ticket: vSphere power_action has no role check + unsanitized vm_id

wayfinder:task
Priority: P0
Phase: Critical

## Finding

`src/api/vsphere.rs:64-83` — `power_action` is routed at `main.rs:1627-1630` and takes `vm_id` from the URL path. Any authenticated user (any role, including `viewer`) can power off/reset arbitrary VMs. The `vm_id` is interpolated unsanitized into the vCenter REST URL via `vsphere.rs:412-414`, and could contain `/` or `..` to reach other vCenter API paths using the app's privileged session.

## Fix

1. **Role check**: Add `has_role("operator")` like sibling `connect_vm` (`api/vsphere.rs:118`). Reject `viewer` and lower roles.
2. **vm_id validation**: Validate `vm_id` against a strict charset (alphanumeric + hyphens + underscores only, max 128 chars) before building the REST URL. Alternatively, validate against the known VM inventory from `GET /rest/vmware/vm` so only real VM IDs are accepted.
3. **URL construction**: Ensure the `vm_id` is URL-encoded before interpolation into the vCenter REST path.

## Files

- `src/api/vsphere.rs:64-83` — `power_action`
- `src/vsphere.rs:412-414` — URL construction
- `src/main.rs:1627-1630` — route registration

## Deliverable

`power_action` requires `operator` role. `vm_id` is validated against strict charset or VM inventory. URL construction uses percent-encoding. `cargo check` passes.
