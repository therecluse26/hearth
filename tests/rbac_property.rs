//! Property-based tests for the RBAC engine.
//!
//! Covers `docs/specs/TEST_SCENARIOS.md` §"Authorization (RBAC) Engine" — Property:
//! - Random role DAGs (no cycles) produce correct reachability
//! - Random group graphs (no cycles) produce correct transitive membership
//! - Random assign/unassign sequences maintain invariants

mod common;

use hearth::core::{RealmId, UserId};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupMember, Permission, Scope,
    Subject,
};
use proptest::prelude::*;
use std::collections::{BTreeSet, HashMap};

fn p(s: &str) -> Permission {
    Permission::new(s).expect("valid perm in test")
}

fn make_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

// ---------------------------------------------------------------------------
// Strategy: random DAG as topological-order node list.
// Node i may reference any subset of nodes in 0..i as parents — no cycles.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RoleNode {
    perm_count: usize,
    parent_indices: Vec<usize>,
}

fn arb_role_dag(size: usize) -> BoxedStrategy<Vec<RoleNode>> {
    let mut strats: Vec<BoxedStrategy<RoleNode>> = Vec::with_capacity(size);
    for i in 0..size {
        let max_par = i.min(3);
        let s = (
            1usize..=3,
            proptest::collection::vec(0usize..i.max(1), 0..=max_par),
        )
            .prop_map(move |(pc, mut pars)| {
                pars.sort_unstable();
                pars.dedup();
                pars.retain(|&p| p < i);
                RoleNode {
                    perm_count: pc,
                    parent_indices: pars,
                }
            })
            .boxed();
        strats.push(s);
    }
    strats.into_iter().fold(Just(vec![]).boxed(), |acc, s| {
        (acc, s)
            .prop_map(|(mut v, n)| {
                v.push(n);
                v
            })
            .boxed()
    })
}

#[derive(Debug, Clone)]
struct GroupNode {
    parent_indices: Vec<usize>,
}

fn arb_group_dag(size: usize) -> BoxedStrategy<Vec<GroupNode>> {
    let mut strats: Vec<BoxedStrategy<GroupNode>> = Vec::with_capacity(size);
    for i in 0..size {
        let max_par = i.min(2);
        let s = proptest::collection::vec(0usize..i.max(1), 0..=max_par)
            .prop_map(move |mut pars| {
                pars.sort_unstable();
                pars.dedup();
                pars.retain(|&p| p < i);
                GroupNode {
                    parent_indices: pars,
                }
            })
            .boxed();
        strats.push(s);
    }
    strats.into_iter().fold(Just(vec![]).boxed(), |acc, s| {
        (acc, s)
            .prop_map(|(mut v, n)| {
                v.push(n);
                v
            })
            .boxed()
    })
}

// ---------------------------------------------------------------------------
// Property 1: Random role DAG — resolved permissions == union of all reachable
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..Default::default() })]

    #[test]
    fn random_role_dag_produces_correct_union(dag in arb_role_dag(6)) {
        let rt = make_rt();
        let h = rt.block_on(common::TestHarness::embedded()).expect("harness");
        let realm = RealmId::generate();
        let user = UserId::generate();

        let mut role_ids: Vec<hearth::rbac::RoleId> = Vec::new();
        let mut role_perms: HashMap<usize, BTreeSet<String>> = HashMap::new();

        for (i, node) in dag.iter().enumerate() {
            let direct: Vec<Permission> = (0..node.perm_count)
                .map(|j| p(&format!("role{i}.p{j}")))
                .collect();
            let names: BTreeSet<String> = direct.iter().map(|p| p.as_str().to_string()).collect();
            role_perms.insert(i, names);

            let parents: Vec<hearth::rbac::RoleId> =
                node.parent_indices.iter().map(|&pi| role_ids[pi].clone()).collect();

            let role = rt.block_on(async {
                h.rbac()
                    .create_role(
                        &realm,
                        &CreateRoleRequest {
                            name: format!("r{i}"),
                            description: None,
                            permissions: direct,
                            parent_roles: parents,
                            ..Default::default()
                        },
                    )
                    .expect("create role")
            });
            role_ids.push(role.id);
        }

        let leaf = dag.len() - 1;
        rt.block_on(async {
            h.rbac()
                .assign_role(
                    &realm,
                    &AssignRoleRequest {
                        subject: Subject::User(user.clone()),
                        role_id: role_ids[leaf].clone(),
                        scope: Scope::Realm,
                        assigned_by: None,
                    },
                )
                .expect("assign leaf");
        });

        // Expected: all permissions reachable from leaf via DAG parent edges.
        let mut reachable: BTreeSet<usize> = BTreeSet::new();
        let mut stack = vec![leaf];
        while let Some(idx) = stack.pop() {
            if reachable.insert(idx) {
                for &pi in &dag[idx].parent_indices {
                    stack.push(pi);
                }
            }
        }
        let expected: BTreeSet<String> = reachable
            .iter()
            .flat_map(|&i| role_perms[&i].iter().cloned())
            .collect();

        let resolved = rt.block_on(async {
            h.rbac().resolve_permissions(&user, &realm, None, None).expect("resolve")
        });
        let got: BTreeSet<String> =
            resolved.permissions.iter().map(|p| p.as_str().to_string()).collect();

        prop_assert_eq!(got, expected);
    }
}

// ---------------------------------------------------------------------------
// Property 2: Random group graph — transitive membership resolves role
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..Default::default() })]

    #[test]
    fn random_group_graph_transitive_membership_resolves_role(dag in arb_group_dag(5)) {
        let rt = make_rt();
        let h = rt.block_on(common::TestHarness::embedded()).expect("harness");
        let realm = RealmId::generate();
        let user = UserId::generate();

        let mut gids: Vec<hearth::rbac::GroupId> = Vec::new();

        // Create groups in topological order and wire parent edges.
        for (i, node) in dag.iter().enumerate() {
            let gid = rt.block_on(async {
                h.rbac()
                    .create_group(
                        &realm,
                        &CreateGroupRequest {
                            name: format!("G{i}"),
                            slug: format!("grp{i}"),
                            description: None,
                        },
                    )
                    .expect("create group")
                    .id
            });
            // "This group is a member of each parent group" means adding gid
            // as a member of each parent group.
            for &pi in &node.parent_indices {
                rt.block_on(async {
                    h.rbac()
                        .add_group_member(&realm, &gids[pi], &GroupMember::Group(gid.clone()))
                        .expect("add group member");
                });
            }
            gids.push(gid);
        }

        // User joins group 0 (the leaf with no parents it introduces cycles).
        rt.block_on(async {
            h.rbac()
                .add_group_member(&realm, &gids[0], &GroupMember::User(user.clone()))
                .expect("user in g0");
        });

        // Compute groups reachable from group 0 upward through parent edges.
        let mut reachable: BTreeSet<usize> = BTreeSet::new();
        let mut stack = vec![0usize];
        while let Some(idx) = stack.pop() {
            if reachable.insert(idx) {
                for &pi in &dag[idx].parent_indices {
                    stack.push(pi);
                }
            }
        }

        // Create a single role and assign it to every reachable group.
        let perm = p("grp.access");
        let role = rt.block_on(async {
            h.rbac()
                .create_role(
                    &realm,
                    &CreateRoleRequest {
                        name: "grp-role".into(),
                        description: None,
                        permissions: vec![perm.clone()],
                        parent_roles: vec![],
                        ..Default::default()
                    },
                )
                .expect("create grp-role")
        });
        for &gi in &reachable {
            rt.block_on(async {
                h.rbac()
                    .assign_role(
                        &realm,
                        &AssignRoleRequest {
                            subject: Subject::Group(gids[gi].clone()),
                            role_id: role.id.clone(),
                            scope: Scope::Realm,
                            assigned_by: None,
                        },
                    )
                    .expect("assign role to group");
            });
        }

        let resolved = rt.block_on(async {
            h.rbac().resolve_permissions(&user, &realm, None, None).expect("resolve")
        });
        let got: BTreeSet<String> =
            resolved.permissions.iter().map(|p| p.as_str().to_string()).collect();

        if reachable.is_empty() {
            prop_assert!(got.is_empty());
        } else {
            prop_assert!(
                got.contains("grp.access"),
                "grp.access must be present via group membership; got {got:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 3: Random assign/unassign sequences maintain invariants
//   - Resolved permissions match the set of currently-assigned roles
//   - No duplicate permissions (BTreeSet-deduplicated output)
//   - Realm isolation: realm B unaffected by realm A operations
//
// Each case: assign a random subset of 5 roles, then unassign a random
// sub-subset. Final resolved permissions must equal the remaining subset's
// permissions exactly.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..Default::default() })]

    #[test]
    fn random_assign_unassign_sequence_maintains_invariants(
        // assign_mask: bitmask of which of 5 roles to assign (bits 0-4)
        assign_mask in 0u8..32,
        // unassign_mask: bitmask of which assigned roles to then unassign
        unassign_mask in 0u8..32,
    ) {
        let rt = make_rt();
        let h = rt.block_on(common::TestHarness::embedded()).expect("harness");
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        let user = UserId::generate();

        // Create 5 roles, each with one distinct permission.
        let role_data: Vec<(hearth::rbac::RoleId, String)> = (0..5usize)
            .map(|i| {
                let pname = format!("seq{i}.act");
                let role = rt.block_on(async {
                    h.rbac()
                        .create_role(
                            &realm_a,
                            &CreateRoleRequest {
                                name: format!("seq-{i}"),
                                description: None,
                                permissions: vec![p(&pname)],
                                parent_roles: vec![],
                                ..Default::default()
                            },
                        )
                        .expect("create seq role")
                });
                (role.id, pname)
            })
            .collect();

        // Phase 1: assign roles selected by assign_mask.
        let mut assigned_ids: BTreeSet<usize> = BTreeSet::new();
        for i in 0..5usize {
            if assign_mask & (1u8 << i) != 0 {
                let (rid, _) = &role_data[i];
                rt.block_on(async {
                    h.rbac()
                        .assign_role(
                            &realm_a,
                            &AssignRoleRequest {
                                subject: Subject::User(user.clone()),
                                role_id: rid.clone(),
                                scope: Scope::Realm,
                                assigned_by: None,
                            },
                        )
                        .expect("assign role");
                });
                assigned_ids.insert(i);
            }
        }

        // Phase 2: unassign roles selected by the intersection of
        // unassign_mask and assign_mask (can only unassign what was assigned).
        let to_unassign: BTreeSet<usize> = (0..5usize)
            .filter(|&i| unassign_mask & (1u8 << i) != 0 && assigned_ids.contains(&i))
            .collect();

        for i in &to_unassign {
            let (rid, _) = &role_data[*i];
            rt.block_on(async {
                let assignments = h.rbac()
                    .list_user_assignments(&realm_a, &user)
                    .expect("list assignments");
                if let Some(a) = assignments.iter().find(|a| &a.role_id == rid) {
                    h.rbac().unassign_role(&realm_a, &a.id).expect("unassign");
                }
            });
        }

        // Expected: permissions from roles that were assigned but not unassigned.
        let active: BTreeSet<usize> = assigned_ids.difference(&to_unassign).copied().collect();
        let expected: BTreeSet<String> =
            active.iter().map(|&i| role_data[i].1.clone()).collect();

        // Invariant 1: resolved set matches active assignments exactly.
        let resolved = rt.block_on(async {
            h.rbac().resolve_permissions(&user, &realm_a, None, None).expect("resolve A")
        });
        let got: BTreeSet<String> =
            resolved.permissions.iter().map(|p| p.as_str().to_string()).collect();
        prop_assert_eq!(&got, &expected, "resolved permissions must match active assignment set");

        // Invariant 2: no duplicate permissions in the resolved Vec.
        let perm_vec: Vec<String> =
            resolved.permissions.iter().map(|p| p.as_str().to_string()).collect();
        let perm_set: BTreeSet<String> = perm_vec.iter().cloned().collect();
        prop_assert_eq!(perm_vec.len(), perm_set.len(), "no duplicate permissions");

        // Invariant 3: realm B sees nothing regardless of realm A operations.
        let in_b = rt.block_on(async {
            h.rbac().resolve_permissions(&user, &realm_b, None, None).expect("resolve B")
        });
        prop_assert!(
            in_b.permissions.is_empty(),
            "realm B must be isolated from realm A; got {:?}",
            in_b.permissions
        );
    }
}
