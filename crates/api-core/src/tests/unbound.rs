/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use carbide_dpf::{DpuServiceObservation, NAMESPACE, ObjectMeta, dpu_service_observation};
use carbide_machine_controller::dpf::MockDpfOperations;
use model::machine::{
    DpfState, DpuReprovisionStates, HostPlatformConfigurationState, InstanceState,
    ManagedHostState, ReprovisionState,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{self};
use serde_json::json;
use tonic::Request;

use crate::cfg::file::DpfUnboundConfig;
use crate::tests::common::api_fixtures::instance::single_interface_network_config;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_managed_host_with_dpf_multi, create_test_env_with_overrides,
    get_config,
};

const DPU_LABEL: &str = "carbide.nvidia.com/dpu-machine-id";
const VPC_LABEL: &str = "carbide.nvidia.com/unbound-vpc-id";

#[crate::sqlx_test]
async fn unbound_machine_ticks_place_each_membership_and_wait_for_retirement(
    pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let services = Arc::new(Mutex::new(BTreeMap::<String, DpuServiceObservation>::new()));
    let devices = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let node_labels = Arc::new(Mutex::new(
        HashMap::<String, BTreeMap<String, String>>::new(),
    ));
    let mut mock = MockDpfOperations::new();
    mock.expect_register_dpu_device()
        .returning(|_, _, _| Ok(()));
    mock.expect_register_dpu_node().returning(|_| Ok(()));
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));
    mock.expect_get_dpu_phase()
        .returning(|_, _| Ok(carbide_dpf::DpuPhase::Ready));
    mock.expect_deployment_type_for_dpu()
        .returning(|_, _| Ok(carbide_dpf::DpuDeploymentType::Bf3));
    mock.expect_verify_node_labels().returning(|_, _| Ok(true));
    mock.expect_get_service_versions_for_dpu()
        .returning(|_| Ok(vec![]));
    let owners = devices.clone();
    mock.expect_get_dpu_device_metadata()
        .returning(move |device| {
            Ok(Some(ObjectMeta {
                name: Some(carbide_dpf::dpu_device_cr_name(device)),
                namespace: Some(NAMESPACE.into()),
                uid: Some(format!("device-uid-{device}")),
                labels: Some(BTreeMap::from([(
                    DPU_LABEL.into(),
                    owners.lock().expect("device owners")[device].clone(),
                )])),
                ..Default::default()
            }))
        });
    let reads = node_labels.clone();
    mock.expect_get_dpu_device_node_labels()
        .returning(move |device| {
            Ok(reads
                .lock()
                .expect("node labels")
                .get(device)
                .cloned()
                .unwrap_or_default())
        });
    let writes = node_labels.clone();
    mock.expect_merge_dpu_device_node_labels()
        .returning(move |device, delta| {
            let mut labels = writes.lock().expect("node labels");
            let labels = labels.entry(device.into()).or_default();
            for (key, value) in delta {
                if let Some(value) = value {
                    labels.insert(key, value);
                } else {
                    labels.remove(&key);
                }
            }
            Ok(())
        });
    let reads = services.clone();
    mock.expect_list_dpu_services()
        .returning(move |_| Ok(reads.lock().expect("services").values().cloned().collect()));
    let reads = services.clone();
    mock.expect_get_dpu_service()
        .returning(move |name| Ok(reads.lock().expect("services").get(name).cloned()));
    let writes = services.clone();
    mock.expect_create_dpu_service()
        .returning(move |definition| {
            assert_eq!(
                definition
                    .service_daemon_set
                    .as_ref()
                    .expect("submitted daemon set")
                    .node_selector_labels
                    .as_ref(),
                Some(&BTreeMap::from([(
                    DPU_LABEL.into(),
                    definition.labels[DPU_LABEL].clone(),
                )]))
            );
            let service = dpu_service_observation(definition);
            assert!(
                writes
                    .lock()
                    .expect("services")
                    .insert(definition.name.clone(), service.clone())
                    .is_none()
            );
            Ok(service)
        });
    // An unchanged reconciliation must not patch; deletion retains the CR until simulated finalizers finish.
    mock.expect_patch_dpu_service().never();
    let writes = services.clone();
    mock.expect_delete_dpu_service()
        .returning(move |name, preconditions| {
            let mut services = writes.lock().expect("services");
            let service = services.get_mut(name).expect("owned service");
            assert_eq!(service.uid.as_ref(), Some(&preconditions.uid));
            assert_eq!(
                service.resource_version.as_ref(),
                Some(&preconditions.resource_version)
            );
            service.is_deleting = true;
            Ok(())
        });
    let mut config = get_config();
    config.dpf.enabled = true;
    config.dpf.deployments.bf3.bfb_url = Some("http://example.com/test.bfb".into());
    let mut service = crate::dpf_services::default_unbound_service();
    service.helm_version = "1.2.3".into();
    service.docker_image_tag = "integration-test".into();
    service.extra_helm_values = json!({"unboundConfig": "server:\n  interface: 127.0.0.1\n"})
        .as_object()
        .cloned();
    config.dpf.unbound = Some(DpfUnboundConfig {
        enabled: true,
        service,
    });
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config).with_dpf_sdk(Arc::new(mock)),
    )
    .await;
    let mh = create_managed_host_with_dpf_multi(&env, 3).await;
    let segments = env.create_vpc_and_tenant_segments(2).await;
    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    txn.commit().await?;
    for dpu in &snapshot.dpu_snapshots {
        devices
            .lock()
            .expect("device owners")
            .insert(dpu.dpf_id().expect("DPF identity"), dpu.id.to_string());
    }
    let host = snapshot.host_snapshot;
    let primary = host.primary_attached_dpu_machine_id().expect("primary DPU");
    let secondary = snapshot
        .dpu_snapshots
        .iter()
        .find(|dpu| dpu.id != primary)
        .expect("secondary DPU")
        .id;
    let mut network = forge::InstanceNetworkConfig::default();
    let mut expected = BTreeMap::new();
    for (dpu, segment) in [primary, secondary].iter().zip(&segments) {
        let locator = host.get_device_locator_for_dpu_id(dpu)?;
        let mut interface = single_interface_network_config(*segment)
            .interfaces
            .remove(0);
        interface.device = Some(locator.device);
        interface.device_instance = locator.device_instance as u32;
        network.interfaces.push(interface);
        let vpc = db::vpc::find_by_segment(&env.pool, *segment)
            .await?
            .expect("segment VPC");
        expected.insert(dpu.to_string(), vpc.id.to_string());
    }
    let instance = mh.instance_builer(&env).network(network).build().await;
    for _ in 0..3 {
        env.run_machine_state_controller_iteration().await;
    }
    let names = {
        let services = services.lock().expect("services");
        assert_eq!(services.len(), expected.len());
        let mut actual = BTreeMap::new();
        for service in services.values() {
            assert_eq!(service.namespace.as_deref(), Some(NAMESPACE));
            assert_eq!(service.helm_chart.version, "1.2.3");
            let values = service.helm_chart.values.as_ref().expect("chart values");
            assert_eq!(values["image"]["tag"], "integration-test");
            let dpu = &service.labels[DPU_LABEL];
            let devices = devices.lock().expect("device owners");
            let device = devices
                .iter()
                .find(|(_, id)| *id == dpu)
                .expect("device owner")
                .0;
            assert_eq!(service.owner_references.len(), 1);
            assert_eq!(
                service.owner_references[0].uid,
                format!("device-uid-{device}")
            );
            assert!(values.get("serviceDaemonSet").is_none());
            let daemon_set = service.service_daemon_set.as_ref().expect("daemon set");
            assert_eq!(
                daemon_set.node_selector,
                Some(json!({"nodeSelectorTerms": [{"matchExpressions": [{
                    "key": DPU_LABEL, "operator": "In", "values": [dpu]
                }]}]}))
            );
            actual.insert(dpu.clone(), service.labels[VPC_LABEL].clone());
        }
        assert_eq!(actual, expected);
        services.keys().cloned().collect::<Vec<_>>()
    };
    env.run_machine_state_controller_iteration().await;
    assert_eq!(
        services
            .lock()
            .expect("services")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        names
    );

    let expected_node_labels = devices
        .lock()
        .expect("device owners")
        .iter()
        .filter(|(_, dpu)| expected.contains_key(*dpu))
        .map(|(device, dpu)| {
            (
                device.clone(),
                BTreeMap::from([(DPU_LABEL.into(), dpu.clone())]),
            )
        })
        .collect::<HashMap<_, _>>();
    assert_eq!(
        *node_labels.lock().expect("node labels"),
        expected_node_labels
    );

    env.api
        .release_instance(Request::new(forge::InstanceReleaseRequest {
            id: Some(instance.id),
            ..Default::default()
        }))
        .await?;
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.host().id,
        8,
        ManagedHostState::Assigned {
            instance_state: InstanceState::HostPlatformConfiguration {
                platform_config_state: HostPlatformConfigurationState::CheckHostConfig,
            },
        },
    )
    .await;
    mh.network_configured(&env).await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.host().id,
        2,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForDpusToUp,
        },
    )
    .await;
    mh.network_configured(&env).await;
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.host().id,
        1,
        ManagedHostState::Assigned {
            instance_state: InstanceState::BootingWithDiscoveryImage {
                retry: model::machine::RetryInfo { count: 0 },
            },
        },
    )
    .await;
    let mut txn = env.db_txn().await;
    let machine = mh.host().db_machine(&mut txn).await;
    db::machine::update_reboot_time(&machine, &mut txn).await?;
    txn.commit().await?;
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.host().id,
        2,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForNetworkReconfig,
        },
    )
    .await;
    env.run_machine_state_controller_iteration().await;
    assert!(
        services
            .lock()
            .expect("services")
            .values()
            .all(|service| !service.is_deleting)
    );
    let mut txn = env.db_txn().await;
    let waiting = mh.snapshot(&mut txn).await;
    assert!(waiting.use_admin_network());
    assert!(!waiting.managed_host_network_config_version_synced());
    assert!(waiting.needs_site_prefix_isolation());
    txn.commit().await?;
    mh.network_configured(&env).await;
    env.run_machine_state_controller_iteration().await;
    assert!(
        services
            .lock()
            .expect("services")
            .values()
            .all(|service| service.is_deleting)
    );
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    assert_eq!(
        mh.snapshot(&mut txn).await.managed_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForNetworkReconfig
        }
    );
    txn.commit().await?;
    services.lock().expect("services").clear();
    env.run_ib_fabric_monitor_iteration().await;
    env.run_ib_fabric_monitor_iteration().await;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    assert_ne!(
        mh.snapshot(&mut txn).await.managed_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForNetworkReconfig
        }
    );
    txn.commit().await?;
    Ok(())
}

#[crate::sqlx_test]
async fn unbound_preserves_workloads_while_dpf_recreates_missing_owners(
    pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let owners = Arc::new(Mutex::new(BTreeMap::<String, ObjectMeta>::new()));
    let services = Arc::new(Mutex::new(BTreeMap::<String, DpuServiceObservation>::new()));
    let device_registrations = Arc::new(AtomicUsize::new(0));
    let node_registrations = Arc::new(AtomicUsize::new(0));
    let service_lists = Arc::new(AtomicUsize::new(0));
    let device_ready = Arc::new(AtomicBool::new(true));
    let metadata_timeout = Arc::new(AtomicBool::new(false));
    let metadata_fault_reads = Arc::new(AtomicUsize::new(0));
    let mut mock = MockDpfOperations::new();
    let writes = owners.clone();
    let registrations = device_registrations.clone();
    mock.expect_register_dpu_device()
        .returning(move |info, _, _| {
            let generation = registrations.fetch_add(1, Ordering::SeqCst);
            writes.lock().expect("owners").insert(
                info.device_id.clone(),
                ObjectMeta {
                    name: Some(carbide_dpf::dpu_device_cr_name(&info.device_id)),
                    namespace: Some(NAMESPACE.into()),
                    uid: Some(format!("device-uid-{generation}")),
                    labels: Some(BTreeMap::from([(DPU_LABEL.into(), info.dpu_machine_id)])),
                    ..Default::default()
                },
            );
            Ok(())
        });
    let registrations = node_registrations.clone();
    mock.expect_register_dpu_node().returning(move |_| {
        registrations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    mock.expect_release_maintenance_hold().returning(|_| Ok(()));
    mock.expect_is_reboot_required().returning(|_| Ok(false));
    let ready = device_ready.clone();
    mock.expect_get_dpu_phase().returning(move |_, _| {
        Ok(if ready.load(Ordering::SeqCst) {
            carbide_dpf::DpuPhase::Ready
        } else {
            carbide_dpf::DpuPhase::Provisioning("OsInstalling".into())
        })
    });
    mock.expect_deployment_type_for_dpu()
        .returning(|_, _| Ok(carbide_dpf::DpuDeploymentType::Bf3));
    mock.expect_verify_node_labels().returning(|_, _| Ok(true));
    mock.expect_get_service_versions_for_dpu()
        .returning(|_| Ok(vec![]));
    mock.expect_snapshot_host().times(1).returning(|_| {
        Ok(carbide_dpf::types::HostDpfSnapshot {
            dpu_node: None,
            dpu_devices: vec![],
            dpus: vec![],
        })
    });
    let reads = owners.clone();
    let timeout = metadata_timeout.clone();
    let fault_reads = metadata_fault_reads.clone();
    mock.expect_get_dpu_device_metadata()
        .returning(move |device| {
            if timeout.load(Ordering::SeqCst) {
                if fault_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Ok(None);
                }
                return Err(carbide_dpf::DpfError::Timeout {
                    operation: "DPUDevice metadata lookup".into(),
                    details: "injected metadata timeout".into(),
                });
            }
            Ok(reads.lock().expect("owners").get(device).cloned())
        });
    let reads = owners.clone();
    mock.expect_get_dpu_device_node_labels()
        .returning(move |device| {
            Ok(reads.lock().expect("owners")[device]
                .labels
                .clone()
                .expect("owner labels"))
        });
    let reads = services.clone();
    let lists = service_lists.clone();
    mock.expect_list_dpu_services().returning(move |_| {
        lists.fetch_add(1, Ordering::SeqCst);
        Ok(reads.lock().expect("services").values().cloned().collect())
    });
    let reads = services.clone();
    mock.expect_get_dpu_service()
        .returning(move |name| Ok(reads.lock().expect("services").get(name).cloned()));
    let writes = services.clone();
    mock.expect_create_dpu_service()
        .returning(move |definition| {
            let service = dpu_service_observation(definition);
            assert!(
                writes
                    .lock()
                    .expect("services")
                    .insert(definition.name.clone(), service.clone())
                    .is_none()
            );
            Ok(service)
        });
    mock.expect_patch_dpu_service().never();
    mock.expect_delete_dpu_service().never();

    let mut config = get_config();
    config.dpf.enabled = true;
    config.dpf.deployments.bf3.bfb_url = Some("http://example.com/test.bfb".into());
    let mut service = crate::dpf_services::default_unbound_service();
    service.helm_version = "1.2.3".into();
    service.docker_image_tag = "integration-test".into();
    service.extra_helm_values = json!({"unboundConfig": "server:\n  interface: 127.0.0.1\n"})
        .as_object()
        .cloned();
    config.dpf.unbound = Some(DpfUnboundConfig {
        enabled: true,
        service,
    });
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config).with_dpf_sdk(Arc::new(mock)),
    )
    .await;
    let mh = create_managed_host_with_dpf_multi(&env, 2).await;
    let segments = env.create_vpc_and_tenant_segments(2).await;
    let mut txn = env.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    txn.commit().await?;
    let device_ids = snapshot
        .dpu_snapshots
        .iter()
        .map(|dpu| dpu.dpf_id().expect("DPF identity"))
        .collect::<Vec<_>>();
    let mut network = forge::InstanceNetworkConfig::default();
    for (dpu, segment) in snapshot.dpu_snapshots.iter().zip(&segments) {
        let locator = snapshot
            .host_snapshot
            .get_device_locator_for_dpu_id(&dpu.id)?;
        let mut interface = single_interface_network_config(*segment)
            .interfaces
            .remove(0);
        interface.device = Some(locator.device);
        interface.device_instance = locator.device_instance as u32;
        network.interfaces.push(interface);
    }
    let _instance = mh.instance_builer(&env).network(network).build().await;
    assert_eq!(services.lock().expect("services").len(), 2);
    let names = services
        .lock()
        .expect("services")
        .keys()
        .cloned()
        .collect::<Vec<_>>();

    // One missing owner must preserve the complete workload set, including the healthy DPU.
    owners.lock().expect("owners").remove(&device_ids[0]);
    let lists_before = service_lists.load(Ordering::SeqCst);
    env.run_machine_state_controller_iteration().await;
    assert_eq!(service_lists.load(Ordering::SeqCst), lists_before);
    assert_eq!(
        services
            .lock()
            .expect("services")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        names
    );

    // Reproduce control-plane loss after an approved reprovision has started.
    owners.lock().expect("owners").clear();
    device_ready.store(false, Ordering::SeqCst);
    let devices_before = device_registrations.load(Ordering::SeqCst);
    let nodes_before = node_registrations.load(Ordering::SeqCst);
    let mut txn = env.db_txn().await;
    for dpu in &mh.dpu_ids {
        db::machine::trigger_dpu_reprovisioning_request(dpu, &mut txn, "test", true).await?;
        db::machine::approve_dpu_reprovision_request(dpu, &mut txn).await?;
        db::machine::update_dpu_reprovision_start_time(dpu, &mut txn).await?;
    }
    db::machine::update_state(
        &mut txn,
        &mh.id,
        &ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: DpuReprovisionStates {
                    states: mh
                        .dpu_ids
                        .iter()
                        .map(|id| {
                            (
                                *id,
                                ReprovisionState::DpfStates {
                                    substate: DpfState::Reprovisioning,
                                },
                            )
                        })
                        .collect(),
                },
            },
        },
    )
    .await?;
    txn.commit().await?;
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    let recovered = mh.snapshot(&mut txn).await;
    txn.commit().await?;
    assert_eq!(
        recovered.managed_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision {
                dpu_states: DpuReprovisionStates {
                    states: mh
                        .dpu_ids
                        .iter()
                        .map(|id| (
                            *id,
                            ReprovisionState::DpfStates {
                                substate: DpfState::WaitingForReady { phase_detail: None },
                            }
                        ))
                        .collect(),
                },
            },
        }
    );
    assert_eq!(
        device_registrations.load(Ordering::SeqCst),
        devices_before + 2
    );
    assert_eq!(node_registrations.load(Ordering::SeqCst), nodes_before + 1);
    assert_eq!(service_lists.load(Ordering::SeqCst), lists_before);
    assert_eq!(
        services
            .lock()
            .expect("services")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        names
    );

    // A missing owner must not hide an error while reading the other owner.
    metadata_fault_reads.store(0, Ordering::SeqCst);
    metadata_timeout.store(true, Ordering::SeqCst);
    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    let failed = mh.snapshot(&mut txn).await;
    txn.commit().await?;
    assert!(matches!(failed.host_snapshot.controller_state_outcome,
        Some(model::controller_outcome::PersistentStateHandlerOutcome::Error { err, .. })
            if err.contains("injected metadata timeout")
    ));
    assert_eq!(service_lists.load(Ordering::SeqCst), lists_before);
    assert_eq!(metadata_fault_reads.load(Ordering::SeqCst), 2);
    metadata_timeout.store(false, Ordering::SeqCst);

    // After Kubernetes collects the old owners' workloads, reconciliation must resume.
    services.lock().expect("services").clear();
    env.run_machine_state_controller_iteration().await;
    let services = services.lock().expect("services");
    assert_eq!(services.keys().cloned().collect::<Vec<_>>(), names);
    let owners = owners.lock().expect("owners");
    for service in services.values() {
        let owner = owners
            .values()
            .find(|owner| {
                owner.labels.as_ref().expect("owner labels")[DPU_LABEL] == service.labels[DPU_LABEL]
            })
            .expect("recreated owner");
        assert_eq!(Some(&service.owner_references[0].uid), owner.uid.as_ref());
    }
    Ok(())
}
