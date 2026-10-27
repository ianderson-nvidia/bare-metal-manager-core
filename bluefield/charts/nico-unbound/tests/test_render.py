# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Render the Unbound chart through the DPF Helm values contract."""

from pathlib import Path
import subprocess
import unittest

import yaml


CHART = Path(__file__).resolve().parents[1]
FIXTURE = CHART / "tests" / "values.yaml"


class UnboundChartTest(unittest.TestCase):
    def render(self, release="dns-a", values=None):
        rendered = subprocess.run(
            ["helm", "template", release, str(CHART), "--values", str(FIXTURE),
             "--values", "-"],
            input=yaml.safe_dump(values or {}),
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        return {resource["kind"]: resource for resource in yaml.safe_load_all(rendered.stdout)}

    def test_releases_keep_config_and_pods_separate(self):
        releases = {name: self.render(name) for name in ("dns-a", "dns-b")}
        for release, resources in releases.items():
            with self.subTest(release=release):
                self.assertEqual(set(resources), {"ConfigMap", "DaemonSet"})
                daemon_set = resources["DaemonSet"]
                self.assertEqual(daemon_set["metadata"]["name"], release)
                self.assertEqual(resources["ConfigMap"]["metadata"]["name"], release)
                selectors = daemon_set["spec"]["selector"]["matchLabels"]
                self.assertEqual(selectors["app.kubernetes.io/instance"], release)
                self.assertEqual(daemon_set["spec"]["template"]["metadata"]["labels"], selectors)
                self.assertEqual(daemon_set["spec"]["template"]["spec"]["volumes"], [
                    {"name": "config", "configMap": {"name": release}},
                ])
        pod = releases["dns-a"]["DaemonSet"]["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertFalse(pod.get("hostNetwork", False))
        container = pod["containers"][0]
        self.assertEqual(container["image"], "example.invalid/nico-unbound:0.1.0")
        self.assertNotIn("args", container)
        self.assertEqual(container["volumeMounts"], [
            {"name": "config", "mountPath": "/etc/unbound", "readOnly": True},
        ])
        self.assertEqual(container["ports"], [
            {"name": "dns-udp", "containerPort": 53, "protocol": "UDP"},
            {"name": "dns-tcp", "containerPort": 53, "protocol": "TCP"},
        ])
        self.assertEqual(container["securityContext"], {
            "runAsUser": 0,
            "readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
        })

    def test_dpf_placement_resources_and_metadata_reach_pods(self):
        node_selector = {"nodeSelectorTerms": [{"matchExpressions": [
            {"key": "kubernetes.io/hostname", "operator": "In", "values": ["dpu-a"]},
        ]}]}
        settings = {
            "nodeSelector": node_selector,
            "labels": {"dpu.nvidia.com/service": "dns-a"},
            "annotations": {"k8s.v1.cni.cncf.io/networks": "dns-network"},
            "resources": {"cpu": "250m", "memory": "128Mi"},
            "updateStrategy": {"type": "OnDelete"},
        }
        daemon_set = self.render(values={
            "serviceDaemonSet": settings,
            "image": {"tag": "test-tag"},
            "imagePullSecrets": [{"name": "registry"}],
        })["DaemonSet"]
        for metadata in (daemon_set["metadata"], daemon_set["spec"]["template"]["metadata"]):
            self.assertEqual(metadata["labels"]["dpu.nvidia.com/service"], "dns-a")
            self.assertEqual(metadata["annotations"]["k8s.v1.cni.cncf.io/networks"], "dns-network")
        self.assertEqual(daemon_set["spec"]["updateStrategy"], {"type": "OnDelete"})
        pod = daemon_set["spec"]["template"]["spec"]
        self.assertEqual(pod["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"], node_selector)
        self.assertEqual(pod["imagePullSecrets"], [{"name": "registry"}])
        self.assertEqual(pod["containers"][0]["image"], "example.invalid/nico-unbound:test-tag")
        self.assertEqual(pod["containers"][0]["resources"], {
            "limits": {"cpu": "250m", "memory": "128Mi"},
            "requests": {"cpu": "250m", "memory": "128Mi"},
        })

    def test_native_config_stays_literal_and_changes_restart_pods(self):
        initial = self.render()
        config = yaml.safe_load(FIXTURE.read_text())["unboundConfig"]
        self.assertEqual(initial["ConfigMap"]["data"]["unbound.conf"], config)
        updated = config + '# {{ fail "not a Helm template" }}\n'
        changed = self.render(values={"unboundConfig": updated})
        self.assertEqual(changed["ConfigMap"]["data"]["unbound.conf"], updated)
        initial_annotations = initial["DaemonSet"]["spec"]["template"]["metadata"]["annotations"]
        changed_annotations = changed["DaemonSet"]["spec"]["template"]["metadata"]["annotations"]
        self.assertNotEqual(initial_annotations["checksum/config"], changed_annotations["checksum/config"])

    def test_operator_inputs_are_required(self):
        valid = yaml.safe_load(FIXTURE.read_text())
        cases = (
            ("omitted config", {"image": valid["image"]}, "unboundConfig"),
            ("blank config", valid | {"unboundConfig": " \n"}, "unboundConfig"),
            ("omitted image", {"unboundConfig": valid["unboundConfig"]}, "image.repository"),
        )
        for name, values, field in cases:
            with self.subTest(name=name):
                rendered = subprocess.run(
                    ["helm", "template", "dns-a", str(CHART), "--values", "-"],
                    input=yaml.safe_dump(values),
                    capture_output=True, text=True, timeout=30,
                )
                self.assertNotEqual(rendered.returncode, 0)
                self.assertIn(field, rendered.stderr)


if __name__ == "__main__":
    unittest.main()
