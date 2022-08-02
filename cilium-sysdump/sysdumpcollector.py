#!/usr/bin/env python
# Copyright 2017-2020 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import functools
import json
import logging
import multiprocessing
import os
import re
import shutil
import subprocess
from multiprocessing.pool import ThreadPool

import namespace
import utils

log = logging.getLogger(__name__)


class SysdumpCollector(object):
    """Collects logs and other useful information for debugging.

    Args:
        sysdump_dir_name: the sysdump file name.
        since: the relative duration duration (like 5s, 2m, or 3h) used to
            decide how old the logs can be for them to be collected.
        size_limit: size limit (MB) for the collected logs.
    """

    def __init__(
            self,
            sysdump_dir_name, since, size_limit, output, is_quick_mode,
            cilium_labels, hubble_labels, hubble_relay_labels,
            hubble_ui_labels):
        self.sysdump_dir_name = sysdump_dir_name
        self.since = since
        self.size_limit = size_limit
        self.output = output
        self.is_quick_mode = is_quick_mode
        self.cilium_labels = cilium_labels
        self.hubble_labels = hubble_labels
        self.hubble_relay_labels = hubble_relay_labels
        self.hubble_ui_labels = hubble_ui_labels

    def collect_nodes_overview(self):
        log.info("collecting nodes overview ...")

        nodes_overview_file_name = f"nodes-{utils.get_current_time()}.json"
        cmd = f"kubectl get nodes -o json > {self.sysdump_dir_name}/{nodes_overview_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error(
                    f"Error: {exc}. Could not collect nodes overview: {nodes_overview_file_name}"
                )

        else:
            log.info(f"collected nodes overview: {nodes_overview_file_name}")

    def collect_pods_overview(self):
        log.info("collecting pods overview ...")

        pods_overview_file_name = f"pods-{utils.get_current_time()}.json"
        cmd = f"kubectl get pods -o json --all-namespaces > {self.sysdump_dir_name}/{pods_overview_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error(
                    f"Error: {exc}. Could not collect pods overview: {pods_overview_file_name}"
                )

        else:
            log.info(f"collected pods overview: {pods_overview_file_name}")

    def collect_pods_summary(self):
        log.info("collecting pods summary ...")

        pods_summary_file_name = f"pods-{utils.get_current_time()}.txt"
        cmd = f"kubectl get pods --all-namespaces -o wide > {self.sysdump_dir_name}/{pods_summary_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error(
                    f"Error: {exc}. Could not collect pods summary: {pods_summary_file_name}"
                )

        else:
            log.info(f"collected pods summary: {pods_summary_file_name}")

    def collect_logs(self, pool, subject, label_selector, node_filter):
        log.info(f"collecting {subject} logs ...")

        must_exist = "hubble" not in label_selector
        pool.map_async(
            self.collect_logs_per_pod,
            utils.get_pods_status_iterator_by_labels(
                label_selector,
                node_filter,
                must_exist=must_exist,
            ))

    def collect_logs_per_pod(self, podstatus):
        containers = utils.get_container_names_per_pod(podstatus.namespace,
                                                       podstatus.name)
        # Only get logs from previous containers if pod has restarted.
        # Need to get the pod to access its restartCount.
        podCommandPreFormatted = "kubectl get pod {} -n {} -o json"
        for container in containers:
            log_file_name = f"{podstatus.name}-{container}-{utils.get_current_time()}"
            command = "kubectl logs {} --container={} --timestamps=true " \
                          "--since={} --limit-bytes={} -n {} > {}/{}.log"
            cmd = command.format(
                podstatus.name, container, self.since, self.size_limit,
                podstatus.namespace, self.sysdump_dir_name, log_file_name)
            try:
                subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.error(f"Error: {exc}. Could not collect log file: {log_file_name}")
            else:
                log.info(f"collected log file: {log_file_name}")

            podCmd = podCommandPreFormatted.format(
                podstatus.name, podstatus.namespace,
            )

            try:
                podOutput = subprocess.check_output(
                    podCmd, shell=True, stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.debug("Debug {}: could not get pod {}").format(
                        exc, podstatus[0])
            else:
                # Examine JSON output to see if restartCount > 0
                decodedPodOutput = podOutput.decode()
                jsonOutput = json.loads(decodedPodOutput)
                containerStatuses = jsonOutput['status']['containerStatuses']

                gatherPrevLogs = False

                for value in containerStatuses:
                    restartCount = value['restartCount']
                    if int(restartCount) > 0:
                        gatherPrevLogs = True
                        break
                if gatherPrevLogs:
                    log_file_name_previous = "{0}-previous".format(
                        log_file_name)
                    command = "kubectl logs --previous --timestamps=true " \
                                  "--container={} " \
                                  "--since={} " \
                                  "--limit-bytes={} -n {} {} > {}/{}.log"
                    cmd = command.format(container, self.since,
                                         self.size_limit,
                                         podstatus.namespace, podstatus.name,
                                         self.sysdump_dir_name,
                                         log_file_name_previous)
                    try:
                        subprocess.check_output(
                            cmd, shell=True, stderr=subprocess.STDOUT,
                        )
                    except subprocess.CalledProcessError as exc:
                        if exc.returncode != 0:
                            log.debug(
                                f"Debug: {exc}. Could not collect previous log for '{podstatus.name}': {log_file_name}"
                            )

                    else:
                        log.info(f"collected log file: {log_file_name_previous}")

                else:
                    log.debug(
                        f"no previous pod logs to gather for pod/container {podstatus.name}/{container}"
                    )

    def collect_gops_stats(self, pool, subject, label_selector, node_filter):
        log.info(f"collecting {subject} gops stats ...")

        self.collect_gops(pool, label_selector, node_filter, "stats")
        self.collect_gops(pool, label_selector, node_filter, "memstats")
        self.collect_gops(pool, label_selector, node_filter, "stack")

    def collect_gops(self, pool, label_selector, node_filter, type_of_stat):
        must_exist = "hubble" not in label_selector
        pool.map_async(
            functools.partial(self.collect_gops_per_pod,
                              type_of_stat=type_of_stat),
            utils.get_pods_status_iterator_by_labels(
                label_selector,
                node_filter,
                must_exist=must_exist,
            ))

    def collect_gops_per_pod(self, podstatus, type_of_stat):
        containers = utils.get_container_names_per_pod(podstatus.namespace,
                                                       podstatus.name,
                                                       init_containers=False)
        for container in containers:
            if container == "hubble-ui":
                continue  # gops does not run in hubble-ui container
            file_name = f"{podstatus.name}-{container}-{utils.get_current_time()}-{type_of_stat}.txt"

            cmd = f"kubectl exec -n {podstatus.namespace} {podstatus.name} -c {container} -- /bin/gops {type_of_stat} 1 > {self.sysdump_dir_name}/{file_name}"

            try:
                subprocess.check_output(
                    cmd,
                    shell=True,
                    stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.warning(
                        f"Warning: {exc}. Could not collect gops {type_of_stat}: {file_name}"
                    )

            else:
                log.info(f"collected gops {type_of_stat} file: {file_name}")

    def collect_netpol(self):
        log.info("collecting kubernetes network policy ...")

        netpol_file_name = f"netpol-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get netpol -o yaml --all-namespaces > {self.sysdump_dir_name}/{netpol_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning(
                    f"Warning: {exc}. Could not collect kubernetes network policy: {netpol_file_name}"
                )

        else:
            log.info(f"collected kubernetes network policy: {netpol_file_name}")

    def collect_cnp(self):
        log.info("collecting cilium network policy ...")

        cnp_file_name = f"cnp-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get cnp -o yaml --all-namespaces > {self.sysdump_dir_name}/{cnp_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning(
                    f"Warning: {exc}. Could not collect cilium network policy: {cnp_file_name}"
                )

        else:
            log.info(f"collected cilium network policy: {cnp_file_name}")

    def collect_ccnp(self):
        log.info("collecting cilium clusterwide network policy ...")

        ccnp_file_name = f"ccnp-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get ccnp -o yaml --all-namespaces > {self.sysdump_dir_name}/{ccnp_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning(
                    f"Warning: {exc}. Could not collect cilium clusterwide network policy: {ccnp_file_name}"
                )

        else:
            log.info(f"collected cilium clusterwide network policy: {ccnp_file_name}")

    def collect_cep(self):
        log.info("collecting cilium endpoints ...")

        cep_file_name = f"cep-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get cep -o yaml --all-namespaces > {self.sysdump_dir_name}/{cep_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error(f"Error: {exc}. Could not collect cilium endpoints {cep_file_name}")
        else:
            log.info(f"collected cilium endpoints: {cep_file_name}")

    def collect_ciliumids(self):
        log.info("collecting cilium identities ...")

        ciliumids_file_name = f"ciliumidentities-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get ciliumidentities -o yaml --all-namespaces > {self.sysdump_dir_name}/{ciliumids_file_name}"

        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error(
                    f"Error: {exc}. Could not collect cilium identities {ciliumids_file_name}"
                )

        else:
            log.info(f"collected cilium identities: {ciliumids_file_name}")

    def collect_ciliumnodes(self):
        log.info("collecting cilium nodes ...")

        ciliumnodes_file_name = f"ciliumnodes-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get ciliumnodes -o yaml --all-namespaces > {self.sysdump_dir_name}/{ciliumnodes_file_name}"

        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error(
                    f"Error: {exc}. Could not collect cilium nodes {ciliumnodes_file_name}"
                )

        else:
            log.info(f"collected cilium nodes: {ciliumnodes_file_name}")

    def collect_deployment_yaml(self, name):
        log.info(f"collecting {name} deployment yaml ...")

        ns = namespace.cilium_ns
        fname = f"{name}-deployment-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get deployment {name} -n {ns} -oyaml > {self.sysdump_dir_name}/{fname}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning(f"{exc}. Unable to get {name} deployment yaml")
        else:
            log.info(f"collected {name} deployment yaml file: {fname}")

    def collect_daemonset_yaml(self, name):
        log.info(f"collecting {name} daemonset yaml ...")

        ns = namespace.cilium_ns
        if name == "hubble":
            ns = namespace.hubble_ns
        file_name = f"{name}-ds-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get ds {name} -n {ns} -oyaml > {self.sysdump_dir_name}/{file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0 and name != "hubble":
                log.warning(f"{exc}. Unable to get {name} daemonset yaml")
        else:
            log.info(f"collected {name} daemonset yaml file: {file_name}")

    def collect_cilium_configmap(self):
        log.info("collecting cilium configmap yaml ...")

        configmap_file_name = f"cilium-configmap-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get configmap cilium-config -n {namespace.cilium_ns} -oyaml > {self.sysdump_dir_name}/{configmap_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning(f"Warning: {exc}. Unable to get cilium configmap yaml")
        else:
            log.info(f"collected cilium configmap yaml file: {configmap_file_name}")

    def collect_cilium_secret(self):
        log.info("collecting cilium etcd secret ...")

        secret_file_name = f"cilium-etcd-secrets-{utils.get_current_time()}.json"
        cmd = f"kubectl get secret cilium-etcd-secrets -n {namespace.cilium_ns} -o json"

        try:
            output = json.loads(
                subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT,
                ).decode("utf-8"))
            data = {key: "XXXXX" for key, value in output.get('data').items()}
            output['data'] = data
            with open(
                os.path.join(self.sysdump_dir_name,
                             secret_file_name), 'w') as fp:
                fp.write(json.dumps(output))
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.info(
                    f"{exc}. Unable to get and redact cilium secret (this is expected in CRD mode)."
                )

        else:
            log.info(f"collected and redacted cilium secret file: {secret_file_name}")

    def collect_cilium_bugtool_output(self, pool, label_selector, node_filter):
        log.info("collecting cilium-bugtool output ...")

        must_exist = "hubble" not in label_selector
        pool.map_async(
            self.collect_cilium_bugtool_output_per_pod,
            utils.get_pods_status_iterator_by_labels(
                label_selector,
                node_filter,
                must_exist=must_exist,
            ))

    def collect_cilium_bugtool_output_per_pod(self, podstatus):
        bugtool_output_dir = f"bugtool-{podstatus.name}-{utils.get_current_time()}"
        bugtool_output_file_name = f"{bugtool_output_dir}.tar"
        cmd = f"kubectl exec -n {podstatus.namespace} {podstatus.name} -c cilium-agent cilium-bugtool"

        try:
            encoded_output = subprocess.check_output(
                cmd.split(), shell=False, stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error(f"Error: {exc}. Could not run cilium-bugtool on {podstatus.name}")
        else:
            output = encoded_output.decode()
            p = re.compile(
                "^ARCHIVE at (.*)$")
            output_file_name = ""
            for line in output.splitlines():
                if match := p.search(line):
                    output_file_name = match[1]
            if output_file_name == "":
                log.error(
                    "Error: could not find cilium-bugtool output file name",
                )

            copyCmd = f"kubectl cp {podstatus.namespace}/{podstatus.name}:{output_file_name} ./{self.sysdump_dir_name}/{bugtool_output_file_name}"

            mkdirCmd = f"mkdir -p ./{self.sysdump_dir_name}/{bugtool_output_dir}"
            tarCmd = f"tar -xf ./{self.sysdump_dir_name}/{bugtool_output_file_name} -C ./{self.sysdump_dir_name}/{bugtool_output_dir} --strip-components=1"

            rmCmd = f"rm ./{self.sysdump_dir_name}/{bugtool_output_file_name}"
            try:
                subprocess.check_output(
                    copyCmd.split(), shell=False, stderr=subprocess.STDOUT,
                )
                subprocess.check_output(
                    mkdirCmd.split(), shell=False, stderr=subprocess.STDOUT,
                )
                subprocess.check_output(
                    tarCmd.split(), shell=False, stderr=subprocess.STDOUT,
                )
                subprocess.check_output(
                    rmCmd.split(), shell=False, stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.error(
                        f"Error: {exc} Could not collect cilium-bugtool output: {bugtool_output_file_name}"
                    )

            else:
                log.info(f"collected cilium-bugtool output: {bugtool_output_file_name}")

    def collect_services_overview(self):
        log.info("collecting services overview ...")

        svc_file_name = f"services-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get svc --all-namespaces -oyaml > {self.sysdump_dir_name}/{svc_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get svc overview")
        else:
            log.info(f"collected svc overview: {svc_file_name}")

    def collect_k8s_version_info(self):
        log.info("collecting kubernetes version info ...")

        version_file_name = f"k8s-version-info-{utils.get_current_time()}.txt"
        cmd = f"kubectl version > {self.sysdump_dir_name}/{version_file_name}"
        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get kubernetes version info")
        else:
            log.info(f"collected kubernetes version info: {version_file_name}")

    def collect_k8s_events(self):
        log.info("collecting Kubernetes events JSON ...")

        events_file_name = f"k8s-events-{utils.get_current_time()}.json"
        cmd = f"kubectl get events --all-namespaces -o json > {self.sysdump_dir_name}/{events_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get kubernetes events.")
        else:
            log.info(f"collected kubernetes events: {events_file_name}")

    def collect_k8s_namespaces(self):
        log.info("collecting Kubernetes namespaces yaml ...")

        namespaces_file_name = f"k8s-namespaces-{utils.get_current_time()}.yaml"
        cmd = f"kubectl get ns -o yaml > {self.sysdump_dir_name}/{namespaces_file_name}"

        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get kubernetes namespaces.")
        else:
            log.info(f"collected kubernetes namespaces: {namespaces_file_name}")

    def collect(self, node_filter):
        pool = ThreadPool(min(32, multiprocessing.cpu_count() + 4))

        pool.apply_async(self.collect_k8s_version_info, ())
        pool.apply_async(self.collect_k8s_events, ())
        pool.apply_async(self.collect_k8s_namespaces, ())
        pool.apply_async(self.collect_nodes_overview, ())
        pool.apply_async(self.collect_pods_overview, ())
        pool.apply_async(self.collect_pods_summary, ())
        pool.apply_async(self.collect_services_overview, ())
        self.collect_gops_stats(pool, "cilium", self.cilium_labels,
                                node_filter)
        self.collect_gops_stats(pool, "hubble", self.hubble_labels,
                                node_filter)
        self.collect_gops_stats(pool, "hubble relay", self.hubble_relay_labels,
                                node_filter)
        pool.apply_async(self.collect_netpol, ())
        pool.apply_async(self.collect_cnp, ())
        pool.apply_async(self.collect_ccnp, ())
        pool.apply_async(self.collect_cilium_secret, ())
        pool.apply_async(self.collect_cep, ())
        pool.apply_async(self.collect_ciliumids, ())
        pool.apply_async(self.collect_ciliumnodes, ())
        pool.apply_async(self.collect_daemonset_yaml, ("cilium", ))
        pool.apply_async(self.collect_daemonset_yaml, ("hubble", ))
        pool.apply_async(self.collect_deployment_yaml, ("hubble-relay", ))
        pool.apply_async(self.collect_deployment_yaml, ("hubble-ui", ))
        pool.apply_async(self.collect_deployment_yaml, ("cilium-operator", ))
        pool.apply_async(self.collect_deployment_yaml,
                         ("clustermesh-apiserver", ))
        pool.apply_async(self.collect_cilium_configmap, ())

        if self.is_quick_mode:
            pool.close()
            pool.join()
            return

        # Time-consuming collect actions go here.
        self.collect_cilium_bugtool_output(pool, self.cilium_labels,
                                           node_filter)
        self.collect_logs(pool, "cilium", self.cilium_labels, node_filter)
        self.collect_logs(pool, "cilium operator", "io.cilium/app=operator",
                          [])
        self.collect_logs(pool, "hubble", self.hubble_labels, node_filter)
        self.collect_logs(pool, "hubble relay", self.hubble_relay_labels,
                          node_filter)
        self.collect_logs(pool, "hubble ui", self.hubble_ui_labels,
                          node_filter)
        self.collect_logs(pool, "clustermesh-apiserver",
                          "k8s-app=clustermesh-apiserver", [])

        pool.close()
        pool.join()

    def archive(self):
        filename = self.output or self.sysdump_dir_name
        archive_name = shutil.make_archive(filename, 'zip',
                                           self.sysdump_dir_name)
        log.info(f"deleting directory: {self.sysdump_dir_name}")
        shutil.rmtree(self.sysdump_dir_name)
        log.info(f"the sysdump has been saved in the file {archive_name}.")
