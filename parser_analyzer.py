
"""
Enhanced Amazon Ion file parser for Kubernetes resources with health analysis
Supports multiple files and directory structures
Includes comprehensive health monitoring and issue detection

This is work in progrss and its not for hackweek :)
"""

import amazon.ion.simpleion as ion
from datetime import datetime
import os
import glob
from typing import List, Dict, Any, Union


class KubernetesHealthAnalyzer:
    """Health analysis component for Kubernetes resources"""
    
    @staticmethod
    def analyze_pod_health(pod_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual pod health"""
        issues = []
        pod_name = pod_data.get('name', 'unknown')
        namespace = pod_data.get('namespace', 'unknown')
        
        # Extract status from managed fields or direct structure
        status_info = KubernetesHealthAnalyzer._extract_status_from_managed_fields(pod_data)
        
        health_info = {
            'name': pod_name,
            'namespace': namespace,
            'phase': status_info.get('phase', 'Unknown'),
            'ready': status_info.get('ready', False),
            'restart_count': status_info.get('restart_count', 0),
            'container_statuses': status_info.get('container_statuses', []),
            'conditions': status_info.get('conditions', []),
            'issues': [],
            'health_score': 100,
            'is_healthy': True
        }
        
        # Analyze pod phase
        phase = health_info['phase']
        if phase not in ['Running', 'Succeeded']:
            severity = 'critical' if phase == 'Failed' else 'high' if phase == 'Pending' else 'medium'
            issues.append({
                'type': 'pod_unhealthy',
                'severity': severity,
                'resource': f"{namespace}/{pod_name}",
                'status': phase,
                'message': f"Pod {pod_name} in {namespace} is in {phase} state"
            })
            health_info['health_score'] -= 50
            health_info['is_healthy'] = False
        
        # Analyze container statuses
        for container_status in health_info['container_statuses']:
            container_name = container_status.get('name', 'unknown')
            
            # Check if container is ready
            if not container_status.get('ready', False):
                restart_count = container_status.get('restart_count', 0)
                severity = 'critical' if restart_count > 10 else 'high' if restart_count > 5 else 'medium'
                issues.append({
                    'type': 'container_not_ready',
                    'severity': severity,
                    'resource': f"{namespace}/{pod_name}/{container_name}",
                    'restart_count': restart_count,
                    'message': f"Container {container_name} not ready (restarts: {restart_count})"
                })
                health_info['health_score'] -= 20
                health_info['is_healthy'] = False
            
            # Check for high restart count
            restart_count = container_status.get('restart_count', 0)
            if restart_count > 5:
                severity = 'critical' if restart_count > 20 else 'high' if restart_count > 10 else 'medium'
                issues.append({
                    'type': 'high_restart_count',
                    'severity': severity,
                    'resource': f"{namespace}/{pod_name}/{container_name}",
                    'restart_count': restart_count,
                    'message': f"Container {container_name} has high restart count: {restart_count}"
                })
                health_info['health_score'] -= min(restart_count * 2, 30)
            
            # Check container state
            state = container_status.get('state', {})
            if 'waiting' in state:
                waiting = state['waiting']
                reason = waiting.get('reason', '')
                if reason in ['ImagePullBackOff', 'ErrImagePull', 'CrashLoopBackOff']:
                    issues.append({
                        'type': 'container_waiting',
                        'severity': 'critical',
                        'resource': f"{namespace}/{pod_name}/{container_name}",
                        'reason': reason,
                        'message': f"Container {container_name} waiting: {reason} - {waiting.get('message', '')}"
                    })
                    health_info['health_score'] -= 40
                    health_info['is_healthy'] = False
            
            if 'terminated' in state:
                terminated = state['terminated']
                exit_code = terminated.get('exitCode', 0)
                if exit_code != 0:
                    issues.append({
                        'type': 'container_terminated',
                        'severity': 'high',
                        'resource': f"{namespace}/{pod_name}/{container_name}",
                        'exit_code': exit_code,
                        'message': f"Container {container_name} terminated with exit code {exit_code}: {terminated.get('reason', '')}"
                    })
                    health_info['health_score'] -= 30
        
        # Analyze pod conditions
        for condition in health_info['conditions']:
            condition_type = condition.get('type', '')
            status = condition.get('status', 'Unknown')
            
            if condition_type == 'Ready' and status != 'True':
                issues.append({
                    'type': 'pod_not_ready',
                    'severity': 'high',
                    'resource': f"{namespace}/{pod_name}",
                    'message': f"Pod {pod_name} not ready: {condition.get('message', '')}"
                })
                health_info['health_score'] -= 25
                health_info['is_healthy'] = False
            
            elif condition_type == 'PodScheduled' and status != 'True':
                issues.append({
                    'type': 'pod_not_scheduled',
                    'severity': 'critical',
                    'resource': f"{namespace}/{pod_name}",
                    'message': f"Pod {pod_name} not scheduled: {condition.get('message', '')}"
                })
                health_info['health_score'] -= 40
                health_info['is_healthy'] = False
        
        health_info['issues'] = issues
        health_info['health_score'] = max(0, health_info['health_score'])
        
        return health_info
    
    @staticmethod
    def analyze_event_criticality(event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze event criticality and extract key information"""
        event_info = {
            'name': event_data.get('name', 'unknown'),
            'namespace': event_data.get('namespace', 'unknown'),
            'uid': event_data.get('uid', 'unknown'),
            'type': 'Unknown',
            'reason': 'Unknown',
            'message': 'Unknown',
            'count': 1,
            'severity': 'low',
            'is_critical': False,
            'involved_object': {},
            'first_timestamp': event_data.get('creationTimestamp'),
            'last_timestamp': event_data.get('creationTimestamp')
        }
        
        # Extract event details from managed fields
        managed_fields = event_data.get('managedFields', [])
        for field in managed_fields:
            if field.get('manager') == 'kubelet' or 'event' in field.get('manager', ''):
                fields_v1 = field.get('fieldsV1', {})
                
                # Try to extract type, reason, message from field keys
                for key in fields_v1.keys():
                    if 'f:type' in key:
                        event_info['type'] = 'Warning'  # Most kubelet events are warnings
                    if 'f:reason' in key:
                        event_info['reason'] = 'Available'
                    if 'f:message' in key:
                        event_info['message'] = 'Available'
                    if 'f:count' in key:
                        event_info['count'] = 'Available'
                    if 'f:involvedObject' in key:
                        event_info['involved_object'] = {'available': True}
        
        # Determine severity based on event patterns
        event_name = event_info['name'].lower()
        
        # Critical event patterns
        critical_patterns = [
            'failed', 'error', 'crash', 'kill', 'oom', 'evict',
            'backoff', 'pullimage', 'mount', 'unhealthy'
        ]
        
        # High severity patterns
        high_patterns = [
            'warning', 'restart', 'probe', 'timeout', 'limit'
        ]
        
        if any(pattern in event_name for pattern in critical_patterns):
            event_info['severity'] = 'critical'
            event_info['is_critical'] = True
        elif any(pattern in event_name for pattern in high_patterns):
            event_info['severity'] = 'high'
        elif event_info['type'] == 'Warning':
            event_info['severity'] = 'medium'
        
        return event_info
    
    @staticmethod
    def analyze_node_health(node_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze node health from managed fields and structure"""
        node_name = node_data.get('name', 'unknown')
        
        node_info = {
            'name': node_name,
            'conditions': [],
            'capacity': {},
            'allocatable': {},
            'issues': [],
            'health_score': 100,
            'is_healthy': True,
            'ready': False
        }
        
        # Extract node information from managed fields
        managed_fields = node_data.get('managedFields', [])
        for field in managed_fields:
            if field.get('manager') == 'kubelet':
                fields_v1 = field.get('fieldsV1', {})
                status_fields = fields_v1.get('f:status', {})
                
                # Check for conditions
                conditions = status_fields.get('f:conditions', {})
                for condition_key in conditions.keys():
                    if 'Ready' in condition_key:
                        node_info['ready'] = True
                    elif any(pressure in condition_key for pressure in ['DiskPressure', 'MemoryPressure', 'PIDPressure']):
                        pressure_type = next((p for p in ['DiskPressure', 'MemoryPressure', 'PIDPressure'] if p in condition_key), 'Unknown')
                        node_info['issues'].append({
                            'type': 'resource_pressure',
                            'severity': 'high',
                            'resource': f"node/{node_name}",
                            'pressure_type': pressure_type,
                            'message': f"Node {node_name} has {pressure_type}"
                        })
                        node_info['health_score'] -= 30
                        node_info['is_healthy'] = False
                
                # Check for capacity and allocatable resources
                if 'f:capacity' in status_fields:
                    node_info['capacity'] = {'available': True}
                if 'f:allocatable' in status_fields:
                    node_info['allocatable'] = {'available': True}
        
        # Check if node is ready
        if not node_info['ready']:
            node_info['issues'].append({
                'type': 'node_not_ready',
                'severity': 'critical',
                'resource': f"node/{node_name}",
                'message': f"Node {node_name} is not ready"
            })
            node_info['health_score'] -= 50
            node_info['is_healthy'] = False
        
        return node_info
    
    @staticmethod
    def _extract_status_from_managed_fields(resource_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract status information from managed fields"""
        status_info = {
            'phase': 'Unknown',
            'ready': False,
            'restart_count': 0,
            'container_statuses': [],
            'conditions': []
        }
        
        managed_fields = resource_data.get('managedFields', [])
        for field in managed_fields:
            if field.get('manager') == 'kubelet' and field.get('subresource') == 'status':
                fields_v1 = field.get('fieldsV1', {})
                status_fields = fields_v1.get('f:status', {})
                
                # Extract phase
                if 'f:phase' in status_fields:
                    status_info['phase'] = 'Running'  # Most likely if kubelet is updating
                
                # Extract container statuses
                container_statuses = status_fields.get('f:containerStatuses', {})
                for key in container_statuses.keys():
                    if 'name' in key:
                        container_name = key.split('"name":"')[1].split('"')[0] if '"name":"' in key else 'unknown'
                        
                        container_info = {
                            'name': container_name,
                            'ready': 'f:ready' in container_statuses.get(key, {}),
                            'restart_count': 0,
                            'state': {}
                        }
                        
                        # Try to extract restart count from key patterns
                        if 'restartCount' in key:
                            import re
                            restart_match = re.search(r'restartCount["\s]*:[\s"]*(\d+)', key)
                            if restart_match:
                                container_info['restart_count'] = int(restart_match.group(1))
                        
                        status_info['container_statuses'].append(container_info)
                
                # Extract conditions
                conditions = status_fields.get('f:conditions', {})
                for condition_key in conditions.keys():
                    if 'type' in condition_key:
                        condition_type = condition_key.split('"type":"')[1].split('"')[0] if '"type":"' in condition_key else 'Unknown'
                        condition_info = {
                            'type': condition_type,
                            'status': 'True' if 'True' in condition_key else 'False'
                        }
                        status_info['conditions'].append(condition_info)
                        
                        if condition_type == 'Ready' and 'True' in condition_key:
                            status_info['ready'] = True
        
        return status_info

class MultiFileKubernetesResourceParser:
    """Enhanced parser for Kubernetes resources from multiple Ion files with health analysis"""
    
    def __init__(self, file_paths: Union[str, List[str]] = None, directory: str = None):
        """
        Initialize parser with file paths or directory
        
        Args:
            file_paths: Single file path, list of file paths, or glob pattern
            directory: Directory containing Ion files
        """
        self.file_paths = []
        self.directory = directory
        self.resources = []
        self.parsed_resources = {
            'services': [],
            'deployments': [],
            'pods': [],
            'events': [],
            'nodes': [],
            'unknown': []
        }
        self.file_resource_mapping = {}  # Track which resources came from which files
        self.health_analyzer = KubernetesHealthAnalyzer()
        
        # Handle different input types
        if file_paths:
            if isinstance(file_paths, str):
                if '*' in file_paths or '?' in file_paths:
                    # Handle glob patterns
                    self.file_paths = glob.glob(file_paths)
                else:
                    self.file_paths = [file_paths]
            elif isinstance(file_paths, list):
                self.file_paths = file_paths
        
        if directory:
            self._scan_directory(directory)
    
    def _scan_directory(self, directory: str):
        """Scan directory for Ion files"""
        if not os.path.exists(directory):
            print(f"Warning: Directory '{directory}' does not exist.")
            return
        
        # Look for common patterns
        patterns = [
            '*.ion',
            '*pods*.ion',
            '*services*.ion', 
            '*deployments*.ion',
            '*events*.ion',
            '*nodes*.ion'
        ]
        
        found_files = []
        for pattern in patterns:
            found_files.extend(glob.glob(os.path.join(directory, pattern)))
        
        # Remove duplicates and add to file_paths
        self.file_paths.extend(list(set(found_files)))
        
        if self.file_paths:
            print(f"Found {len(self.file_paths)} Ion files in directory '{directory}'")
            for file_path in sorted(self.file_paths):
                print(f"  - {os.path.basename(file_path)}")
        else:
            print(f"No Ion files found in directory '{directory}'")
    
    def add_file(self, file_path: str):
        """Add a single file to the parser"""
        if os.path.exists(file_path):
            self.file_paths.append(file_path)
            print(f"Added file: {file_path}")
        else:
            print(f"Warning: File '{file_path}' does not exist.")
    
    def add_files(self, file_paths: List[str]):
        """Add multiple files to the parser"""
        for file_path in file_paths:
            self.add_file(file_path)
    
    def read_ion_files(self) -> List[Dict[str, Any]]:
        """Read and parse all Ion files"""
        all_resources = []
        
        if not self.file_paths:
            print("No files to process. Please specify file paths or directory.")
            return []
        
        for file_path in self.file_paths:
            print(f"\nProcessing file: {os.path.basename(file_path)}")
            resources = self._read_single_ion_file(file_path)
            
            if resources:
                print(f"  Found {len(resources)} resources")
                all_resources.extend(resources)
                
                # Track which resources came from which file
                for resource in resources:
                    resource_id = resource.get('uid', f"{resource.get('name', 'unknown')}_{len(all_resources)}")
                    self.file_resource_mapping[resource_id] = file_path
            else:
                print(f"  No resources found")
        
        self.resources = all_resources
        print(f"\nTotal resources loaded: {len(all_resources)}")
        
        # Categorize all resources
        self._categorize_resources()
        return all_resources
    
    def _read_single_ion_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Read and parse a single Ion file"""
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
                
                if not content.strip():
                    print(f"  Warning: File '{file_path}' is empty")
                    return []
                
                ion_data = ion.loads(content, single_value=False)
                
                # Handle different data structures
                if isinstance(ion_data, list):
                    return ion_data
                elif isinstance(ion_data, dict):
                    return [ion_data]
                else:
                    print(f"  Warning: Unexpected data type in '{file_path}': {type(ion_data)}")
                    return []
                    
        except FileNotFoundError:
            print(f"  Error: File '{file_path}' not found.")
            return []
        except Exception as e:
            print(f"  Error reading Ion file '{file_path}': {str(e)}")
            return []
    
    def _categorize_resources(self):
        """Categorize resources by type based on their structure and naming patterns"""
        print(f"\nCategorizing {len(self.resources)} resources...")
        
        for resource in self.resources:
            resource_type = self._detect_resource_type(resource)
            self.parsed_resources[resource_type].append(resource)
        
        # Print categorization summary
        print("Categorization results:")
        for resource_type, resources in self.parsed_resources.items():
            if resources:
                print(f"  {resource_type.title()}: {len(resources)}")
    
    def _detect_resource_type(self, resource: Dict[str, Any]) -> str:
        """Detect the Kubernetes resource type based on structure and patterns"""
        name = resource.get('name', '')
        
        # Check for events (they have unique event-like names and structure)
        if ('.' in name and any(x in name for x in ['184b0507', 'event']) or 
            'involvedObject' in str(resource) or 'reason' in resource):
            return 'events'
        
        # Check managed fields for API version hints
        managed_fields = resource.get('managedFields', [])
        for field in managed_fields:
            api_version = field.get('apiVersion', '')
            if api_version == 'apps/v1':
                return 'deployments'
        
        # Check owner references for pod identification
        owner_refs = resource.get('ownerReferences', [])
        if owner_refs:
            for ref in owner_refs:
                if ref.get('kind') == 'ReplicaSet':
                    return 'pods'
        
        # Check for pod-specific patterns
        if ('-' in name and any(x in name for x in ['pod', 'deployment']) and 
            len(name.split('-')) >= 3):
            # Check if it has generateName (pods from deployments have this)
            if resource.get('generateName'):
                return 'pods'
        
        # Check for service-specific patterns
        if (name.endswith('-service') or name in ['kubernetes'] or 
            'service' in name.lower()):
            return 'services'
        
        # Check for deployment patterns
        if name.endswith('-deployment') or 'deployment' in name.lower():
            return 'deployments'
        
        # Check for node patterns
        if name.startswith('node-') or 'node' in name.lower():
            return 'nodes'
        
        # Default categorization based on structure
        if 'spec' in resource and 'selector' in resource.get('spec', {}):
            return 'deployments'
        elif 'spec' in resource and 'containers' in resource.get('spec', {}):
            return 'pods'
        elif 'involvedObject' in resource or 'reason' in resource:
            return 'events'
        
        return 'unknown'
    
    # HEALTH ANALYSIS METHODS
    def analyze_cluster_health(self) -> Dict[str, Any]:
        """Perform comprehensive cluster health analysis"""
        self.read_ion_files()
        
        # Analyze pods health
        pod_health_results = []
        healthy_pods = 0
        for pod in self.parsed_resources['pods']:
            health_info = self.health_analyzer.analyze_pod_health(pod)
            pod_health_results.append(health_info)
            if health_info['is_healthy']:
                healthy_pods += 1
        
        # Analyze events for criticality
        critical_events = []
        for event in self.parsed_resources['events']:
            event_analysis = self.health_analyzer.analyze_event_criticality(event)
            if event_analysis['is_critical'] or event_analysis['severity'] in ['critical', 'high']:
                critical_events.append(event_analysis)
        
        # Analyze nodes health
        node_health_results = []
        healthy_nodes = 0
        for node in self.parsed_resources['nodes']:
            health_info = self.health_analyzer.analyze_node_health(node)
            node_health_results.append(health_info)
            if health_info['is_healthy']:
                healthy_nodes += 1
        
        # Collect all issues
        all_issues = []
        for pod_health in pod_health_results:
            all_issues.extend(pod_health['issues'])
        
        for node_health in node_health_results:
            all_issues.extend(node_health['issues'])
        
        # Convert events to issue format
        for event in critical_events:
            all_issues.append({
                'type': 'k8s_event',
                'severity': event['severity'],
                'resource': f"{event['namespace']}/{event['name']}",
                'reason': event['reason'],
                'message': f"Critical event: {event['reason']}",
                'timestamp': event['first_timestamp']
            })
        
        # Calculate severity counts
        severity_counts = {
            'critical': len([i for i in all_issues if i.get('severity') == 'critical']),
            'high': len([i for i in all_issues if i.get('severity') == 'high']),
            'medium': len([i for i in all_issues if i.get('severity') == 'medium']),
            'low': len([i for i in all_issues if i.get('severity') == 'low'])
        }
        
        # Calculate overall cluster health score
        total_pods = len(pod_health_results)
        total_nodes = len(node_health_results)
        pod_health_score = sum(p['health_score'] for p in pod_health_results) / max(total_pods, 1)
        node_health_score = sum(n['health_score'] for n in node_health_results) / max(total_nodes, 1)
        
        # Weight: 70% pods, 30% nodes
        overall_health_score = (pod_health_score * 0.7 + node_health_score * 0.3) if total_nodes > 0 else pod_health_score
        
        return {
            'timestamp': datetime.now().isoformat(),
            'cluster_health': {
                'total_pods': total_pods,
                'healthy_pods': healthy_pods,
                'unhealthy_pods': total_pods - healthy_pods,
                'total_nodes': total_nodes,
                'healthy_nodes': healthy_nodes,
                'unhealthy_nodes': total_nodes - healthy_nodes,
                'overall_health_score': round(overall_health_score, 2),
                # 'health_status': self._determine_health_status(overall_health_score, severity_counts)
            },
            'issues': all_issues,
            'severity_counts': severity_counts,
            'issue_types': {
                'pod_issues': len([i for i in all_issues if 'pod' in i.get('type', '').lower()]),
                'node_issues': len([i for i in all_issues if 'node' in i.get('type', '').lower()]),
                'event_issues': len([i for i in all_issues if i.get('type') == 'k8s_event']),
                'container_issues': len([i for i in all_issues if 'container' in i.get('type', '').lower()])
            },
            'detailed_analysis': {
                'pod_health': pod_health_results,
                'node_health': node_health_results,
                'critical_events': critical_events
            },
            # 'recommendations': self._generate_recommendations(all_issues, severity_counts)
        }

    def extract_pod_info(self, pod: Dict[str, Any]) -> Dict[str, Any]:
        """Extract comprehensive pod information including health analysis"""
        basic_info = {
            'type': 'Pod',
            'name': pod.get('name', 'Unknown'),
            'namespace': pod.get('namespace', 'default'),
            'uid': pod.get('uid', 'Unknown'),
            'creation_timestamp': pod.get('creationTimestamp'),
            'labels': pod.get('labels', {}),
            'generate_name': pod.get('generateName'),
            'age': self._calculate_age(pod.get('creationTimestamp')),
            'pod_ip': self._extract_pod_ip(pod),
            'host_ip': self._extract_host_ip(pod),
            'source_file': self.file_resource_mapping.get(pod.get('uid', ''), 'Unknown')
        }
        
        # Add health analysis
        health_info = self.health_analyzer.analyze_pod_health(pod)
        basic_info.update({
            'health_analysis': health_info,
            'status': health_info['phase'],
            'is_healthy': health_info['is_healthy'],
            'health_score': health_info['health_score'],
            'issues_count': len(health_info['issues'])
        })
        
        # Extract owner information
        owner_refs = pod.get('ownerReferences', [])
        if owner_refs:
            owner = owner_refs[0]
            basic_info['owner_kind'] = owner.get('kind', 'Unknown')
            basic_info['owner_name'] = owner.get('name', 'Unknown')
        
        return basic_info
    
    # def extract_event_info(self, event: Dict[str, Any]) -> Dict[str, Any

def parse_files(file_paths: Union[str, List[str]]) -> MultiFileKubernetesResourceParser:
    """Create parser from file paths"""
    return MultiFileKubernetesResourceParser(file_paths=file_paths)
def main():
         
        print("Multi-File Kubernetes Ion Parser")
        print("=" * 50)
        files = ['pods.ion', 'services.ion', 'deployments.ion', 'events.ion']
        parser = parse_files(files)
        if parser.file_paths:
           cluster_sum =    parser.analyze_cluster_health()

           cluster_health = cluster_sum['cluster_health']
           issues = cluster_sum['issues']
           severity_counts = cluster_sum['severity_counts']

           print('health....',cluster_health)
           print('issues',issues)
           print('counts',severity_counts)



           

if __name__ == "__main__":
    main()