#!/usr/bin/env python3

import os
import argparse
import json
import time
from datetime import datetime
from main import run_log_analysis
from utils.visualization import visualize_results

def create_demo_logs():
    """Create demo log files for different attack scenarios"""
    demo_dir = "demo_logs"
    if not os.path.exists(demo_dir):
        os.makedirs(demo_dir)

    # Define demo scenarios with sample log data
    scenarios = {
        "lateral_movement": {
            "query": "Can you identify any lateral movement or host discovery activities in the logs?",
            "logs": [
                {
                    "timestamp": "2024-03-15T10:34:56Z",
                    "event": {"type": "ProcessRollup2"},
                    "process": {
                        "name": "cmd.exe",
                        "command_line": "cmd.exe /c net use \\\\10.1.1.12\\admin$ /user:domain\\admin password123",
                        "pid": 1234
                    },
                    "user": {"username": "jsmith"}
                },
                {
                    "timestamp": "2024-03-15T10:35:10Z",
                    "event": {"type": "NetworkConnectionIP4"},
                    "process": {"name": "cmd.exe", "pid": 1234},
                    "network": {
                        "direction": "outbound",
                        "protocol": "tcp",
                        "local_ip": "10.1.1.5",
                        "local_port": 49321,
                        "remote_ip": "10.1.1.12",
                        "remote_port": 445
                    }
                }
            ]
        },
        "credential_theft": {
            "query": "Check if there are any credential theft attempts in the logs",
            "logs": [
                {
                    "timestamp": "2024-03-15T11:22:15Z",
                    "event": {"type": "ProcessRollup2"},
                    "process": {
                        "name": "rundll32.exe",
                        "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
                        "pid": 2345
                    },
                    "user": {"username": "jsmith"}
                },
                {
                    "timestamp": "2024-03-15T11:22:18Z",
                    "event": {"type": "FileWritten"},
                    "file": {
                        "path": "C:\\temp\\lsass.dmp",
                        "size": 45678912
                    },
                    "process": {"name": "rundll32.exe", "pid": 2345}
                }
            ]
        },
        "data_exfiltration": {
            "query": "Check if there's evidence of data exfiltration in these logs",
            "logs": [
                {
                    "timestamp": "2024-03-15T12:15:30Z",
                    "event": {"type": "NetworkConnectionIP4"},
                    "process": {"name": "powershell.exe", "pid": 3456},
                    "network": {
                        "direction": "outbound",
                        "protocol": "tcp",
                        "local_ip": "10.1.1.5",
                        "local_port": 54321,
                        "remote_ip": "45.67.89.123",
                        "remote_port": 443
                    }
                },
                {
                    "timestamp": "2024-03-15T12:15:35Z",
                    "event": {"type": "FileWritten"},
                    "file": {
                        "path": "C:\\temp\\data.zip",
                        "size": 1024000
                    },
                    "process": {"name": "powershell.exe", "pid": 3456}
                }
            ]
        }
    }

    # Write each scenario to a separate file
    for scenario, data in scenarios.items():
        file_path = os.path.join(demo_dir, f"{scenario}.json")
        with open(file_path, 'w') as f:
            for log in data["logs"]:
                f.write(f"{json.dumps(log)}\n")

    return scenarios

def run_demo(scenario=None):
    """Run a demonstration of the CrowdStrike Falcon anomaly detection system"""

    # Create demo logs if they don't exist
    scenarios = create_demo_logs()

    # Use specified scenario or ask user to choose one
    if not scenario or scenario not in scenarios:
        print("\nAvailable demo scenarios:")
        for i, (key, value) in enumerate(scenarios.items(), 1):
            print(f"{i}. {key.replace('_', ' ').title()}: {value['query']}")
        print(f"{len(scenarios) + 1}. Custom Query")

        choice = input("\nSelect a scenario number: ")
        try:
            if int(choice) == len(scenarios) + 1:
                scenario = "custom"
            else:
                scenario = list(scenarios.keys())[int(choice) - 1]
        except (ValueError, IndexError):
            print("Invalid choice. Using 'lateral_movement' scenario.")
            scenario = "lateral_movement"

    # Get the selected scenario
    if scenario == "custom":
        query = input("Enter your custom security investigation query: ")
        log_file = input("Enter path to your CrowdStrike Falcon log file: ")
        selected = {"query": query, "log_file": log_file}
    else:
        selected = {
            "query": scenarios[scenario]["query"],
            "log_file": f"demo_logs/{scenario}.json"
        }

    print("\n" + "="*80)
    print(f"DEMO: CrowdStrike Falcon Anomaly Detection")
    print("="*80)
    print(f"\nInvestigation Request: {selected['query']}")
    print(f"Analyzing log file: {selected['log_file']}")
    print("\nStarting multi-agent analysis...\n")

    # Run the analysis
    start_time = time.time()
    result = run_log_analysis(selected['query'], selected['log_file'])
    end_time = time.time()

    # Display results
    print("\n" + "="*80)
    print("RESULTS")
    print("="*80)

    print(f"\nAnalysis completed in {end_time - start_time:.2f} seconds\n")

    print(f"ANALYSIS PLAN:")
    print(f"{result['plan']}\n")

    print("SPECIALIST FINDINGS:")
    for i in range(1, 6):
        worker_key = f"worker{i}_output"
        if worker_key in result:
            role = result[worker_key]['role']
            print(f"\n{i}. {role} Analysis:")
            print("-" * (len(role) + 11))
            print(f"{result[worker_key]['analysis']}\n")

    print("\n" + "="*80)
    print("VOTING-BASED CONSENSUS")
    print("="*80)
    print(f"\n{result['critique_output']['assessment']}\n")

    print("\n" + "="*80)
    print("FINAL VERDICT & REMEDIATION")
    print("="*80)
    print(f"\n{result['final_judgment']['evaluation']}")

    # Create visualization
    print("\nGenerating visualizations...")
    try:
        viz_files = visualize_results(result, selected['query'])
        print("\nVisualizations saved:")
        for viz_type, file_path in viz_files.items():
            print(f"- {viz_type}: {file_path}")
    except Exception as e:
        print(f"\nError generating visualizations: {e}")
        print("Please ensure matplotlib and networkx are installed:")
        print("pip install matplotlib networkx")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CrowdStrike Falcon Anomaly Detection Demo")
    parser.add_argument("--scenario", type=str, help="Demo scenario to run")
    args = parser.parse_args()

    run_demo(args.scenario)
