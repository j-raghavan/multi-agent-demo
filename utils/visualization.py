#!/usr/bin/env python3

import os
import re
import json
from datetime import datetime
import matplotlib.pyplot as plt
import networkx as nx
from typing import Dict, List, Any, Tuple
import numpy as np

def extract_events_timeline(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract timeline events from worker analyses"""
    events = []
    
    # Process each worker's analysis
    for i in range(1, 6):
        worker_key = f"worker{i}_output"
        if worker_key in result:
            analysis = result[worker_key]['analysis']
            role = result[worker_key]['role']
            
            # Look for timestamps in the analysis
            timestamp_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
            matches = re.findall(timestamp_pattern, analysis)
            
            for ts in matches:
                # Extract surrounding context (50 chars before and after)
                idx = analysis.find(ts)
                start = max(0, idx - 50)
                end = min(len(analysis), idx + 50)
                context = analysis[start:end].strip()
                
                # Create an event
                events.append({
                    'timestamp': ts,
                    'description': context,
                    'source': role,
                    'datetime': datetime.fromisoformat(ts.replace('Z', '+00:00'))
                })
    
    # Sort events by timestamp
    events.sort(key=lambda x: x['datetime'])
    return events

def create_attack_graph(events: List[Dict[str, Any]], query: str) -> str:
    """Create a directed graph visualization of the attack path"""
    plt.figure(figsize=(12, 8))
    
    G = nx.DiGraph()
    
    # Add nodes and edges
    prev_node = "Initial Access"
    G.add_node(prev_node, color='lightgreen')
    
    for i, event in enumerate(events[:10]):  # Limit to 10 events for readability
        node_name = f"{event['timestamp']}: {event['description'][:30]}..."
        G.add_node(node_name, color='lightblue')
        G.add_edge(prev_node, node_name)
        prev_node = node_name
    
    # Draw the graph
    pos = nx.spring_layout(G, k=1, iterations=50)
    
    # Draw nodes with different colors
    node_colors = [G.nodes[node].get('color', 'lightblue') for node in G.nodes()]
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=3000)
    
    # Draw edges and labels
    nx.draw_networkx_edges(G, pos, arrows=True, arrowsize=15, edge_color='gray')
    nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold')
    
    plt.title(f"Attack Path Visualization: {query}")
    plt.axis('off')
    plt.tight_layout()
    
    # Save the graph
    output_path = "output/attack_graph.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path

def create_confidence_chart(critique: str) -> str:
    """Create a bar chart of confidence levels"""
    plt.figure(figsize=(10, 6))
    
    # Extract confidence levels
    high_confidence = len(re.findall(r'HIGH CONFIDENCE', critique, re.IGNORECASE))
    medium_confidence = len(re.findall(r'MEDIUM CONFIDENCE', critique, re.IGNORECASE))
    low_confidence = len(re.findall(r'LOW CONFIDENCE', critique, re.IGNORECASE))
    
    # Create bar chart
    confidence_levels = ['High', 'Medium', 'Low']
    confidence_counts = [high_confidence, medium_confidence, low_confidence]
    colors = ['#2ecc71', '#f1c40f', '#e74c3c']  # Green, Yellow, Red
    
    bars = plt.bar(confidence_levels, confidence_counts, color=colors)
    
    # Add value labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom')
    
    plt.title('Finding Confidence Levels (After Voting)')
    plt.xlabel('Confidence Level')
    plt.ylabel('Number of Findings')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Save the chart
    output_path = "output/confidence_levels.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path

def create_specialist_chart(result: Dict[str, Any]) -> str:
    """Create a pie chart of specialist contributions"""
    plt.figure(figsize=(10, 8))
    
    # Count how many findings each specialist contributed
    specialist_contributions = {}
    
    for i in range(1, 6):
        worker_key = f"worker{i}_output"
        if worker_key in result:
            role = result[worker_key]['role']
            # Count paragraphs as rough proxy for findings
            paragraphs = len(result[worker_key]['analysis'].split('\n\n'))
            specialist_contributions[role] = paragraphs
    
    # Create pie chart
    labels = list(specialist_contributions.keys())
    sizes = list(specialist_contributions.values())
    
    # Calculate explode values to highlight key areas
    explode = [0.1 if any(key in l for key in ["Lateral Movement", "Initial Access", "Credential"]) 
              else 0 for l in labels]
    
    # Use a color palette
    colors = plt.cm.Pastel1(np.linspace(0, 1, len(labels)))
    
    plt.pie(sizes, explode=explode, labels=labels, colors=colors,
            autopct='%1.1f%%', shadow=True, startangle=90)
    plt.axis('equal')
    plt.title('Specialist Contribution to Investigation')
    
    # Save the chart
    output_path = "output/specialist_contributions.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return output_path

def visualize_results(result: Dict[str, Any], query: str) -> Dict[str, str]:
    """Generate visualizations based on analysis results"""
    # Create output directory if it doesn't exist
    if not os.path.exists("output"):
        os.makedirs("output")
    
    try:
        # 1. Create attack graph visualization
        events = extract_events_timeline(result)
        attack_graph_path = create_attack_graph(events, query)
        
        # 2. Create confidence visualization
        critique = result.get('critique_output', {}).get('assessment', '')
        confidence_chart_path = create_confidence_chart(critique)
        
        # 3. Create specialist contribution visualization
        specialist_chart_path = create_specialist_chart(result)
        
        return {
            "attack_graph": attack_graph_path,
            "confidence_levels": confidence_chart_path,
            "specialist_contributions": specialist_chart_path
        }
        
    except Exception as e:
        print(f"Error in visualization: {str(e)}")
        raise

if __name__ == "__main__":
    # Test visualization with sample data
    sample_result = {
        "worker1_output": {
            "role": "Lateral Movement Specialist",
            "analysis": "Found evidence at 2024-03-15T10:34:56Z: Suspicious network connection"
        },
        "worker2_output": {
            "role": "Credential Access Specialist",
            "analysis": "Detected at 2024-03-15T10:35:10Z: Possible credential access"
        },
        "critique_output": {
            "assessment": "HIGH CONFIDENCE: Lateral movement detected\nMEDIUM CONFIDENCE: Credential access attempt"
        }
    }
    
    visualize_results(sample_result, "Test Query") 