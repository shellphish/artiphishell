#!/usr/bin/env python3
"""
Database utility functions for Permanence Service.
Use for maintenance and retrieving information from the database.
"""

import os
import sqlite3
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# Default DB path
DB_PATH = os.environ.get("PERMANENCE_DB_PATH", "permanence.db")

def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Get a connection to the database"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def list_projects() -> List[str]:
    """List all projects in the database"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT DISTINCT project_name FROM indexed_functions")
    projects = [row['project_name'] for row in cursor.fetchall()]
    
    conn.close()
    return projects

def list_harnesses(project_name: str) -> List[str]:
    """List all harnesses for a project"""
    conn = get_connection()
    cursor = conn.cursor()
    
    harnesses = set()
    
    # Check all tables that have harness_name
    tables = [
        "grammar_reached_functions",
        "seed_reached_functions",
        "deduplicated_pov_reports",
        "poi_reports",
        "patch_attempts"
    ]
    
    for table in tables:
        cursor.execute(f"SELECT DISTINCT harness_name FROM {table} WHERE project_name = ?", (project_name,))
        harnesses.update(row['harness_name'] for row in cursor.fetchall())
    
    conn.close()
    return sorted(list(harnesses))

def get_project_stats(project_name: str) -> Dict[str, Any]:
    """Get statistics for a project"""
    conn = get_connection()
    cursor = conn.cursor()
    
    stats = {
        "project_name": project_name,
        "functions_count": 0,
        "harnesses": {},
        "creation_time": None,
        "last_updated": None
    }
    
    # Get function count
    cursor.execute(
        "SELECT COUNT(*) as count FROM indexed_functions WHERE project_name = ?", 
        (project_name,)
    )
    stats["functions_count"] = cursor.fetchone()['count']
    
    # Get harnesses
    harnesses = list_harnesses(project_name)
    
    for harness_name in harnesses:
        harness_stats = {
            "grammar_count": 0,
            "seed_count": 0,
            "pov_report_count": 0,
            "poi_report_count": 0,
            "successful_patches": 0,
            "unsuccessful_patches": 0
        }
        
        # Get grammar count
        cursor.execute(
            "SELECT COUNT(*) as count FROM grammar_reached_functions WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        harness_stats["grammar_count"] = cursor.fetchone()['count']
        
        # Get seed count
        cursor.execute(
            "SELECT COUNT(*) as count FROM seed_reached_functions WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        harness_stats["seed_count"] = cursor.fetchone()['count']
        
        # Get POV report count
        cursor.execute(
            "SELECT COUNT(*) as count FROM deduplicated_pov_reports WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        harness_stats["pov_report_count"] = cursor.fetchone()['count']
        
        # Get POI report count
        cursor.execute(
            "SELECT COUNT(*) as count FROM poi_reports WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        harness_stats["poi_report_count"] = cursor.fetchone()['count']
        
        # Get successful patches count
        cursor.execute(
            "SELECT COUNT(*) as count FROM patch_attempts WHERE project_name = ? AND harness_name = ? AND successful = 1", 
            (project_name, harness_name)
        )
        harness_stats["successful_patches"] = cursor.fetchone()['count']
        
        # Get unsuccessful patches count
        cursor.execute(
            "SELECT COUNT(*) as count FROM patch_attempts WHERE project_name = ? AND harness_name = ? AND successful = 0", 
            (project_name, harness_name)
        )
        harness_stats["unsuccessful_patches"] = cursor.fetchone()['count']
        
        stats["harnesses"][harness_name] = harness_stats
    
    # Get creation time
    cursor.execute(
        """
        SELECT MIN(timestamp) as first_ts FROM (
            SELECT MIN(timestamp) as timestamp FROM indexed_functions WHERE project_name = ?
            UNION ALL
            SELECT MIN(timestamp) as timestamp FROM grammar_reached_functions WHERE project_name = ?
            UNION ALL
            SELECT MIN(timestamp) as timestamp FROM seed_reached_functions WHERE project_name = ?
        )
        """,
        (project_name, project_name, project_name)
    )
    result = cursor.fetchone()
    if result and result['first_ts']:
        stats["creation_time"] = result['first_ts']
    
    # Get last updated time
    cursor.execute(
        """
        SELECT MAX(timestamp) as last_ts FROM (
            SELECT MAX(timestamp) as timestamp FROM indexed_functions WHERE project_name = ?
            UNION ALL
            SELECT MAX(timestamp) as timestamp FROM grammar_reached_functions WHERE project_name = ?
            UNION ALL
            SELECT MAX(timestamp) as timestamp FROM seed_reached_functions WHERE project_name = ?
            UNION ALL
            SELECT MAX(timestamp) as timestamp FROM deduplicated_pov_reports WHERE project_name = ?
            UNION ALL
            SELECT MAX(timestamp) as timestamp FROM poi_reports WHERE project_name = ?
            UNION ALL
            SELECT MAX(timestamp) as timestamp FROM patch_attempts WHERE project_name = ?
        )
        """,
        (project_name, project_name, project_name, project_name, project_name, project_name)
    )
    result = cursor.fetchone()
    if result and result['last_ts']:
        stats["last_updated"] = result['last_ts']
    
    conn.close()
    return stats

def get_function_details(project_name: str, function_key: str) -> Optional[Dict[str, Any]]:
    """Get details of a specific function"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM indexed_functions WHERE project_name = ? AND function_key = ?", 
        (project_name, function_key)
    )
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return None
    
    function_data = {
        "project_name": row['project_name'],
        "function_key": row['function_key'],
        "timestamp": row['timestamp'],
        "function_data": json.loads(row['function_data'])
    }
    
    # Get harnesses that use this function
    function_data["used_in_harnesses"] = {}
    
    # Check seed reached functions
    cursor.execute(
        """
        SELECT DISTINCT harness_name 
        FROM seed_reached_functions 
        WHERE project_name = ? AND hit_functions LIKE ?
        """, 
        (project_name, f'%"{function_key}"%')
    )
    seed_harnesses = [row['harness_name'] for row in cursor.fetchall()]
    
    # Check grammar reached functions
    cursor.execute(
        """
        SELECT DISTINCT harness_name 
        FROM grammar_reached_functions 
        WHERE project_name = ? AND hit_functions LIKE ?
        """, 
        (project_name, f'%"{function_key}"%')
    )
    grammar_harnesses = [row['harness_name'] for row in cursor.fetchall()]
    
    # Check patched functions
    cursor.execute(
        """
        SELECT DISTINCT harness_name 
        FROM patch_attempts 
        WHERE project_name = ? AND functions_attempted LIKE ?
        """, 
        (project_name, f'%"{function_key}"%')
    )
    patch_harnesses = [row['harness_name'] for row in cursor.fetchall()]
    
    # Combine all harnesses
    all_harnesses = set(seed_harnesses + grammar_harnesses + patch_harnesses)
    
    for harness in all_harnesses:
        function_data["used_in_harnesses"][harness] = {
            "reached_by_seeds": harness in seed_harnesses,
            "reached_by_grammars": harness in grammar_harnesses,
            "attempted_patch": harness in patch_harnesses
        }
    
    conn.close()
    return function_data

def get_latest_entries(limit: int = 10) -> Dict[str, List[Dict[str, Any]]]:
    """Get the latest entries of each type"""
    conn = get_connection()
    cursor = conn.cursor()
    
    latest = {
        "indexed_functions": [],
        "grammar_reached_functions": [],
        "seed_reached_functions": [],
        "deduplicated_pov_reports": [],
        "poi_reports": [],
        "patch_attempts": []
    }
    
    # Get latest indexed functions
    cursor.execute(
        "SELECT * FROM indexed_functions ORDER BY timestamp DESC LIMIT ?", 
        (limit,)
    )
    for row in cursor.fetchall():
        latest["indexed_functions"].append({
            "project_name": row['project_name'],
            "function_key": row['function_key'],
            "timestamp": row['timestamp']
        })
    
    # Get latest grammar reached functions
    cursor.execute(
        "SELECT * FROM grammar_reached_functions ORDER BY timestamp DESC LIMIT ?", 
        (limit,)
    )
    for row in cursor.fetchall():
        latest["grammar_reached_functions"].append({
            "project_name": row['project_name'],
            "harness_name": row['harness_name'],
            "grammar_type": row['grammar_type'],
            "timestamp": row['timestamp'],
            "hit_function_count": len(json.loads(row['hit_functions']))
        })
    
    # Get latest seed reached functions
    cursor.execute(
        "SELECT * FROM seed_reached_functions ORDER BY timestamp DESC LIMIT ?", 
        (limit,)
    )
    for row in cursor.fetchall():
        latest["seed_reached_functions"].append({
            "project_name": row['project_name'],
            "harness_name": row['harness_name'],
            "seed_path": row['seed_path'],
            "timestamp": row['timestamp'],
            "hit_function_count": len(json.loads(row['hit_functions']))
        })
    
    # Get latest POV reports
    cursor.execute(
        "SELECT * FROM deduplicated_pov_reports ORDER BY timestamp DESC LIMIT ?", 
        (limit,)
    )
    for row in cursor.fetchall():
        latest["deduplicated_pov_reports"].append({
            "project_name": row['project_name'],
            "harness_name": row['harness_name'],
            "report_path": row['report_path'],
            "seed_path": row['seed_path'],
            "timestamp": row['timestamp']
        })
    
    # Get latest POI reports
    cursor.execute(
        "SELECT * FROM poi_reports ORDER BY timestamp DESC LIMIT ?", 
        (limit,)
    )
    for row in cursor.fetchall():
        latest["poi_reports"].append({
            "project_name": row['project_name'],
            "harness_name": row['harness_name'],
            "report_path": row['report_path'],
            "timestamp": row['timestamp']
        })
    
    # Get latest patch attempts
    cursor.execute(
        "SELECT * FROM patch_attempts ORDER BY timestamp DESC LIMIT ?", 
        (limit,)
    )
    for row in cursor.fetchall():
        latest["patch_attempts"].append({
            "project_name": row['project_name'],
            "harness_name": row['harness_name'],
            "report_path": row['report_path'],
            "successful": bool(row['successful']),
            "timestamp": row['timestamp'],
            "function_count": len(json.loads(row['functions_attempted']))
        })
    
    conn.close()
    return latest

def export_data(project_name: str, output_file: str) -> None:
    """Export all data for a project to a JSON file"""
    conn = get_connection()
    cursor = conn.cursor()
    
    data = {
        "project_name": project_name,
        "exported_at": datetime.now().isoformat(),
        "indexed_functions": [],
        "harnesses": {}
    }
    
    # Get all functions
    cursor.execute(
        "SELECT * FROM indexed_functions WHERE project_name = ?", 
        (project_name,)
    )
    for row in cursor.fetchall():
        data["indexed_functions"].append({
            "function_key": row['function_key'],
            "function_data": json.loads(row['function_data']),
            "timestamp": row['timestamp']
        })
    
    # Get all harnesses
    harnesses = list_harnesses(project_name)
    
    for harness_name in harnesses:
        harness_data = {
            "grammar_reached_functions": [],
            "seed_reached_functions": [],
            "deduplicated_pov_reports": [],
            "poi_reports": [],
            "patch_attempts": []
        }
        
        # Get grammar reached functions
        cursor.execute(
            "SELECT * FROM grammar_reached_functions WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        for row in cursor.fetchall():
            harness_data["grammar_reached_functions"].append({
                "grammar_type": row['grammar_type'],
                "grammar": row['grammar'],
                "hit_functions": json.loads(row['hit_functions']),
                "extra": json.loads(row['extra']) if row['extra'] else None,
                "timestamp": row['timestamp']
            })
        
        # Get seed reached functions
        cursor.execute(
            "SELECT * FROM seed_reached_functions WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        for row in cursor.fetchall():
            harness_data["seed_reached_functions"].append({
                "seed_path": row['seed_path'],
                "hit_functions": json.loads(row['hit_functions']),
                "extra": json.loads(row['extra']) if row['extra'] else None,
                "timestamp": row['timestamp']
            })
        
        # Get POV reports
        cursor.execute(
            "SELECT * FROM deduplicated_pov_reports WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        for row in cursor.fetchall():
            harness_data["deduplicated_pov_reports"].append({
                "report_path": row['report_path'],
                "seed_path": row['seed_path'],
                "extra": json.loads(row['extra']) if row['extra'] else None,
                "timestamp": row['timestamp']
            })
        
        # Get POI reports
        cursor.execute(
            "SELECT * FROM poi_reports WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        for row in cursor.fetchall():
            harness_data["poi_reports"].append({
                "report_path": row['report_path'],
                "extra": json.loads(row['extra']) if row['extra'] else None,
                "timestamp": row['timestamp']
            })
        
        # Get patch attempts
        cursor.execute(
            "SELECT * FROM patch_attempts WHERE project_name = ? AND harness_name = ?", 
            (project_name, harness_name)
        )
        for row in cursor.fetchall():
            patch_data = {
                "report_path": row['report_path'],
                "functions_attempted": json.loads(row['functions_attempted']),
                "successful": bool(row['successful']),
                "timestamp": row['timestamp']
            }
            
            if row['patch_path']:
                patch_data["patch_path"] = row['patch_path']
                
            if row['reasoning']:
                patch_data["reasoning"] = row['reasoning']
                
            harness_data["patch_attempts"].append(patch_data)
        
        data["harnesses"][harness_name] = harness_data
    
    conn.close()
    
    # Write to file
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Permanence Service Database Utilities")
    parser.add_argument('--db', default=DB_PATH, help='Path to the database file')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # List projects
    list_projects_parser = subparsers.add_parser('list-projects', help='List all projects')
    
    # List harnesses
    list_harnesses_parser = subparsers.add_parser('list-harnesses', help='List all harnesses for a project')
    list_harnesses_parser.add_argument('project', help='Project name')
    
    # Project stats
    project_stats_parser = subparsers.add_parser('project-stats', help='Get statistics for a project')
    project_stats_parser.add_argument('project', help='Project name')
    
    # Function details
    function_details_parser = subparsers.add_parser('function-details', help='Get details of a specific function')
    function_details_parser.add_argument('project', help='Project name')
    function_details_parser.add_argument('function_key', help='Function key')
    
    # Latest entries
    latest_parser = subparsers.add_parser('latest', help='Get latest entries')
    latest_parser.add_argument('--limit', type=int, default=10, help='Number of entries to return')
    
    # Export data
    export_parser = subparsers.add_parser('export', help='Export all data for a project')
    export_parser.add_argument('project', help='Project name')
    export_parser.add_argument('output', help='Output file path')
    
    args = parser.parse_args()
    
    if args.command == 'list-projects':
        projects = list_projects()
        print(f"Found {len(projects)} projects:")
        for project in projects:
            print(f"- {project}")
    
    elif args.command == 'list-harnesses':
        harnesses = list_harnesses(args.project)
        print(f"Found {len(harnesses)} harnesses for project '{args.project}':")
        for harness in harnesses:
            print(f"- {harness}")
    
    elif args.command == 'project-stats':
        stats = get_project_stats(args.project)
        print(json.dumps(stats, indent=2))
    
    elif args.command == 'function-details':
        details = get_function_details(args.project, args.function_key)
        if details:
            print(json.dumps(details, indent=2))
        else:
            print(f"Function '{args.function_key}' not found in project '{args.project}'")
    
    elif args.command == 'latest':
        latest = get_latest_entries(args.limit)
        print(json.dumps(latest, indent=2))
    
    elif args.command == 'export':
        export_data(args.project, args.output)
        print(f"Exported data for project '{args.project}' to '{args.output}'")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()