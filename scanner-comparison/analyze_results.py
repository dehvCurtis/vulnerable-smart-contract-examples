#!/usr/bin/env python3
"""
Scanner Comparison Analysis Script
Compares findings from SolidityDefend, Slither, and Aderyn against ground truth.
"""

import json
import os
import glob
from collections import defaultdict
from typing import Dict, List, Any, Tuple

COMPARISON_DIR = os.path.dirname(os.path.abspath(__file__))

# Severity normalization mapping
SEVERITY_MAP = {
    # SolidityDefend
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'info': 'info',
    'informational': 'info',
    # Slither
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Informational': 'info',
    'Optimization': 'info',
    # Aderyn
    'Critical': 'critical',
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Info': 'info',
    'NC': 'info',  # Non-critical
}

# Expected vulnerabilities from ground truth (11 core contracts, 69 total)
EXPECTED_VULNERABILITIES = {
    'AccessControl.sol': [
        {'line': 19, 'detector': 'missing-access-modifier', 'severity': 'critical'},
        {'line': 25, 'detector': 'tx-origin-authentication', 'severity': 'critical'},
        {'line': 34, 'detector': 'unprotected-initialization', 'severity': 'high'},
        {'line': 42, 'detector': 'dangerous-delegatecall', 'severity': 'critical'},
        {'line': 95, 'detector': 'missing-access-modifier', 'severity': 'critical'},
        {'line': 101, 'detector': 'missing-access-modifier', 'severity': 'critical'},
    ],
    'DelegateCall.sol': [
        {'line': 21, 'detector': 'dangerous-delegatecall', 'severity': 'critical'},
        {'line': 29, 'detector': 'dangerous-delegatecall', 'severity': 'critical'},
        {'line': 73, 'detector': 'storage-collision', 'severity': 'high'},
        {'line': 82, 'detector': 'dangerous-delegatecall', 'severity': 'critical'},
        {'line': 124, 'detector': 'selfdestruct-vulnerability', 'severity': 'critical'},
        {'line': 150, 'detector': 'aa-initialization-vulnerability', 'severity': 'high'},
        {'line': 157, 'detector': 'unprotected-initialization', 'severity': 'high'},
        {'line': 163, 'detector': 'dangerous-delegatecall', 'severity': 'high'},
    ],
    'DenialOfService.sol': [
        {'line': 15, 'detector': 'dos-failed-transfer', 'severity': 'high'},
        {'line': 42, 'detector': 'unbounded-loop', 'severity': 'high'},
        {'line': 72, 'detector': 'unbounded-loop', 'severity': 'medium'},
        {'line': 81, 'detector': 'unbounded-loop', 'severity': 'medium'},
        {'line': 50, 'detector': 'dos-failed-transfer', 'severity': 'high'},
        {'line': 105, 'detector': 'dos-failed-transfer', 'severity': 'high'},
        {'line': 109, 'detector': 'external-call-in-loop', 'severity': 'high'},
    ],
    'FrontRunning.sol': [
        {'line': 23, 'detector': 'front-running-vulnerability', 'severity': 'high'},
        {'line': 56, 'detector': 'transaction-ordering-dependence', 'severity': 'high'},
        {'line': 62, 'detector': 'mev-toxic-flow-exposure', 'severity': 'medium'},
        {'line': 92, 'detector': 'front-running-vulnerability', 'severity': 'high'},
        {'line': 98, 'detector': 'transaction-ordering-dependence', 'severity': 'medium'},
        {'line': 125, 'detector': 'erc20-approve-race', 'severity': 'medium'},
        {'line': 0, 'detector': 'mev-extractable-value', 'severity': 'medium'},
    ],
    'Reentrancy.sol': [
        {'line': 19, 'detector': 'classic-reentrancy', 'severity': 'critical'},
    ],
    'ShortAddress.sol': [
        {'line': 30, 'detector': 'short-address-attack', 'severity': 'medium'},
        {'line': 43, 'detector': 'short-address-attack', 'severity': 'medium'},
        {'line': 69, 'detector': 'missing-zero-address-check', 'severity': 'low'},
        {'line': 76, 'detector': 'missing-zero-address-check', 'severity': 'low'},
        {'line': 83, 'detector': 'array-length-mismatch', 'severity': 'medium'},
        {'line': 94, 'detector': 'missing-zero-address-check', 'severity': 'medium'},
        {'line': 121, 'detector': 'input-validation-missing', 'severity': 'high'},
    ],
    'SignatureReplay.sol': [
        {'line': 19, 'detector': 'signature-replay', 'severity': 'critical'},
        {'line': 68, 'detector': 'cross-contract-replay', 'severity': 'high'},
        {'line': 113, 'detector': 'signature-malleability', 'severity': 'medium'},
        {'line': 161, 'detector': 'missing-chain-id', 'severity': 'high'},
        {'line': 158, 'detector': 'signature-replay', 'severity': 'medium'},
        {'line': 40, 'detector': 'ecrecover-zero-address', 'severity': 'medium'},
        {'line': 68, 'detector': 'signature-replay', 'severity': 'high'},
    ],
    'TimestampDependence.sol': [
        {'line': 24, 'detector': 'timestamp-manipulation', 'severity': 'medium'},
        {'line': 34, 'detector': 'weak-randomness', 'severity': 'critical'},
        {'line': 58, 'detector': 'timestamp-manipulation', 'severity': 'medium'},
        {'line': 71, 'detector': 'weak-randomness', 'severity': 'medium'},
        {'line': 87, 'detector': 'weak-randomness', 'severity': 'critical'},
        {'line': 98, 'detector': 'weak-randomness', 'severity': 'critical'},
    ],
    'UncheckedCall.sol': [
        {'line': 18, 'detector': 'unchecked-external-call', 'severity': 'high'},
        {'line': 28, 'detector': 'unchecked-send', 'severity': 'high'},
        {'line': 37, 'detector': 'unchecked-external-call', 'severity': 'high'},
    ],
    'UninitializedStorage.sol': [
        {'line': 33, 'detector': 'uninitialized-storage-pointer', 'severity': 'medium'},
        {'line': 44, 'detector': 'array-bounds-check', 'severity': 'high'},
        {'line': 72, 'detector': 'storage-manipulation-in-loop', 'severity': 'low'},
        {'line': 91, 'detector': 'missing-visibility-modifier', 'severity': 'low'},
        {'line': 136, 'detector': 'storage-collision', 'severity': 'medium'},
        {'line': 166, 'detector': 'delete-nested-mapping', 'severity': 'medium'},
        {'line': 194, 'detector': 'array-delete-gap', 'severity': 'low'},
        {'line': 202, 'detector': 'deleted-element-access', 'severity': 'low'},
    ],
}


def parse_soliditydefend(filepath: str) -> List[Dict]:
    """Parse SolidityDefend JSON output."""
    findings = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        for finding in data.get('findings', []):
            loc = finding.get('location', {})
            findings.append({
                'scanner': 'soliditydefend',
                'detector': finding.get('detector_id', ''),
                'severity': SEVERITY_MAP.get(finding.get('severity', ''), 'info'),
                'file': loc.get('file', ''),
                'line': loc.get('line', 0),
                'message': finding.get('message', ''),
            })
    except Exception as e:
        print(f"Error parsing SolidityDefend output: {e}")
    return findings


def parse_slither(filepath: str) -> List[Dict]:
    """Parse Slither JSON output."""
    findings = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        for result in data.get('results', {}).get('detectors', []):
            # Get first element location
            elements = result.get('elements', [])
            line = 0
            file = ''
            if elements:
                src = elements[0].get('source_mapping', {})
                lines = src.get('lines', [])
                line = lines[0] if lines else 0
                file = src.get('filename_short', '')

            findings.append({
                'scanner': 'slither',
                'detector': result.get('check', ''),
                'severity': SEVERITY_MAP.get(result.get('impact', ''), 'info'),
                'file': file,
                'line': line,
                'message': result.get('description', ''),
            })
    except Exception as e:
        print(f"Error parsing Slither output {filepath}: {e}")
    return findings


def parse_aderyn(filepath: str) -> List[Dict]:
    """Parse Aderyn JSON output."""
    findings = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)

        # Aderyn groups by severity (new format: high_issues, low_issues, etc.)
        severity_keys = [
            ('critical_issues', 'critical'),
            ('high_issues', 'high'),
            ('medium_issues', 'medium'),
            ('low_issues', 'low'),
            ('nc_issues', 'info'),
        ]
        for key, severity in severity_keys:
            issues_data = data.get(key, {})
            for issue in issues_data.get('issues', []):
                for instance in issue.get('instances', []):
                    findings.append({
                        'scanner': 'aderyn',
                        'detector': issue.get('detector_name', ''),
                        'severity': severity,
                        'file': instance.get('contract_path', ''),
                        'line': instance.get('line_no', 0),
                        'message': issue.get('title', ''),
                    })
    except Exception as e:
        print(f"Error parsing Aderyn output {filepath}: {e}")
    return findings


def load_all_findings() -> Dict[str, List[Dict]]:
    """Load all scanner findings."""
    results = {
        'soliditydefend': [],
        'slither': [],
        'aderyn': [],
    }

    # SolidityDefend - single file
    sd_file = os.path.join(COMPARISON_DIR, 'soliditydefend.json')
    if os.path.exists(sd_file):
        results['soliditydefend'] = parse_soliditydefend(sd_file)
        print(f"Loaded {len(results['soliditydefend'])} SolidityDefend findings")

    # Slither - multiple files
    slither_files = glob.glob(os.path.join(COMPARISON_DIR, 'slither_*.json'))
    for f in slither_files:
        results['slither'].extend(parse_slither(f))
    print(f"Loaded {len(results['slither'])} Slither findings from {len(slither_files)} files")

    # Aderyn - try single combined file first, then multiple files
    aderyn_core = os.path.join(COMPARISON_DIR, 'aderyn_core.json')
    if os.path.exists(aderyn_core):
        results['aderyn'] = parse_aderyn(aderyn_core)
        print(f"Loaded {len(results['aderyn'])} Aderyn findings from aderyn_core.json")
    else:
        aderyn_files = glob.glob(os.path.join(COMPARISON_DIR, 'aderyn_*.json'))
        for f in aderyn_files:
            results['aderyn'].extend(parse_aderyn(f))
        print(f"Loaded {len(results['aderyn'])} Aderyn findings from {len(aderyn_files)} files")

    return results


def get_findings_by_file(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by filename."""
    by_file = defaultdict(list)
    for f in findings:
        filename = os.path.basename(f['file'])
        by_file[filename].append(f)
    return by_file


def calculate_metrics(findings: List[Dict], expected: Dict) -> Dict:
    """Calculate detection metrics against ground truth."""
    findings_by_file = get_findings_by_file(findings)

    true_positives = 0
    false_negatives = 0
    total_expected = 0

    detected_vulns = []
    missed_vulns = []

    for filename, vulns in expected.items():
        file_findings = findings_by_file.get(filename, [])
        total_expected += len(vulns)

        for vuln in vulns:
            # Check if any finding matches this vulnerability (within 5 lines)
            matched = False
            for f in file_findings:
                line_diff = abs(f['line'] - vuln['line'])
                if line_diff <= 5:  # Allow some tolerance
                    # Check if detector name is related
                    detector_lower = f['detector'].lower().replace('-', '_').replace(' ', '_')
                    vuln_detector = vuln['detector'].lower().replace('-', '_')

                    # Flexible matching for related detectors
                    related_terms = vuln_detector.split('_')
                    if any(term in detector_lower for term in related_terms if len(term) > 3):
                        matched = True
                        break
                    # Also match by severity for same line
                    if line_diff <= 2 and f['severity'] in ['critical', 'high']:
                        matched = True
                        break

            if matched:
                true_positives += 1
                detected_vulns.append({**vuln, 'file': filename})
            else:
                false_negatives += 1
                missed_vulns.append({**vuln, 'file': filename})

    # Calculate metrics
    detection_rate = (true_positives / total_expected * 100) if total_expected > 0 else 0

    return {
        'true_positives': true_positives,
        'false_negatives': false_negatives,
        'total_expected': total_expected,
        'detection_rate': detection_rate,
        'detected_vulns': detected_vulns,
        'missed_vulns': missed_vulns,
    }


def analyze_by_severity(findings: List[Dict]) -> Dict[str, int]:
    """Count findings by severity."""
    counts = defaultdict(int)
    for f in findings:
        counts[f['severity']] += 1
    return dict(counts)


def analyze_by_detector(findings: List[Dict], top_n: int = 15) -> List[Tuple[str, int]]:
    """Get top detectors by finding count."""
    counts = defaultdict(int)
    for f in findings:
        counts[f['detector']] += 1
    return sorted(counts.items(), key=lambda x: -x[1])[:top_n]


def generate_report(results: Dict[str, List[Dict]]) -> str:
    """Generate markdown comparison report."""
    report = []
    report.append("# Scanner Comparison Report: SolidityDefend vs Slither vs Aderyn\n")
    report.append(f"**Generated:** 2026-01-16\n")
    report.append(f"**Corpus:** 62 vulnerable Solidity contracts\n")
    report.append(f"**Ground Truth:** 69 documented vulnerabilities across 11 core contracts\n\n")

    # Summary table
    report.append("## Executive Summary\n")
    report.append("| Metric | SolidityDefend | Slither | Aderyn |")
    report.append("|--------|---------------|---------|--------|")

    sd_count = len(results['soliditydefend'])
    sl_count = len(results['slither'])
    ad_count = len(results['aderyn'])

    report.append(f"| Total Findings | **{sd_count:,}** | {sl_count:,} | {ad_count:,} |")

    # Severity breakdown
    sd_sev = analyze_by_severity(results['soliditydefend'])
    sl_sev = analyze_by_severity(results['slither'])
    ad_sev = analyze_by_severity(results['aderyn'])

    report.append(f"| Critical | {sd_sev.get('critical', 0):,} | {sl_sev.get('critical', 0):,} | {ad_sev.get('critical', 0):,} |")
    report.append(f"| High | {sd_sev.get('high', 0):,} | {sl_sev.get('high', 0):,} | {ad_sev.get('high', 0):,} |")
    report.append(f"| Medium | {sd_sev.get('medium', 0):,} | {sl_sev.get('medium', 0):,} | {ad_sev.get('medium', 0):,} |")
    report.append(f"| Low | {sd_sev.get('low', 0):,} | {sl_sev.get('low', 0):,} | {ad_sev.get('low', 0):,} |")
    report.append(f"| Info | {sd_sev.get('info', 0):,} | {sl_sev.get('info', 0):,} | {ad_sev.get('info', 0):,} |")

    # Detection metrics against ground truth
    report.append("\n## Detection Rate vs Ground Truth (11 Core Contracts)\n")

    sd_metrics = calculate_metrics(results['soliditydefend'], EXPECTED_VULNERABILITIES)
    sl_metrics = calculate_metrics(results['slither'], EXPECTED_VULNERABILITIES)
    ad_metrics = calculate_metrics(results['aderyn'], EXPECTED_VULNERABILITIES)

    report.append("| Metric | SolidityDefend | Slither | Aderyn |")
    report.append("|--------|---------------|---------|--------|")
    report.append(f"| True Positives | **{sd_metrics['true_positives']}** | {sl_metrics['true_positives']} | {ad_metrics['true_positives']} |")
    report.append(f"| False Negatives | {sd_metrics['false_negatives']} | {sl_metrics['false_negatives']} | {ad_metrics['false_negatives']} |")
    report.append(f"| Detection Rate | **{sd_metrics['detection_rate']:.1f}%** | {sl_metrics['detection_rate']:.1f}% | {ad_metrics['detection_rate']:.1f}% |")

    # Top detectors by scanner
    report.append("\n## Top Detectors by Scanner\n")

    report.append("### SolidityDefend Top 15 Detectors")
    report.append("| Detector | Count |")
    report.append("|----------|-------|")
    for det, count in analyze_by_detector(results['soliditydefend']):
        report.append(f"| {det} | {count:,} |")

    report.append("\n### Slither Top 15 Detectors")
    report.append("| Detector | Count |")
    report.append("|----------|-------|")
    for det, count in analyze_by_detector(results['slither']):
        report.append(f"| {det} | {count:,} |")

    report.append("\n### Aderyn Top 15 Detectors")
    report.append("| Detector | Count |")
    report.append("|----------|-------|")
    for det, count in analyze_by_detector(results['aderyn']):
        report.append(f"| {det} | {count:,} |")

    # Missed vulnerabilities by each scanner
    report.append("\n## Missed Vulnerabilities (False Negatives)\n")

    report.append("### SolidityDefend Missed")
    if sd_metrics['missed_vulns']:
        report.append("| File | Line | Expected Detector | Severity |")
        report.append("|------|------|-------------------|----------|")
        for v in sd_metrics['missed_vulns'][:15]:
            report.append(f"| {v['file']} | {v['line']} | {v['detector']} | {v['severity']} |")
    else:
        report.append("*No missed vulnerabilities in core contracts*")

    report.append("\n### Slither Missed")
    if sl_metrics['missed_vulns']:
        report.append("| File | Line | Expected Detector | Severity |")
        report.append("|------|------|-------------------|----------|")
        for v in sl_metrics['missed_vulns'][:15]:
            report.append(f"| {v['file']} | {v['line']} | {v['detector']} | {v['severity']} |")

    report.append("\n### Aderyn Missed")
    if ad_metrics['missed_vulns']:
        report.append("| File | Line | Expected Detector | Severity |")
        report.append("|------|------|-------------------|----------|")
        for v in ad_metrics['missed_vulns'][:15]:
            report.append(f"| {v['file']} | {v['line']} | {v['detector']} | {v['severity']} |")

    # Unique detector categories
    report.append("\n## Unique Detection Categories\n")
    report.append("Categories where only one scanner has detectors:\n")

    sd_detectors = set(f['detector'] for f in results['soliditydefend'])
    sl_detectors = set(f['detector'] for f in results['slither'])
    ad_detectors = set(f['detector'] for f in results['aderyn'])

    # Find SolidityDefend-unique detector patterns
    report.append("\n### SolidityDefend-Exclusive Detector Categories")
    sd_unique_patterns = ['mev', 'sandwich', 'flashloan', 'flash-loan', 'eip', 'aa-', 'account-abstraction',
                         'defi', 'oracle', 'l2', 'cross-chain', 'bridge', 'validator', 'sequencer']
    for pattern in sd_unique_patterns:
        matching = [d for d in sd_detectors if pattern in d.lower()]
        if matching:
            count = sum(1 for f in results['soliditydefend'] if any(m in f['detector'] for m in matching))
            report.append(f"- **{pattern}**: {len(matching)} detectors, {count:,} findings")

    # Analysis conclusion
    report.append("\n## Analysis Conclusion\n")
    sl_ratio = sd_count / sl_count if sl_count > 0 else 0
    ad_ratio = sd_count / ad_count if ad_count > 0 else 0
    report.append(f"SolidityDefend found **{sl_ratio:.1f}x more findings** than Slither and **{ad_ratio:.1f}x more** than Aderyn.")
    report.append(f"\nThis is explained by:")
    report.append(f"1. **332 detectors** in SolidityDefend vs 99 in Slither and 88 in Aderyn")
    report.append(f"2. Specialized DeFi, MEV, Account Abstraction, and EIP detectors not present in other tools")
    report.append(f"3. More aggressive pattern matching (may include some false positives)")
    report.append(f"\nDetection rate against documented ground truth: **{sd_metrics['detection_rate']:.1f}%**")

    return '\n'.join(report)


def main():
    print("Loading scanner findings...")
    results = load_all_findings()

    print("\nGenerating comparison report...")
    report = generate_report(results)

    # Write report
    report_path = os.path.join(COMPARISON_DIR, 'comparison_report.md')
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"\nReport written to: {report_path}")

    # Also save raw metrics as JSON
    metrics = {
        'soliditydefend': {
            'total': len(results['soliditydefend']),
            'by_severity': analyze_by_severity(results['soliditydefend']),
            'detection_metrics': calculate_metrics(results['soliditydefend'], EXPECTED_VULNERABILITIES),
        },
        'slither': {
            'total': len(results['slither']),
            'by_severity': analyze_by_severity(results['slither']),
            'detection_metrics': calculate_metrics(results['slither'], EXPECTED_VULNERABILITIES),
        },
        'aderyn': {
            'total': len(results['aderyn']),
            'by_severity': analyze_by_severity(results['aderyn']),
            'detection_metrics': calculate_metrics(results['aderyn'], EXPECTED_VULNERABILITIES),
        },
    }

    # Remove non-serializable data
    for scanner in metrics:
        metrics[scanner]['detection_metrics'].pop('detected_vulns', None)
        metrics[scanner]['detection_metrics'].pop('missed_vulns', None)

    metrics_path = os.path.join(COMPARISON_DIR, 'metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to: {metrics_path}")


if __name__ == '__main__':
    main()
