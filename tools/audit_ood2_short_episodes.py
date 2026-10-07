"""Audit OOD2 episode evidence without changing labels or model artifacts."""
import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from extract_opcua_features_ext import load_episodes, episode_for


def main():
    timeline = 'test_results/day8/timeline_ood2.csv'
    dataset = 'data_opc/day8_out/opcua_ood2_ext_aa.csv'
    pcap = 'data_opc/day8_out/ood2_merged.pcap'
    with open(dataset, newline='') as handle:
        rows = list(csv.DictReader(handle))
    intervals = load_episodes(timeline)
    selected = Counter()
    for row in rows:
        match = episode_for(int(row['window_start_ms']), int(row['window_end_ms']), intervals)
        if match:
            selected[match[1]] += 1
    fields = ['frame.time_epoch', 'frame.number', 'ip.src', 'ip.dst',
              'tcp.srcport', 'tcp.dstport', 'tcp.len',
              'opcua.servicenodeid.numeric', 'opcua.ServiceResult', 'opcua.StatusCode',
              'opcua.Results']
    command = ['tshark', '-r', pcap, '-o', 'tcp.desegment_tcp_streams:TRUE',
               '-Y', 'ip.addr == 192.168.210.32', '-T', 'fields']
    for field in fields:
        command.extend(['-e', field])
    proc = subprocess.run(command, check=True, capture_output=True, text=True)
    packets = []
    for line in proc.stdout.splitlines():
        values = line.split('\t')
        packet = dict(zip(fields, values))
        packet['ms'] = int(float(packet['frame.time_epoch']) * 1000)
        packets.append(packet)
    results = []
    for start, end, label, episode in intervals:
        if label.upper().startswith('BENIGN') or selected[episode]:
            continue
        exact = [p for p in packets if start <= p['ms'] < end]
        scope = [p for p in exact if '192.168.210.211' in (p['ip.src'], p['ip.dst'])
                 and '4840' in (p['tcp.srcport'], p['tcp.dstport'])]
        relevant_rows = [r for r in rows if int(r['window_start_ms']) < end
                         and int(r['window_end_ms']) > start]
        results.append({
            'episode': episode, 'label': label, 'duration_ms': end-start,
            'attacker_related_packets_in_interval': len(exact),
            'pipeline_scope_packets_in_interval': len(scope),
            'attacker_originated_scope_payload_packets': sum(
                p['ip.src'] == '192.168.210.32' and int(p['tcp.len'] or 0) > 0 for p in scope),
            'service_ids': dict(Counter(p['opcua.servicenodeid.numeric'] for p in scope
                                       if p['opcua.servicenodeid.numeric'])),
            'service_results': dict(Counter(p['opcua.ServiceResult'] for p in scope
                                           if p['opcua.ServiceResult'])),
            'status_codes': dict(Counter(p['opcua.StatusCode'] for p in scope
                                        if p['opcua.StatusCode'])),
            'write_response_results': dict(Counter(p['opcua.Results'] for p in scope
                if '676' in p['opcua.servicenodeid.numeric'].split(',') and p['opcua.Results'])),
            'packet_numbers': [int(p['frame.number']) for p in scope],
            'overlapping_csv_windows': [
                {'start_ms': r['window_start_ms'], 'label': r['label'],
                 'episode_id': r['episode_id']} for r in relevant_rows],
        })
    report = {
        'pcap': pcap, 'timeline': timeline, 'dataset': dataset,
        'interval_rule': 'start <= packet timestamp truncated to ms < end',
        'scope': 'TCP 4840 involving PLC 192.168.210.211 and attacker 192.168.210.32',
        'missing_episodes': results,
        'limitation': 'Packet presence and service decoding do not establish intent or successful process impact. ServiceResult is not a substitute for per-node WriteResponse results.',
    }
    output = Path('experiments/opcua_research_v2/ood2_short_episode_audit.json')
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    for r in results:
        print(r['episode'], 'scope_packets=', r['pipeline_scope_packets_in_interval'],
              'payload_from_attacker=', r['attacker_originated_scope_payload_packets'],
              'services=', r['service_ids'], 'results=', r['service_results'],
              'statuses=', r['status_codes'],
              'write_results=', r['write_response_results'],
              'csv_labels=', [w['label'] for w in r['overlapping_csv_windows']])
    print('Report:', output)


if __name__ == '__main__':
    main()
