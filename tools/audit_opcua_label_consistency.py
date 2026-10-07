"""Read PCAP/timeline/feature CSV; audit both label directions without relabeling."""
import csv
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from extract_opcua_features_ext import load_episodes, episode_for


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_csv(path, rows):
    if rows:
        with path.open('w', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


def audit(name, pcap, timeline, dataset, output):
    inputs = {str(p): sha(p) for p in (pcap, timeline, dataset)}
    with open(dataset, newline='') as handle:
        rows = list(csv.DictReader(handle))
    intervals = load_episodes(str(timeline))
    attacks = [e for e in intervals if not e[2].upper().startswith('BENIGN')]
    fields = ['frame.time_epoch','frame.number','frame.len','ip.src','ip.dst',
              'tcp.len','tcp.flags.syn','opcua.servicenodeid.numeric','opcua.Results']
    command = ['tshark','-r',str(pcap),'-o','tcp.desegment_tcp_streams:TRUE',
               '-Y','tcp.port == 4840 && ip.addr == 192.168.210.211','-T','fields']
    for field in fields:
        command.extend(['-e',field])
    proc = subprocess.run(command, capture_output=True,text=True,check=True)
    windows = defaultdict(lambda: [0,0,False])
    evidence = defaultdict(list)
    for line in proc.stdout.splitlines():
        values = line.split('\t')
        packet = dict(zip(fields,values))
        ms = int(float(packet['frame.time_epoch'])*1000)
        start = ms//5000*5000
        w = windows[start]
        w[0] += 1
        w[1] += int(packet['frame.len'])
        w[2] |= '192.168.210.32' in (packet['ip.src'],packet['ip.dst'])
        if packet['ip.src'] != '192.168.210.32':
            continue
        payload = int(packet['tcp.len'] or 0)>0
        syn = packet['tcp.flags.syn'] in ('1','True')
        if not payload and not syn:
            continue
        for s,e,label,episode in attacks:
            if s <= ms < e and (payload or (label=='OPCUA_SESSION_BURST' and syn)):
                evidence[(start,episode)].append(int(packet['frame.number']))
    by_window = defaultdict(dict)
    for (start,episode), numbers in evidence.items():
        by_window[start][episode] = numbers
    label_map = {e[3]:e[2] for e in attacks}
    window_rows = []
    mismatch = Counter()
    for r in rows:
        s,e = int(r['window_start_ms']),int(r['window_end_ms'])
        w = windows.get(s,[0,0,False])
        match = episode_for(s,e,intervals)
        expected = match[0] if match and w[2] else 'benign'
        for key,bad in [('label',r['label']!=expected),('packet_count',int(r['opcua_packet_count'])!=w[0]),
                        ('byte_count',int(r['opcua_byte_count'])!=w[1]),('window_length',e-s!=5000)]:
            if bad:
                mismatch[key]+=1
        labels = sorted(set(label_map[ep] for ep in by_window[s]))
        benign = r['label'].upper().startswith('BENIGN')
        reason = ('benign_with_event_evidence' if benign and labels else
                  'attack_without_in_interval_event_evidence' if not benign and not labels else
                  'attack_label_conflicts_with_event_evidence' if not benign and labels and r['label'] not in labels else '')
        window_rows.append(dict(window_start_ms=s,window_end_ms=e,stored_label=r['label'],
            stored_episode=r['episode_id'],event_labels=json.dumps(labels),
            event_frames=json.dumps(by_window[s]),finding=reason,
            majority_overlap_label=match[0] if match else '',
            attacker_related_packet_present=w[2]))
    episode_rows=[]
    for s,e,label,ep in attacks:
        ep_windows = sorted(ws for ws,episode in evidence if episode==ep)
        old = [r for r in rows if r['episode_id']==ep and not r['label'].upper().startswith('BENIGN')]
        episode_rows.append(dict(episode=ep,label=label,start_ms=s,end_ms=e,
            original_attack_windows=len(old),event_evidence_windows=len(ep_windows),
            evidence_frames=json.dumps({ws:evidence[(ws,ep)] for ws in ep_windows})))
    keys={int(r['window_start_ms']) for r in rows}
    summary=dict(name=name,n_windows=len(rows),timeline_rows=len(intervals),
        timeline_benign_rows=sum(e[2].upper().startswith('BENIGN') for e in intervals),
        timeline_attack_episodes=len(attacks),stored_labels=dict(Counter(r['label'] for r in rows)),
        mismatches=dict(mismatch),pcap_only_windows=len(set(windows)-keys),csv_only_windows=len(keys-set(windows)),
        findings=dict(Counter(r['finding'] for r in window_rows if r['finding'])),
        benign_with_event_evidence_by_label=dict(Counter(label for r in window_rows
            if r['finding']=='benign_with_event_evidence' for label in json.loads(r['event_labels']))),
        episodes_with_no_old_attack_windows=sum(r['original_attack_windows']==0 for r in episode_rows),
        episodes_with_no_event_evidence=sum(r['event_evidence_windows']==0 for r in episode_rows),
        original_sha256=inputs,source_files_unchanged=all(sha(p)==h for p,h in inputs.items()))
    write_csv(output/f'{name}_window_audit.csv',window_rows)
    write_csv(output/f'{name}_findings.csv',[r for r in window_rows if r['finding']])
    write_csv(output/f'{name}_episode_audit.csv',episode_rows)
    return summary


def main():
    output=Path('experiments/opcua_research_v2/train_ood2_label_audit')
    output.mkdir(parents=True,exist_ok=True)
    rule='Event evidence: attacker-originated payload within attack interval and PLC TCP4840 scope; SESSION_BURST also accepts SYN. No predictions are read. Evidence is traffic presence, not attack success.'
    datasets=[('harvest','harvest_ot1786331948_merged.pcap','timeline_harvest.csv','opcua_harvest_ext_aa.csv'),
              ('ood2','ood2_merged.pcap','timeline_ood2.csv','opcua_ood2_ext_aa.csv')]
    results=[]
    for name,pcap,timeline,dataset in datasets:
        result=audit(name,Path('data_opc/day8_out')/pcap,
                     Path('test_results/day8')/timeline,Path('data_opc/day8_out')/dataset,output)
        results.append(result)
        print(json.dumps(result,ensure_ascii=False,indent=2),flush=True)
    (output/'summary.json').write_text(json.dumps(dict(rule=rule,datasets=results),ensure_ascii=False,indent=2)+'\n')


if __name__=='__main__':
    main()
