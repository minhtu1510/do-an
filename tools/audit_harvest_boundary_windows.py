"""Inspect the 16 harvest attack windows lacking in-interval event evidence."""
import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from extract_opcua_features_ext import load_episodes

root=Path('experiments/opcua_research_v2/train_ood2_label_audit')
with (root/'harvest_findings.csv').open() as f:
    findings=list(csv.DictReader(f))
intervals={ep:(s,e) for s,e,lab,ep in load_episodes('test_results/day8/timeline_harvest.csv')}
clauses=['(frame.time_epoch >= %.3f && frame.time_epoch < %.3f)' %
         (int(r['window_start_ms'])/1000,int(r['window_end_ms'])/1000) for r in findings]
cmd=['tshark','-r','data_opc/day8_out/harvest_ot1786331948_merged.pcap',
     '-Y','tcp.port == 4840 && ip.addr == 192.168.210.211 && ip.addr == 192.168.210.32 && ('+' || '.join(clauses)+')',
     '-T','fields','-e','frame.time_epoch','-e','frame.number','-e','ip.src','-e','tcp.len','-e','tcp.flags.syn']
p=subprocess.run(cmd,capture_output=True,text=True,check=True)
packets=[]
for line in p.stdout.splitlines():
    t,n,src,length,syn=line.split('\t')
    packets.append((int(float(t)*1000),int(n),src,int(length or 0),syn))
results=[]
for r in findings:
    ws,we=int(r['window_start_ms']),int(r['window_end_ms'])
    s,e=intervals[r['stored_episode']]
    group=[p for p in packets if ws<=p[0]<we]
    counts=Counter()
    for ms,n,src,length,syn in group:
        region='inside_episode' if s<=ms<e else 'outside_episode'
        direction='attacker' if src=='192.168.210.32' else 'plc_reply'
        kind='payload' if length else 'syn' if syn in ('True','1') else 'control_no_payload'
        counts[f'{region}_{direction}_{kind}']+=1
    results.append(dict(window_start_ms=ws,label=r['stored_label'],episode=r['stored_episode'],
                        episode_start_ms=s,episode_end_ms=e,counts=dict(counts),frames=[p[1] for p in group]))
(root/'harvest_boundary_details.json').write_text(json.dumps(results,indent=2)+'\n')
for r in results:
    print(r['window_start_ms'],r['label'],r['counts'])
