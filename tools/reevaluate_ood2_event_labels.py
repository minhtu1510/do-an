"""Create a separate event-aware OOD2 label view and score a frozen model."""
import csv
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import classification_report, confusion_matrix, f1_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from extract_opcua_features_ext import load_episodes
from tools.opcua_export_predictions import normalize_label


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metrics(truth, prediction, classes):
    t = np.asarray(truth) != 'benign'
    p = np.asarray(prediction) != 'benign'
    tp, fp, tn, fn = [int(v) for v in (
        (t & p).sum(), (~t & p).sum(), (~t & ~p).sum(), (t & ~p).sum())]
    return dict(tp=tp, fp=fp, tn=tn, fn=fn,
                attack_precision=tp/(tp+fp) if tp+fp else 0,
                attack_recall=tp/(tp+fn) if tp+fn else 0,
                attack_f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0,
                fpr=fp/(fp+tn) if fp+tn else 0,
                macro_f1_union=float(f1_score(truth, prediction, average='macro', zero_division=0)),
                macro_f1_fixed_model_classes=float(f1_score(
                    truth, prediction, labels=classes, average='macro', zero_division=0)))


def main():
    root = Path('experiments/opcua_research_v2/ood2_event_aware')
    root.mkdir(parents=True, exist_ok=True)
    source = Path('data_opc/day8_out/opcua_ood2_ext_aa.csv')
    timeline = Path('test_results/day8/timeline_ood2.csv')
    pcap = Path('data_opc/day8_out/ood2_merged.pcap')
    model_path = Path('model_opcua/classifier.joblib')
    before = {str(p): digest(p) for p in (source, timeline, pcap, model_path)}
    frame = pd.read_csv(source)
    episodes = [e for e in load_episodes(str(timeline)) if not e[2].upper().startswith('BENIGN')]
    cmd = ['tshark', '-r', str(pcap), '-Y',
           'tcp.port == 4840 && ip.addr == 192.168.210.211 && ip.src == 192.168.210.32 && (tcp.len > 0 || tcp.flags.syn == 1)',
           '-T', 'fields', '-e', 'frame.time_epoch', '-e', 'frame.number',
           '-e', 'tcp.len', '-e', 'tcp.flags.syn']
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    packet_evidence = defaultdict(list)
    for line in proc.stdout.splitlines():
        timestamp, number, length, syn = line.split('\t')
        ms = int(float(timestamp)*1000)
        for start, end, label, episode in episodes:
            qualifies = int(length or 0) > 0 or (label == 'OPCUA_SESSION_BURST' and syn in ('1','True'))
            if start <= ms < end and qualifies:
                packet_evidence[(ms//5000*5000, episode)].append(int(number))
    revised = frame.copy()
    indices = {int(s): i for i, s in enumerate(frame.window_start_ms)}
    missing = set(s for s, ep in packet_evidence) - set(indices)
    if missing:
        raise ValueError(f'Evidence windows missing from dataset: {sorted(missing)}')
    label_by_episode = {e[3]: e[2] for e in episodes}
    selected_by_window = defaultdict(list)
    for start, episode in packet_evidence:
        selected_by_window[start].append(episode)
    conflicts = {str(s): ep for s, ep in selected_by_window.items()
                 if len({label_by_episode[e] for e in ep}) > 1}
    if conflicts:
        raise ValueError(f'Multiple attack labels in one window; do not choose silently: {conflicts}')
    comparison = []
    # Preserve existing labels; override only windows with independently timed
    # attacker-originated payload (or SYN for SESSION_BURST) inside an interval.
    for start, ep_list in selected_by_window.items():
        episode = sorted(ep_list)[0]
        i = indices[start]
        revised.at[i, 'label'] = label_by_episode[episode]
        revised.at[i, 'episode_id'] = episode
    features = json.loads(Path('model_opcua/features.json').read_text())
    if not frame[features].equals(revised[features]):
        raise AssertionError('Feature values changed')
    model = joblib.load(model_path)
    matrix = frame[features].apply(pd.to_numeric, errors='coerce').fillna(0)
    pred = np.array([normalize_label(p) for p in model.predict(matrix)])
    probabilities = model.predict_proba(matrix)
    classes = [normalize_label(c) for c in model.classes_]
    score = 1-probabilities[:, classes.index('benign')]
    old_truth = np.array([normalize_label(v) for v in frame.label])
    new_truth = np.array([normalize_label(v) for v in revised.label])
    for i, row in frame.iterrows():
        start = int(row.window_start_ms)
        evidence = {e: packet_evidence[(start, e)] for e in selected_by_window.get(start, [])}
        comparison.append(dict(window_start_ms=start, window_end_ms=int(row.window_end_ms),
                               old_label=row.label, new_label=revised.at[i, 'label'],
                               old_episode=row.episode_id, new_episode=revised.at[i, 'episode_id'],
                               label_changed=row.label != revised.at[i, 'label'],
                               evidence_frames=json.dumps(evidence), prediction=pred[i]))
    revised.to_csv(root/'ood2_event_aware.csv', index=False)
    pd.DataFrame(comparison).to_csv(root/'window_label_comparison.csv', index=False)
    output = revised.copy()
    output['label_eval'] = new_truth
    output['pred_label_eval'] = pred
    output['pred_attack_score'] = score
    output['is_correct'] = new_truth == pred
    output.to_csv(root/'predictions.csv', index=False)
    episode_rows = []
    for start, end, label, episode in episodes:
        eligible = sorted(s for s, e in packet_evidence if e == episode)
        positions = [indices[s] for s in eligible]
        overlap_positions = [i for i, r in frame.iterrows()
                             if int(r.window_start_ms) < end and int(r.window_end_ms) > start]
        episode_rows.append(dict(episode=episode, label=label, start_ms=start, end_ms=end,
            evidence_windows=len(positions),
            evidence_frames=json.dumps([n for s in eligible for n in packet_evidence[(s, episode)]]),
            assessable=bool(positions),
            detected_argmax=bool(any(pred[i] != 'benign' for i in positions)),
            detected_attack_score_05=bool(any(score[i] >= .5 for i in positions)),
            subtype_correct=bool(any(pred[i] == normalize_label(label) for i in positions)),
            predictions=json.dumps([str(pred[i]) for i in positions]),
            old_labeled_attack_windows=sum(frame.at[i,'episode_id']==episode and
                                          old_truth[i]!='benign' for i in overlap_positions)))
    pd.DataFrame(episode_rows).to_csv(root/'all_28_episode_results.csv', index=False)
    report = classification_report(new_truth, pred, labels=classes, output_dict=True, zero_division=0)
    (root/'classification_report.json').write_text(json.dumps(report, indent=2)+'\n')
    pd.DataFrame(confusion_matrix(new_truth, pred, labels=classes),
                 index=classes, columns=classes).to_csv(root/'confusion_matrix.csv')
    legacy = pd.read_csv('experiments/opcua_research_v2/warmup_ood/ood2_predictions.csv')
    legacy_by_window = dict(zip(legacy.window_start_ms, legacy.pred_label_eval))
    agreement = all(legacy_by_window[int(s)] == pred[i] for i,s in enumerate(frame.window_start_ms))
    summary = dict(rule='Preserve old labels; prioritize attack only with attacker-originated TCP payload to PLC:4840 inside the attack timeline interval; SESSION_BURST also accepts attacker-originated SYN. No label is chosen from model predictions.',
        sklearn_version=sklearn.__version__, n_windows=len(frame), features_unchanged=True,
        changed_windows=int((frame.label != revised.label).sum()),
        original_metrics=metrics(old_truth,pred,classes), event_aware_metrics=metrics(new_truth,pred,classes),
        timeline_attack_episodes=len(episodes), evidence_assessable_episodes=sum(r['assessable'] for r in episode_rows),
        detected_episodes_argmax=sum(r['detected_argmax'] for r in episode_rows),
        detected_episodes_attack_score_05=sum(r['detected_attack_score_05'] for r in episode_rows),
        correct_subtype_episodes=sum(r['subtype_correct'] for r in episode_rows),
        predictions_match_existing_artifact=agreement, original_sha256=before,
        source_files_unchanged=all(digest(p)==h for p,h in before.items()),
        limitations=['Evidence denotes a declared test action with traffic, not proof of malicious intent or successful process impact.',
                     'Fuzz payload presence does not independently prove malformed content.',
                     'Model was selected using OOD2; this is a label-rule sensitivity analysis, not a final independent test.',
                     'Existing 61 features and model are frozen; no opcua.Results feature was added.',
                     'Binary argmax and summed attack probability >=0.5 are different detection rules, reported separately.'])
    if not agreement or not summary['source_files_unchanged']:
        raise AssertionError('Frozen-input or prediction-reproduction check failed')
    (root/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(summary,ensure_ascii=False,indent=2))


if __name__ == '__main__':
    main()
