"""Bounded independent evidence and conservative scores for GLOBAL candidates."""
import math

import clash_common as common

WINDOW_SECONDS = 3600
SAMPLE_GAP_SECONDS = 60
MAX_OBSERVATIONS = 60


def epoch(cfg):
    """Only measurement policy changes invalidate like-for-like observations."""
    keys = ('checks', 'max_jitter_ms', 'max_tcp_ms', 'tcp_samples',
            'tcp_timeout_seconds', 'timeout_seconds', 'binary')
    return common.fingerprint(dict(version=2, policy={key: cfg.get(key) for key in keys}))


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


RECENT_SECONDS = 300
HALF_LIFE_SECONDS = 90


def summarize(history, latest=None, now=None):
    """Score fresh evidence, not a node's historical reputation.

    The latest full probe contributes 80 points; only the preceding five
    minutes contribute the remaining 20, with a 90-second half-life.
    """
    if now is None:
        now = latest.get('at', 0) if latest else (history[-1]['at'] if history else 0)
    recent = [row for row in history if 0 <= now - row['at'] <= RECENT_SECONDS]
    if latest is None and recent:
        sample = recent[-1]
        latest = dict(sample, ok=sample['transport_ok'])
    latest = latest or {}
    count = len(recent)
    weights = [2 ** (-(now - row['at']) / HALF_LIFE_SECONDS) for row in recent]
    total_weight = sum(weights)
    def rate(key):
        return sum(weight * bool(row[key]) for weight, row in zip(weights, recent)) / total_weight if total_weight else 0
    stable_rate, success_rate, timeout_rate = rate('stable'), rate('transport_ok'), rate('timeout')
    streak = 0
    for row in reversed(recent):
        if not row['stable']:
            break
        streak += 1
    tcp_ms = latest.get('tcp_ms') if _number(latest.get('tcp_ms')) else None
    jitter_ms = latest.get('jitter_ms') if _number(latest.get('jitter_ms')) else None
    span = recent[-1]['at'] - recent[0]['at'] if count else 0
    age = now - latest.get('at', 0)
    fresh = 0 <= age <= RECENT_SECONDS
    available = bool(latest.get('ok', latest.get('transport_ok'))) and fresh
    current_stable = bool(latest.get('stable', latest.get('ok'))) and available
    current_points = (50 * available + 20 * current_stable
                      + (7 * max(0, 1 - tcp_ms / 800) if tcp_ms is not None and available else 0)
                      + (3 * max(0, 1 - jitter_ms / 250) if jitter_ms is not None and available else 0))
    recent_points = (10 * success_rate + 8 * stable_rate + 2 * (1 - timeout_rate)) if count else 0
    # Old evidence loses influence even within its short eligibility window.
    freshness = 2 ** (-max(age, 0) / RECENT_SECONDS)
    score = (current_points * freshness + recent_points) if available else 0
    sustained = (current_stable and count >= 3 and span >= 120 and streak >= 3
                 and stable_rate >= .8 and success_rate >= .9)
    return dict(score=round(score, 2), sustained=sustained, observations=count,
                span_seconds=round(span, 2), success_rate=round(success_rate, 3),
                stable_rate=round(stable_rate, 3), stable_streak=streak,
                timeout_rate=round(timeout_rate, 3), tcp_ms=tcp_ms, jitter_ms=jitter_ms,
                current_available=available, current_stable=current_stable,
                window_seconds=RECENT_SECONDS, half_life_seconds=HALF_LIFE_SECONDS)


def observe(previous, report, identity, measurement_epoch, now, scheduled=True):
    """Latest health stays separate from time-spaced, conservative history.

    A recheck cannot add independent observations. Any failure in the same
    observation is retained even if a later recheck happens to work.
    """
    compatible = (previous.get('identity') == identity
                  and previous.get('statistics_epoch') == measurement_epoch)
    history = [dict(row) for row in previous.get('history', [])
               if compatible and 0 <= now - row['at'] <= WINDOW_SECONDS]
    history = history[-MAX_OBSERVATIONS:]
    sample = dict(at=now, stable=bool(report.get('stable', report.get('ok'))),
                  transport_ok=bool(report.get('ok')), switchable=bool(report.get('switchable')),
                  timeout=bool(report.get('tcp_timeouts', 0)) or any(
                      row.get('curl_exit') == 28 for row in report.get('relay', [])),
                  tcp_ms=report.get('tcp_ms'), jitter_ms=report.get('jitter_ms'),
                  max_tcp_ms=report.get('max_tcp_ms'),
                  relay_successes=report.get('relay_successes'), relay_total=report.get('relay_total'))
    if scheduled and (not history or now - history[-1]['at'] >= SAMPLE_GAP_SECONDS):
        history.append(sample)
    elif history:
        last = history[-1]
        last['stable'] = last['stable'] and sample['stable']
        last['transport_ok'] = last['transport_ok'] and sample['transport_ok']
        last['switchable'] = last['switchable'] or sample['switchable']
        last['timeout'] = last['timeout'] or sample['timeout']
        for key in ('tcp_ms', 'jitter_ms', 'max_tcp_ms'):
            values = [value for value in (last.get(key), sample.get(key)) if _number(value)]
            last[key] = max(values) if values else None
        if sample['relay_successes'] is not None:
            values = [value for value in (last.get('relay_successes'), sample['relay_successes']) if value is not None]
            last['relay_successes'] = min(values)
            last['relay_total'] = sample['relay_total']
    history = history[-MAX_OBSERVATIONS:]
    ranking = summarize(history, dict(report, at=now), now)
    recent = [row for row in history if 0 <= now - row['at'] <= RECENT_SECONDS]
    stability = dict(observations=ranking['observations'],
                     stable_observations=sum(row['stable'] for row in recent),
                     stable_rate=ranking['stable_rate'],
                     last_stable_at=next((row['at'] for row in reversed(history) if row['stable']), 0))
    return dict(history=history, statistics_epoch=measurement_epoch, stability=stability, ranking=ranking)
