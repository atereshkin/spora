//! Perf-metrics registry for the lab's performance suites.
//!
//! Scenarios record named metrics into the process-wide registry
//! ([`record`] / [`global`]); the suite's `main()` calls [`finish`] at the
//! end, which prints an aligned table, optionally writes a JSON snapshot
//! (`SPORA_LAB_PERF_JSON=<path>`), and optionally gates against a baseline
//! snapshot (`SPORA_LAB_PERF_BASELINE=<path>`,
//! `SPORA_LAB_PERF_TOLERANCE=<pct>`, default 30).
//!
//! Names are stable flat identifiers (e.g. `download_mbps.relay.shaped50`).
//! Baseline comparison only gates metrics present in BOTH current run and
//! baseline; metrics missing from either side are warnings, never failures —
//! adding or retiring a metric must not break the gate. Absolute values on a
//! developer machine are report-only; the hard gates are the rate-shaped
//! targets chosen far below CPU capacity (see the perf suites).
//!
//! Every metric carries its own `noise_pct`: the run-to-run variance band
//! the recording scenario expects for it (shaped throughput is tight,
//! unshaped/CPU numbers swing ±15% per run on an idle machine). Baseline
//! comparison and `perf-diff` gate each metric at
//! `max(global tolerance, metric noise_pct)` — a uniform tolerance tight
//! enough for stable metrics would cry wolf on the noisy ones (an A/A
//! self-comparison empirically fails at a flat 10%).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    pub value: f64,
    pub unit: String,
    pub higher_is_better: bool,
    /// Expected run-to-run variance band (percent) for this metric; the
    /// effective gate tolerance is `max(global tolerance, noise_pct)`.
    pub noise_pct: f64,
}

/// A flat-namespace registry of perf metrics. `BTreeMap` keeps printing and
/// JSON output in stable (alphabetical) order.
#[derive(Debug, Default)]
pub struct Metrics {
    entries: BTreeMap<String, Metric>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &mut self,
        name: &str,
        value: f64,
        unit: &str,
        higher_is_better: bool,
        noise_pct: f64,
    ) {
        let prev = self.entries.insert(
            name.to_string(),
            Metric {
                value,
                unit: unit.to_string(),
                higher_is_better,
                noise_pct,
            },
        );
        if prev.is_some() {
            log::warn!("metric {name} recorded twice; keeping the last value");
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Aligned human-readable table on stdout.
    pub fn print_table(&self) {
        if self.entries.is_empty() {
            println!("(no metrics recorded)");
            return;
        }
        let name_w = self
            .entries
            .keys()
            .map(|n| n.len())
            .max()
            .unwrap_or(0)
            .max("metric".len());
        let values: Vec<String> = self
            .entries
            .values()
            .map(|m| format!("{:.3}", m.value))
            .collect();
        let value_w = values
            .iter()
            .map(|v| v.len())
            .max()
            .unwrap_or(0)
            .max("value".len());
        println!("{:<name_w$}  {:>value_w$}  {:<8}  better", "metric", "value", "unit");
        for ((name, m), value) in self.entries.iter().zip(&values) {
            println!(
                "{name:<name_w$}  {value:>value_w$}  {:<8}  {}",
                m.unit,
                if m.higher_is_better { "higher" } else { "lower" },
            );
        }
    }

    /// JSON snapshot: `{ "meta": {...}, "metrics": { name: { value, unit,
    /// higher_is_better } } }`. Everything in `meta` is best-effort.
    pub fn to_json(&self) -> serde_json::Value {
        let metrics: serde_json::Map<String, serde_json::Value> = self
            .entries
            .iter()
            .map(|(name, m)| {
                (
                    name.clone(),
                    serde_json::json!({
                        "value": m.value,
                        "unit": m.unit,
                        "higher_is_better": m.higher_is_better,
                        "noise_pct": m.noise_pct,
                    }),
                )
            })
            .collect();
        serde_json::json!({ "meta": meta(), "metrics": metrics })
    }

    pub fn write_json(&self, path: &Path) -> Result<(), String> {
        let body = serde_json::to_string_pretty(&self.to_json())
            .map_err(|e| format!("serialize metrics: {e}"))?;
        std::fs::write(path, body).map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// Parse a snapshot previously produced by [`write_json`](Self::write_json).
    pub fn from_json(v: &serde_json::Value) -> Result<Metrics, String> {
        let obj = v
            .get("metrics")
            .and_then(|m| m.as_object())
            .ok_or("baseline JSON has no \"metrics\" object")?;
        let mut out = Metrics::new();
        for (name, m) in obj {
            let value = m
                .get("value")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| format!("baseline metric {name}: missing numeric \"value\""))?;
            let unit = m.get("unit").and_then(|v| v.as_str()).unwrap_or("");
            let higher_is_better = m
                .get("higher_is_better")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| format!("baseline metric {name}: missing \"higher_is_better\""))?;
            // Older snapshots have no noise_pct; 0 = "use the global tolerance".
            let noise_pct = m.get("noise_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
            out.record(name, value, unit, higher_is_better, noise_pct);
        }
        Ok(out)
    }

    /// Gate against `baseline`: every metric present in BOTH runs must not be
    /// worse than the baseline by more than the metric's effective tolerance
    /// — `max(tolerance_pct, noise_pct of either side)` — in its "worse"
    /// direction (below `baseline * (1 - t)` when higher is better, above
    /// `baseline * (1 + t)` when lower is better; exactly at the edge still
    /// passes). All violations are collected into one error. Metrics present
    /// on only one side, direction-flag mismatches, and non-finite or zero
    /// baselines (uncomparable) are warnings — they are printed, and included
    /// in the error message if there is one, but never fail the gate by
    /// themselves.
    pub fn compare_with(&self, baseline: &Metrics, tolerance_pct: f64) -> Result<(), String> {
        let mut violations: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        for (name, cur) in &self.entries {
            let Some(base) = baseline.entries.get(name) else {
                warnings.push(format!("{name}: not in baseline (new metric?)"));
                continue;
            };
            if base.higher_is_better != cur.higher_is_better {
                warnings.push(format!(
                    "{name}: higher_is_better flag differs from baseline; using current ({})",
                    cur.higher_is_better
                ));
            }
            if !base.value.is_finite() || base.value == 0.0 || !cur.value.is_finite() {
                warnings.push(format!(
                    "{name}: uncomparable values (baseline {}, current {})",
                    base.value, cur.value
                ));
                continue;
            }
            let effective_pct = tolerance_pct.max(cur.noise_pct).max(base.noise_pct);
            let t = effective_pct / 100.0;
            let (worse, bound) = if cur.higher_is_better {
                let bound = base.value * (1.0 - t);
                (cur.value < bound, bound)
            } else {
                let bound = base.value * (1.0 + t);
                (cur.value > bound, bound)
            };
            if worse {
                violations.push(format!(
                    "{name}: {:.3} {} is worse than baseline {:.3} by more than {effective_pct}% \
                     (allowed {} {bound:.3})",
                    cur.value,
                    cur.unit,
                    base.value,
                    if cur.higher_is_better { ">=" } else { "<=" },
                ));
            }
        }
        for name in baseline.entries.keys() {
            if !self.entries.contains_key(name) {
                warnings.push(format!("{name}: in baseline but not in this run"));
            }
        }

        for w in &warnings {
            eprintln!("baseline warning: {w}");
        }
        if violations.is_empty() {
            return Ok(());
        }
        let mut msg = format!(
            "{} metric(s) regressed past the {tolerance_pct}% tolerance:\n  {}",
            violations.len(),
            violations.join("\n  ")
        );
        if !warnings.is_empty() {
            msg.push_str(&format!("\nwarnings (not failures):\n  {}", warnings.join("\n  ")));
        }
        Err(msg)
    }

    /// [`compare_with`](Self::compare_with) against a JSON snapshot on disk.
    pub fn compare_baseline(&self, path: &Path, tolerance_pct: f64) -> Result<(), String> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| format!("read baseline {}: {e}", path.display()))?;
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("parse baseline {}: {e}", path.display()))?;
        self.compare_with(&Metrics::from_json(&v)?, tolerance_pct)
    }
}

/// The process-wide registry the perf scenarios record into. (Lab suites are
/// `harness = false` and run scenarios sequentially on the main thread; the
/// mutex makes it safe to record from anywhere regardless.)
pub fn global() -> &'static Mutex<Metrics> {
    static GLOBAL: OnceLock<Mutex<Metrics>> = OnceLock::new();
    GLOBAL.get_or_init(|| Mutex::new(Metrics::new()))
}

/// Record into the [`global`] registry. `noise_pct` is the metric's expected
/// run-to-run variance band — see the module docs.
pub fn record(name: &str, value: f64, unit: &str, higher_is_better: bool, noise_pct: f64) {
    global()
        .lock()
        .expect("metrics mutex poisoned")
        .record(name, value, unit, higher_is_better, noise_pct);
}

/// Suite-end hook: print the table, write the JSON snapshot if
/// `SPORA_LAB_PERF_JSON` is set, and gate against `SPORA_LAB_PERF_BASELINE`
/// if set (tolerance from `SPORA_LAB_PERF_TOLERANCE`, default 30%). Returns
/// `Err` so a `harness = false` suite can fail its run on a regression.
pub fn finish(suite: &str) -> Result<(), String> {
    let metrics = global().lock().expect("metrics mutex poisoned");
    println!("\n{suite}: perf metrics");
    metrics.print_table();

    if let Ok(path) = std::env::var("SPORA_LAB_PERF_JSON") {
        metrics.write_json(Path::new(&path))?;
        println!("{suite}: wrote perf JSON to {path}");
    }
    if let Ok(path) = std::env::var("SPORA_LAB_PERF_BASELINE") {
        let tolerance = match std::env::var("SPORA_LAB_PERF_TOLERANCE") {
            Ok(v) => v.parse::<f64>().unwrap_or_else(|e| {
                eprintln!(
                    "{suite}: SPORA_LAB_PERF_TOLERANCE={v} is not a number ({e}); using 30"
                );
                30.0
            }),
            Err(_) => 30.0,
        };
        metrics.compare_baseline(Path::new(&path), tolerance)?;
        println!("{suite}: baseline check passed ({path}, tolerance {tolerance}%)");
    }
    Ok(())
}

/// Best-effort run metadata for the JSON snapshot.
fn meta() -> serde_json::Value {
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let git_sha = command_line("git", &["rev-parse", "--short", "HEAD"]);
    let nproc = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let kernel = command_line("uname", &["-r"]);
    serde_json::json!({
        "unix_time": unix_time,
        "git_sha": git_sha,
        "nproc": nproc,
        "kernel": kernel,
    })
}

/// First line of a command's stdout, or `None` (serialized as JSON null) if
/// it cannot run — meta only, never fatal.
fn command_line(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(entries: &[(&str, f64, bool)]) -> Metrics {
        let mut m = Metrics::new();
        for (name, value, hib) in entries {
            m.record(name, *value, "u", *hib, 0.0);
        }
        m
    }

    #[test]
    fn higher_is_better_direction() {
        let base = metrics(&[("mbps", 100.0, true)]);
        // Better and slightly worse both pass.
        assert!(metrics(&[("mbps", 130.0, true)]).compare_with(&base, 25.0).is_ok());
        assert!(metrics(&[("mbps", 80.0, true)]).compare_with(&base, 25.0).is_ok());
        // Worse by more than the tolerance fails.
        let err = metrics(&[("mbps", 60.0, true)])
            .compare_with(&base, 25.0)
            .unwrap_err();
        assert!(err.contains("mbps"), "error names the metric: {err}");
    }

    #[test]
    fn lower_is_better_direction() {
        let base = metrics(&[("rtt_ms", 100.0, false)]);
        assert!(metrics(&[("rtt_ms", 70.0, false)]).compare_with(&base, 25.0).is_ok());
        assert!(metrics(&[("rtt_ms", 120.0, false)]).compare_with(&base, 25.0).is_ok());
        let err = metrics(&[("rtt_ms", 140.0, false)])
            .compare_with(&base, 25.0)
            .unwrap_err();
        assert!(err.contains("rtt_ms"), "error names the metric: {err}");
    }

    #[test]
    fn tolerance_edges_pass() {
        // 25% of 100 is exact in binary: the bounds are exactly 75 and 125.
        let base_hi = metrics(&[("m", 100.0, true)]);
        assert!(metrics(&[("m", 75.0, true)]).compare_with(&base_hi, 25.0).is_ok());
        assert!(metrics(&[("m", 74.9, true)]).compare_with(&base_hi, 25.0).is_err());

        let base_lo = metrics(&[("m", 100.0, false)]);
        assert!(metrics(&[("m", 125.0, false)]).compare_with(&base_lo, 25.0).is_ok());
        assert!(metrics(&[("m", 125.1, false)]).compare_with(&base_lo, 25.0).is_err());
    }

    #[test]
    fn zero_tolerance_requires_no_regression_at_all() {
        let base = metrics(&[("m", 100.0, true)]);
        assert!(metrics(&[("m", 100.0, true)]).compare_with(&base, 0.0).is_ok());
        assert!(metrics(&[("m", 99.9, true)]).compare_with(&base, 0.0).is_err());
    }

    #[test]
    fn missing_and_extra_metrics_are_not_failures() {
        let base = metrics(&[("only_in_baseline", 1.0, true), ("shared", 100.0, true)]);
        let cur = metrics(&[("only_in_current", 1.0, true), ("shared", 100.0, true)]);
        assert!(cur.compare_with(&base, 10.0).is_ok());
        // ... but a real violation still reports them as warnings.
        let cur_bad = metrics(&[("only_in_current", 1.0, true), ("shared", 10.0, true)]);
        let err = cur_bad.compare_with(&base, 10.0).unwrap_err();
        assert!(err.contains("shared"));
        assert!(err.contains("warnings"));
        assert!(err.contains("only_in_baseline"));
    }

    #[test]
    fn all_violations_are_collected() {
        let base = metrics(&[("a", 100.0, true), ("b", 100.0, false)]);
        let cur = metrics(&[("a", 10.0, true), ("b", 1000.0, false)]);
        let err = cur.compare_with(&base, 30.0).unwrap_err();
        assert!(err.contains("a:") && err.contains("b:"), "both in: {err}");
        assert!(err.contains("2 metric(s)"), "count in: {err}");
    }

    #[test]
    fn json_roundtrip_and_file_baseline() {
        let mut m = Metrics::new();
        m.record("download_mbps.relay.shaped50", 4.2, "mbps", true, 0.0);
        m.record("cpu_seconds.client", 1.25, "s", false, 0.0);

        let parsed = Metrics::from_json(&m.to_json()).expect("roundtrip parses");
        assert_eq!(parsed.entries, m.entries);

        let path = std::env::temp_dir().join(format!(
            "spora-lab-metrics-test-{}.json",
            std::process::id()
        ));
        m.write_json(&path).expect("write JSON");
        // Identical run vs its own snapshot: passes at any tolerance.
        m.compare_baseline(&path, 0.0).expect("self-compare passes");
        // A regressed run against the same snapshot: fails.
        let mut worse = Metrics::new();
        worse.record("download_mbps.relay.shaped50", 1.0, "mbps", true, 0.0);
        worse.record("cpu_seconds.client", 1.25, "s", false, 0.0);
        assert!(worse.compare_baseline(&path, 30.0).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_baseline_is_an_error() {
        assert!(Metrics::from_json(&serde_json::json!({})).is_err());
        assert!(
            Metrics::from_json(&serde_json::json!({"metrics": {"m": {"unit": "x"}}})).is_err()
        );
    }
}
