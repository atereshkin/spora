//! perf-diff: compare two sets of perf-suite JSON snapshots
//! (`SPORA_LAB_PERF_JSON` outputs; see `spora_lab::metrics`).
//!
//! ```text
//! perf-diff [--tolerance <pct>] <baseline.json>... -- <current.json>...
//! perf-diff [--tolerance <pct>] <baseline-dir> <current-dir>
//! ```
//!
//! Per metric: the MEDIAN of each side (robust against one noisy
//! iteration), then a signed percent delta oriented so that NEGATIVE =
//! regression regardless of the metric's direction (`higher_is_better`
//! from the snapshots). Prints an aligned table; exits 1 if any metric
//! regresses past its EFFECTIVE tolerance: `max(--tolerance, the metric's
//! own noise_pct from the snapshots)` — report-only metrics carry wide
//! noise bands by design (an A/A self-comparison must stay quiet) while
//! stable shaped metrics stay tight. `--tolerance` defaults to 10. Metrics
//! present on only one side, or with zero/non-finite medians, are listed as
//! warnings, never failures.
//!
//! Dependencies: std + serde_json (already in the tree for the metrics
//! snapshots themselves).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_TOLERANCE_PCT: f64 = 10.0;

const USAGE: &str = "usage: perf-diff [--tolerance <pct>] <baseline.json>... -- <current.json>...
       perf-diff [--tolerance <pct>] <baseline-dir> <current-dir>";

#[derive(Default)]
struct Side {
    /// metric name -> (samples, higher_is_better, unit, max noise_pct seen)
    metrics: BTreeMap<String, (Vec<f64>, bool, String, f64)>,
}

impl Side {
    fn load(&mut self, path: &Path) -> Result<(), String> {
        let body =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;
        let obj = v
            .get("metrics")
            .and_then(|m| m.as_object())
            .ok_or_else(|| format!("{}: no \"metrics\" object", path.display()))?;
        for (name, m) in obj {
            let value = m
                .get("value")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| format!("{}: metric {name}: bad \"value\"", path.display()))?;
            let hib = m
                .get("higher_is_better")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| {
                    format!(
                        "{}: metric {name}: bad \"higher_is_better\"",
                        path.display()
                    )
                })?;
            let unit = m
                .get("unit")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Pre-noise_pct snapshots read as 0 (= "--tolerance applies").
            let noise = m.get("noise_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let entry = self
                .metrics
                .entry(name.clone())
                .or_insert_with(|| (Vec::new(), hib, unit, 0.0));
            entry.0.push(value);
            entry.3 = entry.3.max(noise);
        }
        Ok(())
    }
}

/// Median of a sample set (mean of the two middle elements when even).
fn median(samples: &[f64]) -> f64 {
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

struct Args {
    tolerance_pct: f64,
    baseline: Vec<PathBuf>,
    current: Vec<PathBuf>,
}

fn json_files_in(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("read dir {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("{}: no .json files", dir.display()));
    }
    Ok(files)
}

fn parse_args() -> Result<Args, String> {
    let mut tolerance_pct = DEFAULT_TOLERANCE_PCT;
    let mut positional: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--tolerance" {
            let v = args.next().ok_or("--tolerance needs a value")?;
            tolerance_pct = v
                .parse::<f64>()
                .map_err(|e| format!("--tolerance {v}: {e}"))?;
        } else if let Some(v) = a.strip_prefix("--tolerance=") {
            tolerance_pct = v
                .parse::<f64>()
                .map_err(|e| format!("--tolerance {v}: {e}"))?;
        } else if a == "--help" || a == "-h" {
            return Err(USAGE.to_string());
        } else {
            positional.push(a);
        }
    }

    let (baseline, current) = if let Some(sep) = positional.iter().position(|a| a == "--") {
        let baseline: Vec<PathBuf> = positional[..sep].iter().map(PathBuf::from).collect();
        let current: Vec<PathBuf> = positional[sep + 1..].iter().map(PathBuf::from).collect();
        (baseline, current)
    } else if positional.len() == 2
        && Path::new(&positional[0]).is_dir()
        && Path::new(&positional[1]).is_dir()
    {
        (
            json_files_in(Path::new(&positional[0]))?,
            json_files_in(Path::new(&positional[1]))?,
        )
    } else {
        return Err(USAGE.to_string());
    };
    if baseline.is_empty() || current.is_empty() {
        return Err(USAGE.to_string());
    }
    Ok(Args {
        tolerance_pct,
        baseline,
        current,
    })
}

fn run() -> Result<bool, String> {
    let args = parse_args()?;

    let mut base = Side::default();
    for p in &args.baseline {
        base.load(p)?;
    }
    let mut cur = Side::default();
    for p in &args.current {
        cur.load(p)?;
    }
    println!(
        "perf-diff: {} baseline file(s) vs {} current file(s), tolerance {}%\n",
        args.baseline.len(),
        args.current.len(),
        args.tolerance_pct
    );

    struct Row {
        name: String,
        base: String,
        cur: String,
        delta: String,
        tol: String,
        unit: String,
        regressed: bool,
    }
    let mut rows: Vec<Row> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut regressions: Vec<String> = Vec::new();

    for (name, (samples, hib, unit, cur_noise)) in &cur.metrics {
        let Some((base_samples, base_hib, _, base_noise)) = base.metrics.get(name) else {
            warnings.push(format!("{name}: not in baseline (new metric?)"));
            continue;
        };
        if base_hib != hib {
            warnings.push(format!(
                "{name}: higher_is_better differs between sides; using current ({hib})"
            ));
        }
        let b = median(base_samples);
        let c = median(samples);
        if b == 0.0 || !b.is_finite() || !c.is_finite() {
            warnings.push(format!("{name}: uncomparable medians ({b} vs {c})"));
            continue;
        }
        // Signed so that NEGATIVE = regression in the metric's own terms.
        let delta_pct = if *hib {
            (c - b) / b * 100.0
        } else {
            (b - c) / b * 100.0
        };
        let effective_tol = args.tolerance_pct.max(*cur_noise).max(*base_noise);
        let regressed = delta_pct < -effective_tol;
        if regressed {
            regressions.push(format!(
                "{name}: {delta_pct:+.1}% past its {effective_tol}% tolerance \
                 ({b:.3} -> {c:.3} {unit})"
            ));
        }
        rows.push(Row {
            name: name.clone(),
            base: format!("{b:.3}"),
            cur: format!("{c:.3}"),
            delta: format!("{delta_pct:+.1}%"),
            tol: format!("{effective_tol:.0}%"),
            unit: unit.clone(),
            regressed,
        });
    }
    for name in base.metrics.keys() {
        if !cur.metrics.contains_key(name) {
            warnings.push(format!("{name}: in baseline but not in current"));
        }
    }

    let w_name = rows
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(0)
        .max("metric".len());
    let w_base = rows
        .iter()
        .map(|r| r.base.len())
        .max()
        .unwrap_or(0)
        .max("baseline".len());
    let w_cur = rows
        .iter()
        .map(|r| r.cur.len())
        .max()
        .unwrap_or(0)
        .max("current".len());
    let w_delta = rows
        .iter()
        .map(|r| r.delta.len())
        .max()
        .unwrap_or(0)
        .max("delta".len());
    let w_tol = rows
        .iter()
        .map(|r| r.tol.len())
        .max()
        .unwrap_or(0)
        .max("tol".len());
    println!(
        "{:<w_name$}  {:>w_base$}  {:>w_cur$}  {:>w_delta$}  {:>w_tol$}  unit",
        "metric", "baseline", "current", "delta", "tol"
    );
    for r in &rows {
        println!(
            "{:<w_name$}  {:>w_base$}  {:>w_cur$}  {:>w_delta$}  {:>w_tol$}  {}{}",
            r.name,
            r.base,
            r.cur,
            r.delta,
            r.tol,
            r.unit,
            if r.regressed { "  <-- REGRESSED" } else { "" },
        );
    }
    for w in &warnings {
        println!("warning: {w}");
    }

    if regressions.is_empty() {
        println!(
            "\nperf-diff: OK — no metric regressed past its tolerance \
             (max of {}% and the metric's noise_pct; negative delta = regression)",
            args.tolerance_pct
        );
        Ok(true)
    } else {
        println!(
            "\nperf-diff: {} metric(s) regressed past their tolerance:",
            regressions.len(),
        );
        for r in &regressions {
            println!("  {r}");
        }
        Ok(false)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
