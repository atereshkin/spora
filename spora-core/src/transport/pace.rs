//! BBR-lite pacing estimator for the nz carrier.
//!
//! nz carries inner TCP over unreliable datagrams and, unlike quinn (which
//! paces with BBR), sends each datagram the instant the stack hands it over.
//! On a shaped/lossy bottleneck those micro-bursts overflow the queue and
//! trigger the inner sender's backoff, halving throughput. This restores the
//! missing piece: a delivery-rate-driven pacer.
//!
//! The estimator is fed **receiver-reported delivery-rate samples** (each side
//! measures the rate of tunnel data it receives and reports it to the peer over
//! a `CH_RATE` control frame — see [`super::noise`]). From those it keeps a
//! windowed-max bottleneck-bandwidth estimate and a BBR-style gain schedule:
//!
//! - **Startup:** pace at `BtlBw * 2` so the rate ramps geometrically until the
//!   pipe is full (BtlBw stops growing) — the sender must out-run the estimate
//!   to discover bandwidth, since a receiver only ever measures what was sent.
//! - **ProbeBW:** cruise near `BtlBw * 1`, periodically probing up (`1.25`) then
//!   draining (`0.75`) so the estimate tracks bandwidth changes without building
//!   a standing queue.
//!
//! This is deliberately not full BBR (no ProbeRTT, RTT-estimation, or precise
//! RTT-length phases — the tunnel has no per-packet ACK clock); it is the
//! smallest thing that paces to the measured bottleneck.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Floor so a flow can always bootstrap and recover from idle (1 Mbit/s in
/// bytes/sec). Without it a zero estimate would pace at zero and never send the
/// packets whose delivery would raise the estimate.
const MIN_RATE: f64 = 125_000.0;
/// Bandwidth-max filter window: BtlBw is the max delivery sample over this span,
/// so a single low sample (a loss blip) can't collapse the estimate.
const BW_WINDOW: Duration = Duration::from_secs(2);
/// Startup gain: > 1 so the paced rate outruns the current estimate and ramps
/// geometrically toward the true bottleneck.
const STARTUP_GAIN: f64 = 2.0;
/// ProbeBW gain cycle: probe up, drain the queue the probe built, then cruise.
const GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// How long each ProbeBW gain phase lasts (a stand-in for one RTT; the tunnel
/// has no RTT clock, so a fixed span near a typical RTT is used).
const PHASE: Duration = Duration::from_millis(40);
/// Startup ends when BtlBw fails to grow by 25% for this many samples — the
/// pipe is full, so cruise instead of ramping.
const STARTUP_FULL_ROUNDS: u32 = 3;
/// ...but only once BtlBw is above this multiple of the floor. Below it, a
/// plateau is establishment / early-slow-start noise, not a real bottleneck, so
/// keep ramping — else a few tiny early samples lock the flow at ~1 Mbit/s.
const STARTUP_MIN_EXIT_MULT: f64 = 4.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Startup,
    ProbeBw,
}

/// Delivery-rate estimator + gain schedule. Single-owner (the pacer task);
/// fed samples via [`Pacer::on_sample`] and queried via [`Pacer::pace_rate`].
pub(crate) struct Pacer {
    samples: VecDeque<(Instant, f64)>,
    btlbw: f64,
    mode: Mode,
    startup_best: f64,
    startup_flat: u32,
    phase: usize,
    phase_start: Instant,
}

impl Pacer {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            samples: VecDeque::new(),
            btlbw: 0.0,
            mode: Mode::Startup,
            startup_best: 0.0,
            startup_flat: 0,
            phase: 0,
            phase_start: now,
        }
    }

    /// Record a delivery-rate sample (bytes/sec) the receiver reported.
    pub(crate) fn on_sample(&mut self, now: Instant, rate: f64) {
        if !(rate > 0.0) {
            return;
        }
        self.samples.push_back((now, rate));
        while let Some(&(t, _)) = self.samples.front() {
            if now.duration_since(t) > BW_WINDOW {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        self.btlbw = self.samples.iter().map(|&(_, r)| r).fold(0.0, f64::max);

        if self.mode == Mode::Startup {
            if self.btlbw >= self.startup_best * 1.25 {
                self.startup_best = self.btlbw;
                self.startup_flat = 0;
            } else if self.btlbw >= MIN_RATE * STARTUP_MIN_EXIT_MULT {
                // A genuine plateau at a plausible bottleneck: pipe is full.
                self.startup_flat += 1;
                if self.startup_flat >= STARTUP_FULL_ROUNDS {
                    self.mode = Mode::ProbeBw;
                    self.phase = 0;
                    self.phase_start = now;
                }
            } else {
                // Too low to be the real bottleneck — early establishment /
                // slow-start noise. Keep ramping rather than locking a tiny rate.
                self.startup_flat = 0;
            }
        }
    }

    /// The pacing rate (bytes/sec) to use right now. Advances the ProbeBW gain
    /// phase as time passes.
    pub(crate) fn pace_rate(&mut self, now: Instant) -> f64 {
        let gain = match self.mode {
            Mode::Startup => STARTUP_GAIN,
            Mode::ProbeBw => {
                if now.duration_since(self.phase_start) >= PHASE {
                    self.phase = (self.phase + 1) % GAIN_CYCLE.len();
                    self.phase_start = now;
                }
                GAIN_CYCLE[self.phase]
            }
        };
        (self.btlbw * gain).max(MIN_RATE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_at_min_rate_before_any_sample() {
        let mut p = Pacer::new(Instant::now());
        assert_eq!(p.pace_rate(Instant::now()), MIN_RATE);
    }

    #[test]
    fn startup_ramps_then_plateaus_into_probe_bw() {
        let t0 = Instant::now();
        let mut p = Pacer::new(t0);
        // Ramp: each sample the receiver measures grows (the 2x startup gain let
        // the sender discover more each round), so we stay in startup and pace
        // at 2x the latest BtlBw.
        let mut t = t0;
        for mbit in [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 50.0] {
            t += Duration::from_millis(50);
            let rate = mbit * 125_000.0;
            p.on_sample(t, rate);
            assert_eq!(p.mode, Mode::Startup, "still ramping at {mbit} Mbit/s");
            assert!(
                (p.pace_rate(t) - rate * STARTUP_GAIN).abs() < 1.0,
                "startup paces at 2x BtlBw"
            );
        }
        // Now the link is full: repeated flat samples plateau -> ProbeBW.
        for _ in 0..STARTUP_FULL_ROUNDS {
            t += Duration::from_millis(50);
            p.on_sample(t, 50.0 * 125_000.0);
        }
        assert_eq!(p.mode, Mode::ProbeBw, "flat BtlBw exits startup");
        // BtlBw is held at the windowed max (~50 Mbit/s); pace_rate cruises near
        // it (gain cycle averages ~1.0), never below the estimate's drain phase.
        let bw = 50.0 * 125_000.0;
        let r = p.pace_rate(t);
        assert!(r >= bw * 0.7 && r <= bw * 1.3, "cruise near BtlBw, got {r}");
    }

    #[test]
    fn probe_bw_gain_cycles_over_time() {
        let t0 = Instant::now();
        let mut p = Pacer::new(t0);
        // Force into ProbeBW with a steady estimate.
        let bw = 40.0 * 125_000.0;
        let mut t = t0;
        for _ in 0..(STARTUP_FULL_ROUNDS + 2) {
            t += Duration::from_millis(50);
            p.on_sample(t, bw);
        }
        assert_eq!(p.mode, Mode::ProbeBw);
        // Sample the gain across several phases; it must visit both a probe-up
        // (> BtlBw) and a drain (< BtlBw), i.e. it is not stuck at one gain.
        let mut saw_up = false;
        let mut saw_down = false;
        for _ in 0..GAIN_CYCLE.len() * 2 {
            t += PHASE;
            let r = p.pace_rate(t);
            if r > bw * 1.1 {
                saw_up = true;
            }
            if r < bw * 0.9 {
                saw_down = true;
            }
        }
        assert!(saw_up && saw_down, "gain cycle must probe up and drain");
    }

    #[test]
    fn a_single_low_sample_does_not_collapse_btlbw() {
        let t0 = Instant::now();
        let mut p = Pacer::new(t0);
        let mut t = t0;
        // Establish a high estimate.
        for _ in 0..5 {
            t += Duration::from_millis(50);
            p.on_sample(t, 40.0 * 125_000.0);
        }
        // A single loss-blip low sample within the window: the max filter holds.
        t += Duration::from_millis(50);
        p.on_sample(t, 1.0 * 125_000.0);
        assert!(p.btlbw >= 40.0 * 125_000.0, "windowed max ignores the dip");
    }
}
