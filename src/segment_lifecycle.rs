//! Segment boundary state for agent jobs. Lease transport is integrated separately.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Queued,
    Leased,
    Done,
    Failed,
    FloorStopped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lifecycle {
    pub phase: Phase,
    pub segment: u64,
    pub resume_count: u64,
    pub max_segs: u64,
    pub done_items: BTreeSet<String>,
    pub lease_id: Option<String>,
    pub reason: Option<String>,
}

impl Lifecycle {
    pub fn new(max_segs: u64) -> Self {
        Self {
            phase: Phase::Queued,
            segment: 0,
            resume_count: 0,
            max_segs,
            done_items: BTreeSet::new(),
            lease_id: None,
            reason: None,
        }
    }

    /// The caller serializes access to this job and supplies the latest pushed balance.
    pub fn assign(&mut self, lease_id: String, balance: f64, floor: f64) -> bool {
        self.assign_checked(lease_id, balance, floor).is_ok()
    }

    pub fn assign_checked(
        &mut self,
        lease_id: String,
        balance: f64,
        floor: f64,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::Queued {
            return Err(crate::error_catalog::ILLEGAL_TRANSITION);
        }
        if !balance.is_finite() || !floor.is_finite() || floor < 0.0 {
            return Err(crate::error_catalog::BAD_SPEC);
        }
        if balance <= floor + 0.10 {
            self.phase = Phase::FloorStopped;
            self.reason = Some(crate::error_catalog::reason(crate::error_catalog::CU_FLOOR).into());
            return Err(crate::error_catalog::CU_FLOOR);
        }
        if self.segment >= self.max_segs {
            self.phase = Phase::Failed;
            self.reason =
                Some(crate::error_catalog::reason(crate::error_catalog::MAX_SEGS_EXCEEDED).into());
            return Err(crate::error_catalog::MAX_SEGS_EXCEEDED);
        }
        self.phase = Phase::Leased;
        self.lease_id = Some(lease_id);
        Ok(())
    }

    /// A report must match the outstanding lease; duplicate reports cannot mutate the job.
    pub fn report(
        &mut self,
        lease_id: &str,
        segment: u64,
        exit_code: i32,
        session_lost: bool,
        items: &[String],
    ) -> bool {
        self.report_checked(lease_id, segment, exit_code, session_lost, items)
            .is_ok()
    }

    pub fn report_checked(
        &mut self,
        lease_id: &str,
        segment: u64,
        exit_code: i32,
        session_lost: bool,
        items: &[String],
    ) -> Result<(), &'static str> {
        if self.phase != Phase::Leased {
            return Err(crate::error_catalog::ILLEGAL_TRANSITION);
        }
        if self.lease_id.as_deref() != Some(lease_id)
            || self.segment != segment
            || !matches!(exit_code, 0 | 1 | 75)
        {
            return Err(crate::error_catalog::INVALID_REPORT);
        }
        self.done_items.extend(items.iter().cloned());
        self.lease_id = None;
        if session_lost || exit_code == 75 {
            self.segment += 1;
            self.resume_count += 1;
            if self.segment >= self.max_segs {
                self.phase = Phase::Failed;
                self.reason = Some(
                    crate::error_catalog::reason(crate::error_catalog::MAX_SEGS_EXCEEDED).into(),
                );
            } else {
                self.phase = Phase::Queued;
            }
        } else if exit_code == 0 {
            self.phase = Phase::Done;
        } else {
            self.phase = Phase::Failed;
            self.reason =
                Some(crate::error_catalog::reason(crate::error_catalog::SEGMENT_FAILED).into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run32_every_phase_event_pair() {
        use crate::error_catalog as codes;
        let phases = [
            Phase::Queued,
            Phase::Leased,
            Phase::Done,
            Phase::Failed,
            Phase::FloorStopped,
        ];
        // Event, required phase, resulting phase, result, assignment, exit, lost, cap.
        let events = [
            (
                "assign",
                Phase::Queued,
                Phase::Leased,
                Ok(()),
                true,
                0,
                false,
                3,
            ),
            (
                "floor",
                Phase::Queued,
                Phase::FloorStopped,
                Err(codes::CU_FLOOR),
                true,
                0,
                false,
                3,
            ),
            (
                "assign-cap",
                Phase::Queued,
                Phase::Failed,
                Err(codes::MAX_SEGS_EXCEEDED),
                true,
                0,
                false,
                0,
            ),
            (
                "success",
                Phase::Leased,
                Phase::Done,
                Ok(()),
                false,
                0,
                false,
                3,
            ),
            (
                "failure",
                Phase::Leased,
                Phase::Failed,
                Ok(()),
                false,
                1,
                false,
                3,
            ),
            (
                "resume",
                Phase::Leased,
                Phase::Queued,
                Ok(()),
                false,
                75,
                false,
                3,
            ),
            (
                "lost",
                Phase::Leased,
                Phase::Queued,
                Ok(()),
                false,
                1,
                true,
                3,
            ),
            (
                "report-cap",
                Phase::Leased,
                Phase::Failed,
                Ok(()),
                false,
                75,
                false,
                1,
            ),
            (
                "bad-exit",
                Phase::Leased,
                Phase::Leased,
                Err(codes::INVALID_REPORT),
                false,
                2,
                false,
                3,
            ),
            (
                "wrong-lease",
                Phase::Leased,
                Phase::Leased,
                Err(codes::INVALID_REPORT),
                false,
                0,
                false,
                3,
            ),
            (
                "wrong-segment",
                Phase::Leased,
                Phase::Leased,
                Err(codes::INVALID_REPORT),
                false,
                0,
                false,
                3,
            ),
            (
                "bad-balance",
                Phase::Queued,
                Phase::Queued,
                Err(codes::BAD_SPEC),
                true,
                0,
                false,
                3,
            ),
        ];
        let mut pairs = 0;
        for phase in phases {
            for (event, required, next, outcome, assign, exit, lost, cap) in &events {
                let mut job = Lifecycle::new(*cap);
                job.phase = phase.clone();
                job.lease_id = (phase == Phase::Leased).then(|| "lease-1".into());
                job.done_items.insert("retained".into());
                let before = serde_json::to_value(&job).unwrap();
                let result = if *assign {
                    job.assign_checked(
                        "lease-2".into(),
                        if *event == "floor" {
                            5.1
                        } else if *event == "bad-balance" {
                            f64::NAN
                        } else {
                            9.0
                        },
                        5.0,
                    )
                } else {
                    job.report_checked(
                        if *event == "wrong-lease" {
                            "other"
                        } else {
                            "lease-1"
                        },
                        u64::from(*event == "wrong-segment"),
                        *exit,
                        *lost,
                        &["new".into()],
                    )
                };
                let expected = if phase == *required {
                    *outcome
                } else {
                    Err(codes::ILLEGAL_TRANSITION)
                };
                assert_eq!(result, expected, "{phase:?}/{event}");
                let expected_phase = if phase == *required { next } else { &phase };
                assert_eq!(&job.phase, expected_phase, "{phase:?}/{event}");
                if let Err(code) = result {
                    assert_eq!(codes::canonical_code(code), code);
                }
                if expected_phase == &phase && result.is_err() {
                    assert_eq!(
                        serde_json::to_value(&job).unwrap(),
                        before,
                        "{phase:?}/{event}"
                    );
                }
                pairs += 1;
            }
        }
        assert_eq!(pairs, 60);
    }
    #[test]
    fn floor_stops_only_at_boundary() {
        let mut job = Lifecycle::new(5);
        assert!(job.assign("lease-1".into(), 6.0, 5.0));
        assert!(job.report("lease-1", 0, 75, false, &["one".into()]));
        assert!(!job.assign("lease-2".into(), 5.1, 5.0));
        assert_eq!(job.phase, Phase::FloorStopped);
        assert!(job.done_items.contains("one"));
    }
    #[test]
    fn three_resumes_then_success() {
        let mut job = Lifecycle::new(5);
        for segment in 0..3 {
            assert!(job.assign(format!("lease-{segment}"), 9.0, 5.0));
            assert!(job.report(
                &format!("lease-{segment}"),
                segment,
                75,
                false,
                &[format!("item-{segment}")]
            ));
        }
        assert!(job.assign("lease-3".into(), 9.0, 5.0));
        assert!(job.report("lease-3", 3, 0, false, &["item-0".into()]));
        assert_eq!(job.phase, Phase::Done);
        assert_eq!(job.resume_count, 3);
        assert_eq!(job.done_items.len(), 3);
    }
    #[test]
    fn lost_session_preserves_unique_done_items() {
        let mut job = Lifecycle::new(3);
        assert!(job.assign("lease-1".into(), 9.0, 5.0));
        assert!(job.report("lease-1", 0, 1, true, &["a".into(), "a".into()]));
        assert!(job.assign("lease-2".into(), 9.0, 5.0));
        assert_eq!(job.done_items.len(), 1);
        assert_eq!(job.resume_count, 1);
    }
    #[test]
    fn max_segments_fails_with_reason() {
        let mut job = Lifecycle::new(1);
        assert!(job.assign("lease-1".into(), 9.0, 5.0));
        assert!(job.report("lease-1", 0, 75, false, &[]));
        assert_eq!(job.phase, Phase::Failed);
        assert_eq!(
            job.reason.as_deref(),
            Some(crate::error_catalog::MAX_SEGS_EXCEEDED)
        );
    }
    #[test]
    fn duplicate_or_wrong_report_is_refused() {
        let mut job = Lifecycle::new(3);
        assert!(job.assign("lease-1".into(), 9.0, 5.0));
        assert!(!job.assign("lease-2".into(), 9.0, 5.0));
        assert!(!job.report("lease-2", 0, 0, false, &[]));
        assert!(job.report("lease-1", 0, 0, false, &[]));
        assert!(!job.report("lease-1", 0, 0, false, &[]));
    }
}

/// Ledger-backed transitions for a single job. The caller serializes access and
/// supplies the current balance and timestamp from its clock and state source.
#[derive(Clone, Debug)]
pub struct ManagedLifecycle {
    pub lifecycle: Lifecycle,
    pub last_balance: f64,
}

/// Data shared by one boundary transition and its ledger records.
pub struct Boundary<'a> {
    pub root: &'a std::path::Path,
    pub job_id: &'a str,
    pub ts: &'a str,
    pub balance: f64,
    pub floor: f64,
    pub gpu_class: &'a str,
}

impl ManagedLifecycle {
    pub fn new(max_segs: u64, admission_balance: f64) -> Self {
        Self {
            lifecycle: Lifecycle::new(max_segs),
            last_balance: admission_balance,
        }
    }

    fn record(
        &self,
        b: &Boundary<'_>,
        segment: u64,
        event: &str,
        reason: &str,
    ) -> std::io::Result<()> {
        crate::cu_ledger::append(
            b.root,
            &crate::cu_ledger::Entry {
                ts: b.ts,
                job_id: b.job_id,
                segment,
                event,
                balance: b.balance,
                delta: b.balance - self.last_balance,
                floor: b.floor,
                gpu_class: b.gpu_class,
                reason,
            },
        )
    }

    pub fn assign(&mut self, b: &Boundary<'_>, lease: String) -> std::io::Result<bool> {
        let mut next = self.lifecycle.clone();
        let assigned = next.assign(lease, b.balance, b.floor);
        if next.phase == self.lifecycle.phase {
            return Ok(false);
        }
        let (event, reason) = if assigned {
            ("segment-start", "")
        } else if next.phase == Phase::FloorStopped {
            ("stop-floor", crate::error_catalog::CU_FLOOR)
        } else {
            ("failed", crate::error_catalog::MAX_SEGS_EXCEEDED)
        };
        self.record(b, next.segment, event, reason)?;
        self.last_balance = b.balance;
        self.lifecycle = next;
        Ok(assigned)
    }

    /// Record a fresh pushed balance while a lease is active.
    pub fn poll(&mut self, b: &Boundary<'_>, lease: &str) -> std::io::Result<bool> {
        if self.lifecycle.phase != Phase::Leased
            || self.lifecycle.lease_id.as_deref() != Some(lease)
        {
            return Ok(false);
        }
        self.record(b, self.lifecycle.segment, "poll", "")?;
        self.last_balance = b.balance;
        Ok(true)
    }

    pub fn report(
        &mut self,
        b: &Boundary<'_>,
        lease: &str,
        segment: u64,
        exit: i32,
        lost: bool,
        items: &[String],
    ) -> std::io::Result<bool> {
        let mut next = self.lifecycle.clone();
        if !next.report(lease, segment, exit, lost, items) {
            return Ok(false);
        }
        let (event, reason) = match next.phase {
            Phase::Queued => ("resume", if lost { "session-lost" } else { "exit-75" }),
            Phase::Done => ("done", ""),
            Phase::Failed => (
                "failed",
                next.reason
                    .as_deref()
                    .unwrap_or(crate::error_catalog::SEGMENT_FAILED),
            ),
            _ => unreachable!(),
        };
        self.record(b, segment, "segment-end", "")?;
        let previous_balance = self.last_balance;
        self.last_balance = b.balance;
        if let Err(err) = self.record(b, segment, event, reason) {
            self.last_balance = previous_balance;
            return Err(err);
        }
        self.lifecycle = next;
        Ok(true)
    }
}

#[cfg(test)]
mod managed_tests {
    use super::*;
    use std::{fs, path::PathBuf};
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "managed-{}-{:?}",
            std::process::id(),
            (
                std::thread::current().id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
        ))
    }
    fn boundary(root: &std::path::Path, balance: f64) -> Boundary<'_> {
        Boundary {
            root,
            job_id: "job-123",
            ts: "2026-10-31T12:00:00Z",
            balance,
            floor: 5.0,
            gpu_class: "l4",
        }
    }
    #[test]
    fn managed_boundary_stops_after_report_and_records_delta() {
        let root = root();
        let mut m = ManagedLifecycle::new(5, 8.0);
        assert!(m.assign(&boundary(&root, 7.0), "lease-1".into()).unwrap());
        assert!(m
            .report(
                &boundary(&root, 5.1),
                "lease-1",
                0,
                75,
                false,
                &["a".into()]
            )
            .unwrap());
        assert!(!m.assign(&boundary(&root, 5.1), "lease-2".into()).unwrap());
        assert_eq!(m.lifecycle.phase, Phase::FloorStopped);
        let rows = fs::read_to_string(root.join("job-123/cu.csv")).unwrap();
        assert!(rows.contains("\"segment-start\",7,-1,5"));
        assert!(rows.contains("\"stop-floor\""));
    }
    #[test]
    fn managed_three_resumes_then_done() {
        let root = root();
        let mut m = ManagedLifecycle::new(5, 9.0);
        let b = boundary(&root, 9.0);
        for i in 0..3 {
            let lease = format!("lease-{i}");
            assert!(m.assign(&b, lease.clone()).unwrap());
            assert!(m
                .report(&b, &lease, i, 75, false, &[format!("item-{i}")])
                .unwrap());
        }
        assert!(m.assign(&b, "lease-3".into()).unwrap());
        assert!(m.report(&b, "lease-3", 3, 0, false, &[]).unwrap());
        assert_eq!(m.lifecycle.resume_count, 3);
        assert_eq!(m.lifecycle.phase, Phase::Done);
        assert_eq!(m.lifecycle.done_items.len(), 3);
    }
    #[test]
    fn managed_lost_session_deduplicates() {
        let root = root();
        let b = boundary(&root, 9.0);
        let mut m = ManagedLifecycle::new(3, 9.0);
        m.assign(&b, "lease-1".into()).unwrap();
        m.report(&b, "lease-1", 0, 1, true, &["a".into(), "a".into()])
            .unwrap();
        assert_eq!(m.lifecycle.done_items.len(), 1);
        assert_eq!(m.lifecycle.phase, Phase::Queued);
    }
    #[test]
    fn managed_limit_and_duplicate_report() {
        let root = root();
        let b = boundary(&root, 9.0);
        let mut m = ManagedLifecycle::new(1, 9.0);
        m.assign(&b, "lease-1".into()).unwrap();
        assert!(m.report(&b, "lease-1", 0, 75, false, &[]).unwrap());
        assert!(!m.report(&b, "lease-1", 0, 75, false, &[]).unwrap());
        assert_eq!(
            m.lifecycle.reason.as_deref(),
            Some(crate::error_catalog::MAX_SEGS_EXCEEDED)
        );
        assert_eq!(
            fs::read_to_string(root.join("job-123/cu.csv"))
                .unwrap()
                .lines()
                .count(),
            4
        );
    }
    #[test]
    fn managed_write_failure_does_not_change_state() {
        let root = root();
        fs::write(&root, b"file").unwrap();
        let b = boundary(&root, 9.0);
        let mut m = ManagedLifecycle::new(3, 9.0);
        assert!(m.assign(&b, "lease-1".into()).is_err());
        assert_eq!(m.lifecycle.phase, Phase::Queued);
        assert_eq!(m.last_balance, 9.0);
    }
    #[test]
    fn poll_and_segment_end_record_order_and_deltas() {
        let root = root();
        let mut m = ManagedLifecycle::new(3, 9.0);
        m.assign(&boundary(&root, 8.0), "lease-1".into()).unwrap();
        assert!(m.poll(&boundary(&root, 7.5), "lease-1").unwrap());
        assert!(m
            .report(&boundary(&root, 7.0), "lease-1", 0, 75, false, &[])
            .unwrap());
        let rows = fs::read_to_string(root.join("job-123/cu.csv")).unwrap();
        let lines: Vec<_> = rows.lines().collect();
        assert!(lines[2].contains("\"poll\",7.5,-0.5"));
        assert!(lines[3].contains("\"segment-end\",7,-0.5"));
        assert!(lines[4].contains("\"resume\",7,0"));
    }
    #[test]
    fn poll_rejects_wrong_or_finished_lease() {
        let root = root();
        let b = boundary(&root, 9.0);
        let mut m = ManagedLifecycle::new(3, 9.0);
        assert!(!m.poll(&b, "lease-1").unwrap());
        m.assign(&b, "lease-1".into()).unwrap();
        assert!(!m.poll(&b, "lease-2").unwrap());
        m.report(&b, "lease-1", 0, 0, false, &[]).unwrap();
        assert!(!m.poll(&b, "lease-1").unwrap());
        assert_eq!(
            fs::read_to_string(root.join("job-123/cu.csv"))
                .unwrap()
                .lines()
                .count(),
            4
        );
    }
    #[test]
    fn poll_write_failure_preserves_balance() {
        let root = root();
        let mut m = ManagedLifecycle::new(3, 9.0);
        m.lifecycle.assign("lease-1".into(), 9.0, 5.0);
        fs::write(&root, b"file").unwrap();
        assert!(m.poll(&boundary(&root, 8.0), "lease-1").is_err());
        assert_eq!(m.last_balance, 9.0);
    }
}

/// Serializes ownership and ledger transitions for all managed jobs.
#[derive(Default)]
pub struct LeaseManager {
    jobs: std::sync::Mutex<std::collections::BTreeMap<String, ManagedLifecycle>>,
}

impl LeaseManager {
    pub fn insert(&self, id: String, max_segs: u64, balance: f64) -> bool {
        use std::collections::btree_map::Entry;
        let mut jobs = self.jobs.lock().unwrap();
        if let Entry::Vacant(slot) = jobs.entry(id) {
            slot.insert(ManagedLifecycle::new(max_segs, balance));
            true
        } else {
            false
        }
    }

    pub fn assign(&self, b: &Boundary<'_>, lease: String) -> std::io::Result<bool> {
        match self.jobs.lock().unwrap().get_mut(b.job_id) {
            Some(job) => job.assign(b, lease),
            None => Ok(false),
        }
    }

    /// Select the first eligible queued job and assign it under the same lock.
    /// The caller supplies candidates in queue order after checking lane and worker
    /// eligibility. A stopped or failed candidate does not hide later work.
    pub fn assign_next(
        &self,
        candidates: &[String],
        b: &Boundary<'_>,
        lease: &str,
    ) -> std::io::Result<Option<(String, Lifecycle)>> {
        let mut jobs = self.jobs.lock().unwrap();
        for id in candidates {
            let Some(job) = jobs.get_mut(id) else {
                continue;
            };
            let boundary = Boundary { job_id: id, ..*b };
            if job.assign(&boundary, lease.to_owned())? {
                return Ok(Some((id.clone(), job.lifecycle.clone())));
            }
        }
        Ok(None)
    }

    pub fn report(
        &self,
        b: &Boundary<'_>,
        lease: &str,
        segment: u64,
        exit: i32,
        lost: bool,
        items: &[String],
    ) -> std::io::Result<bool> {
        match self.jobs.lock().unwrap().get_mut(b.job_id) {
            Some(job) => job.report(b, lease, segment, exit, lost, items),
            None => Ok(false),
        }
    }

    /// Reclaim only after the caller has confirmed that the session is lost.
    /// This does not interrupt a running lease.
    pub fn reclaim(&self, b: &Boundary<'_>, lease: &str) -> std::io::Result<bool> {
        let mut jobs = self.jobs.lock().unwrap();
        let Some(job) = jobs.get_mut(b.job_id) else {
            return Ok(false);
        };
        let segment = job.lifecycle.segment;
        job.report(b, lease, segment, 1, true, &[])
    }

    pub fn snapshot(&self, id: &str) -> Option<Lifecycle> {
        self.jobs
            .lock()
            .unwrap()
            .get(id)
            .map(|job| job.lifecycle.clone())
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;
    use std::path::{Path, PathBuf};
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "manager-{}-{:?}",
            std::process::id(),
            (
                std::thread::current().id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
        ))
    }
    fn boundary(root: &Path, balance: f64) -> Boundary<'_> {
        Boundary {
            root,
            job_id: "job-123",
            ts: "2026-10-31T12:00:00Z",
            balance,
            floor: 5.0,
            gpu_class: "l4",
        }
    }
    #[test]
    fn floor_stops_at_boundary() {
        let root = root();
        let m = LeaseManager::default();
        m.insert("job-123".into(), 4, 8.0);
        assert!(m.assign(&boundary(&root, 8.0), "lease-1".into()).unwrap());
        assert!(m
            .report(&boundary(&root, 5.1), "lease-1", 0, 75, false, &[])
            .unwrap());
        assert!(!m.assign(&boundary(&root, 5.1), "lease-2".into()).unwrap());
        assert_eq!(m.snapshot("job-123").unwrap().phase, Phase::FloorStopped);
    }
    #[test]
    fn three_resumes_keep_one_record() {
        let root = root();
        let b = boundary(&root, 9.0);
        let m = LeaseManager::default();
        assert!(m.insert("job-123".into(), 5, 9.0));
        assert!(!m.insert("job-123".into(), 5, 9.0));
        for i in 0..4 {
            let lease = format!("lease-{i}");
            assert!(m.assign(&b, lease.clone()).unwrap());
            assert!(m
                .report(
                    &b,
                    &lease,
                    i,
                    if i == 3 { 0 } else { 75 },
                    false,
                    &[format!("item-{i}")]
                )
                .unwrap());
        }
        let job = m.snapshot("job-123").unwrap();
        assert_eq!(job.phase, Phase::Done);
        assert_eq!(job.resume_count, 3);
    }
    #[test]
    fn lost_session_preserves_unique_items() {
        let root = root();
        let b = boundary(&root, 9.0);
        let m = LeaseManager::default();
        m.insert("job-123".into(), 3, 9.0);
        m.assign(&b, "lease-1".into()).unwrap();
        m.report(&b, "lease-1", 0, 1, true, &["one".into(), "one".into()])
            .unwrap();
        m.assign(&b, "lease-2".into()).unwrap();
        assert_eq!(m.snapshot("job-123").unwrap().done_items.len(), 1);
    }
    #[test]
    fn segment_limit_has_reason() {
        let root = root();
        let b = boundary(&root, 9.0);
        let m = LeaseManager::default();
        m.insert("job-123".into(), 1, 9.0);
        m.assign(&b, "lease-1".into()).unwrap();
        m.report(&b, "lease-1", 0, 75, false, &[]).unwrap();
        assert_eq!(
            m.snapshot("job-123").unwrap().reason.as_deref(),
            Some(crate::error_catalog::MAX_SEGS_EXCEEDED)
        );
    }
    #[test]
    fn concurrent_agents_cannot_share_a_job() {
        let root = root();
        let m = std::sync::Arc::new(LeaseManager::default());
        m.insert("job-123".into(), 3, 9.0);
        let handles: Vec<_> = (0..2)
            .map(|i| {
                let m = m.clone();
                let root = root.clone();
                std::thread::spawn(move || {
                    m.assign(&boundary(&root, 9.0), format!("lease-{i}"))
                        .unwrap()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap() as usize)
                .sum::<usize>(),
            1
        );
    }
    #[test]
    fn queue_selects_first_available_candidate() {
        let root = root();
        let m = LeaseManager::default();
        m.insert("job-123".into(), 3, 9.0);
        m.insert("job-234".into(), 3, 9.0);
        let ids = vec!["missing".into(), "job-123".into(), "job-234".into()];
        assert_eq!(
            m.assign_next(&ids, &boundary(&root, 9.0), "lease-1")
                .unwrap()
                .unwrap()
                .0,
            "job-123"
        );
        assert_eq!(
            m.assign_next(&ids, &boundary(&root, 9.0), "lease-2")
                .unwrap()
                .unwrap()
                .0,
            "job-234"
        );
        assert!(m
            .assign_next(&ids, &boundary(&root, 9.0), "lease-3")
            .unwrap()
            .is_none());
    }
    #[test]
    fn queue_records_each_selected_job_in_its_own_ledger() {
        let root = root();
        let m = LeaseManager::default();
        m.insert("job-234".into(), 3, 9.0);
        m.assign_next(&["job-234".into()], &boundary(&root, 8.0), "lease-1")
            .unwrap();
        let rows = std::fs::read_to_string(root.join("job-234/cu.csv")).unwrap();
        assert!(rows.contains("\"job-234\",0,\"segment-start\",8,-1"));
    }
    #[test]
    fn queue_floor_stop_does_not_issue_a_lease() {
        let root = root();
        let m = LeaseManager::default();
        m.insert("job-123".into(), 3, 9.0);
        assert!(m
            .assign_next(&["job-123".into()], &boundary(&root, 5.1), "lease-1")
            .unwrap()
            .is_none());
        assert_eq!(m.snapshot("job-123").unwrap().phase, Phase::FloorStopped);
    }
    #[test]
    fn queue_assignment_propagates_ledger_failure_without_leasing() {
        let root = root();
        std::fs::write(&root, b"file").unwrap();
        let m = LeaseManager::default();
        m.insert("job-123".into(), 3, 9.0);
        assert!(m
            .assign_next(&["job-123".into()], &boundary(&root, 9.0), "lease-1")
            .is_err());
        assert_eq!(m.snapshot("job-123").unwrap().phase, Phase::Queued);
    }
    #[test]
    fn concurrent_queue_polls_never_share_a_job() {
        let root = root();
        let m = std::sync::Arc::new(LeaseManager::default());
        m.insert("job-123".into(), 3, 9.0);
        let handles: Vec<_> = (0..2)
            .map(|i| {
                let m = m.clone();
                let root = root.clone();
                std::thread::spawn(move || {
                    m.assign_next(
                        &["job-123".into()],
                        &boundary(&root, 9.0),
                        &format!("lease-{i}"),
                    )
                    .unwrap()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap().is_some()))
                .sum::<usize>(),
            1
        );
    }
}

#[cfg(test)]
mod admitted_queue_tests {
    use super::Phase;
    use crate::JobTable;
    use serde_json::json;

    #[test]
    fn admission_preserves_queue_order_and_specs() {
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(json!({"job_id":"job-234","max_segs":3,"lane":"tts"}), 12.0));
        assert!(table.enqueue_agent(json!({"job_id":"job-123","max_segs":4,"lane":"stt"}), 11.0));
        assert_eq!(table.agent_queue, ["job-234", "job-123"]);
        assert_eq!(table.jobs["job-234"]["spec"]["lane"], "tts");
    }

    #[test]
    fn duplicate_admission_preserves_original_job_and_lease() {
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(json!({"job_id":"job-123","max_segs":3}), 12.0));
        assert!(!table.enqueue_agent(json!({"job_id":"job-123","max_segs":9}), 1.0));
        assert_eq!(table.agent_queue.len(), 1);
        assert_eq!(table.jobs["job-123"]["spec"]["max_segs"], 3);
        assert_eq!(table.leases.snapshot("job-123").unwrap().max_segs, 3);
    }

    #[test]
    fn admission_initializes_serialized_lifecycle() {
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(json!({"job_id":"job-123","max_segs":4}), 12.0));
        let state = table.leases.snapshot("job-123").unwrap();
        assert_eq!(state.phase, Phase::Queued);
        assert_eq!(state.segment, 0);
        assert_eq!(state.max_segs, 4);
        assert!(state.done_items.is_empty());
    }

    #[test]
    fn invalid_admission_does_not_create_partial_queue_entry() {
        let mut table = JobTable::default();
        assert!(!table.enqueue_agent(json!({"job_id":"job-123"}), 12.0));
        assert!(table.jobs.is_empty());
        assert!(table.agent_queue.is_empty());
        assert!(table.leases.snapshot("job-123").is_none());
    }
}
