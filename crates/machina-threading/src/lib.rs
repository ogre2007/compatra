#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug)]
pub struct PendingGuestThread<C> {
    pub thread_id: u64,
    pub entry: u64,
    pub arg: u64,
    pub stack_top: u64,
    pub exit_pc: u64,
    pub resume: Option<C>,
}

#[derive(Clone, Debug)]
pub struct ActiveGuestThread<C> {
    pub thread_id: u64,
    pub parent_thread_id: u64,
    pub parent: C,
    pub exit_action: GuestThreadExitAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestThreadExitAction {
    ReturnChildResult,
    ReturnValue(u64),
    StoreResultAndReturn { result_addr: u64, return_value: u64 },
}

#[derive(Clone, Debug)]
pub struct ForkParentResume<C> {
    pub parent_tid: u64,
    pub child_pid: u64,
    pub context: C,
}

#[derive(Clone, Debug)]
pub struct WaitingGuestThread<C> {
    pub thread_id: u64,
    pub mutex: u64,
    pub pending: PendingGuestThread<C>,
}

#[derive(Clone, Debug)]
pub struct GuestThreadDispatch<C> {
    pub thread_id: u64,
    pub parent_thread_id: u64,
    pub next: PendingGuestThread<C>,
}

#[derive(Clone, Debug)]
pub struct GuestThreadSwitch<C> {
    pub from_thread_id: u64,
    pub to_thread_id: u64,
    pub next: PendingGuestThread<C>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CondWake {
    pub cond: u64,
    pub thread_id: u64,
    pub remaining_waiters: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CondSignal {
    pub woken_thread_id: Option<u64>,
    pub pending_signals: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestThreadReservation {
    pub thread_id: u64,
    pub stack_base: u64,
    pub stack_top: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestThreadCreateError {
    ThreadLimitReached,
}

#[derive(Debug)]
pub struct GuestThreadRuntime<C> {
    pub next_thread_id: u64,
    pub current_thread_id: u64,
    pub next_stack_base: u64,
    pub pending_threads: VecDeque<PendingGuestThread<C>>,
    pub active_thread: Option<ActiveGuestThread<C>>,
    pub cond_wait_streaks: HashMap<(u64, u64), u32>,
    pub cond_signal_counts: HashMap<u64, u32>,
    pub mutex_owners: HashMap<u64, u64>,
    pub cond_waiters: HashMap<u64, VecDeque<WaitingGuestThread<C>>>,
    pub fork_parent_resumes: HashMap<u64, ForkParentResume<C>>,
    pub completed_threads: HashMap<u64, u64>,
}

impl<C> Default for GuestThreadRuntime<C> {
    fn default() -> Self {
        Self {
            next_thread_id: 0,
            current_thread_id: 0,
            next_stack_base: 0,
            pending_threads: VecDeque::new(),
            active_thread: None,
            cond_wait_streaks: HashMap::new(),
            cond_signal_counts: HashMap::new(),
            mutex_owners: HashMap::new(),
            cond_waiters: HashMap::new(),
            fork_parent_resumes: HashMap::new(),
            completed_threads: HashMap::new(),
        }
    }
}

impl<C> GuestThreadRuntime<C> {
    pub fn has_runnable_guest_threads(&self) -> bool {
        !self.pending_threads.is_empty()
    }

    pub fn enqueue_pending(&mut self, pending: PendingGuestThread<C>) {
        self.pending_threads.push_back(pending);
    }

    pub fn enqueue_pending_front(&mut self, pending: PendingGuestThread<C>) {
        self.pending_threads.push_front(pending);
    }

    pub fn pop_next_pending(&mut self) -> Option<PendingGuestThread<C>> {
        self.pending_threads.pop_front()
    }

    pub fn remove_pending_by_id(&mut self, thread_id: u64) -> Option<PendingGuestThread<C>> {
        let index = self
            .pending_threads
            .iter()
            .position(|thread| thread.thread_id == thread_id)?;
        self.pending_threads.remove(index)
    }

    pub fn activate_thread(&mut self, thread_id: u64, parent_thread_id: u64, parent: C) {
        self.activate_thread_with_exit_action(
            thread_id,
            parent_thread_id,
            parent,
            GuestThreadExitAction::ReturnChildResult,
        );
    }

    pub fn activate_thread_with_exit_action(
        &mut self,
        thread_id: u64,
        parent_thread_id: u64,
        parent: C,
        exit_action: GuestThreadExitAction,
    ) {
        self.current_thread_id = thread_id;
        self.active_thread = Some(ActiveGuestThread {
            thread_id,
            parent_thread_id,
            parent,
            exit_action,
        });
    }

    pub fn dispatch_next(&mut self, parent: C) -> Option<GuestThreadDispatch<C>> {
        self.dispatch_next_with_exit_action(parent, GuestThreadExitAction::ReturnChildResult)
    }

    pub fn dispatch_next_with_exit_action(
        &mut self,
        parent: C,
        exit_action: GuestThreadExitAction,
    ) -> Option<GuestThreadDispatch<C>> {
        if self.active_thread.is_some() {
            return None;
        }
        let next = self.pending_threads.pop_front()?;
        let parent_thread_id = if self.current_thread_id == 0 {
            self.current_thread_id = 1;
            1
        } else {
            self.current_thread_id
        };
        self.activate_thread_with_exit_action(
            next.thread_id,
            parent_thread_id,
            parent,
            exit_action,
        );
        Some(GuestThreadDispatch {
            thread_id: next.thread_id,
            parent_thread_id,
            next,
        })
    }

    pub fn dispatch_thread_by_id(
        &mut self,
        thread_id: u64,
        parent: C,
    ) -> Option<GuestThreadDispatch<C>> {
        self.dispatch_thread_by_id_with_exit_action(
            thread_id,
            parent,
            GuestThreadExitAction::ReturnChildResult,
        )
    }

    pub fn dispatch_thread_by_id_with_exit_action(
        &mut self,
        thread_id: u64,
        parent: C,
        exit_action: GuestThreadExitAction,
    ) -> Option<GuestThreadDispatch<C>> {
        if self.active_thread.is_some() {
            return None;
        }
        let next = self.remove_pending_by_id(thread_id)?;
        let parent_thread_id = self.current_thread_id.max(1);
        self.activate_thread_with_exit_action(
            next.thread_id,
            parent_thread_id,
            parent,
            exit_action,
        );
        Some(GuestThreadDispatch {
            thread_id: next.thread_id,
            parent_thread_id,
            next,
        })
    }

    pub fn yield_active_to_next(
        &mut self,
        resume: PendingGuestThread<C>,
    ) -> Option<GuestThreadSwitch<C>> {
        if self.pending_threads.is_empty() {
            return None;
        }
        let active = self.active_thread.take()?;
        let from_thread_id = active.thread_id;
        self.pending_threads.push_back(resume);
        let Some(next) = self.pending_threads.pop_front() else {
            self.active_thread = Some(active);
            return None;
        };

        let to_thread_id = next.thread_id;
        self.activate_thread_with_exit_action(
            to_thread_id,
            active.parent_thread_id,
            active.parent,
            active.exit_action,
        );
        Some(GuestThreadSwitch {
            from_thread_id,
            to_thread_id,
            next,
        })
    }

    pub fn block_active_on_cond(
        &mut self,
        cond: u64,
        mutex: u64,
        pending: PendingGuestThread<C>,
    ) -> Option<GuestThreadSwitch<C>> {
        let active = self.active_thread.take()?;
        let from_thread_id = active.thread_id;
        self.cond_waiters
            .entry(cond)
            .or_default()
            .push_back(WaitingGuestThread {
                thread_id: from_thread_id,
                mutex,
                pending,
            });

        let Some(next) = self.pending_threads.pop_front() else {
            self.active_thread = Some(active);
            if let Some(waiters) = self.cond_waiters.get_mut(&cond) {
                waiters.pop_back();
                if waiters.is_empty() {
                    self.cond_waiters.remove(&cond);
                }
            }
            return None;
        };

        let to_thread_id = next.thread_id;
        self.activate_thread_with_exit_action(
            to_thread_id,
            active.parent_thread_id,
            active.parent,
            active.exit_action,
        );
        Some(GuestThreadSwitch {
            from_thread_id,
            to_thread_id,
            next,
        })
    }

    pub fn block_current_on_cond_and_dispatch(
        &mut self,
        cond: u64,
        mutex: u64,
        pending: PendingGuestThread<C>,
        parent: C,
    ) -> Option<GuestThreadDispatch<C>> {
        if self.active_thread.is_some() || self.pending_threads.is_empty() {
            return None;
        }
        let thread_id = pending.thread_id;
        self.cond_waiters
            .entry(cond)
            .or_default()
            .push_back(WaitingGuestThread {
                thread_id,
                mutex,
                pending,
            });

        let dispatch = self.dispatch_next(parent);
        if dispatch.is_none() {
            if let Some(waiters) = self.cond_waiters.get_mut(&cond) {
                waiters.pop_back();
                if waiters.is_empty() {
                    self.cond_waiters.remove(&cond);
                }
            }
        }
        dispatch
    }

    pub fn reserve_guest_thread(
        &mut self,
        stack_size: u64,
        max_synthetic_threads: u64,
    ) -> Result<GuestThreadReservation, GuestThreadCreateError> {
        let thread_id = self.reserve_thread_id(max_synthetic_threads)?;
        let stack_base = self.next_stack_base;
        self.next_stack_base = self.next_stack_base.saturating_add(stack_size);
        Ok(GuestThreadReservation {
            thread_id,
            stack_base,
            stack_top: stack_base.saturating_add(stack_size).saturating_sub(0x100),
        })
    }

    pub fn reserve_thread_id(
        &mut self,
        max_synthetic_threads: u64,
    ) -> Result<u64, GuestThreadCreateError> {
        if self.next_thread_id > max_synthetic_threads.saturating_add(1) {
            return Err(GuestThreadCreateError::ThreadLimitReached);
        }
        let thread_id = self.next_thread_id;
        self.next_thread_id = self.next_thread_id.saturating_add(1);
        Ok(thread_id)
    }

    pub fn enqueue_thread_start(
        &mut self,
        reservation: GuestThreadReservation,
        entry: u64,
        arg: u64,
        exit_pc: u64,
    ) {
        self.enqueue_pending(PendingGuestThread {
            thread_id: reservation.thread_id,
            entry,
            arg,
            stack_top: reservation.stack_top,
            exit_pc,
            resume: None,
        });
    }

    pub fn record_thread_completion(&mut self, thread_id: u64, result: u64) {
        self.completed_threads.insert(thread_id, result);
    }

    pub fn take_thread_completion(&mut self, thread_id: u64) -> Option<u64> {
        self.completed_threads.remove(&thread_id)
    }

    pub fn consume_cond_signal(&mut self, cond: u64, mutex: u64, thread_id: u64) -> bool {
        let signaled = self
            .cond_signal_counts
            .get_mut(&cond)
            .map(|count| {
                if *count > 0 {
                    *count -= 1;
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false);
        if signaled {
            self.mutex_owners.insert(mutex, thread_id);
        }
        signaled
    }

    pub fn signal_cond(&mut self, cond: u64) -> CondSignal {
        if let Some(wake) = wake_one_cond_waiter_for(self, cond) {
            return CondSignal {
                woken_thread_id: Some(wake.thread_id),
                pending_signals: wake.remaining_waiters as u32,
            };
        }
        let pending_signals = self
            .cond_signal_counts
            .entry(cond)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        CondSignal {
            woken_thread_id: None,
            pending_signals: *pending_signals,
        }
    }

    pub fn broadcast_cond(&mut self, cond: u64) -> Vec<CondWake> {
        wake_cond_waiters_for(self, cond, usize::MAX)
    }
}

pub fn wake_one_cond_waiter_for<C>(
    runtime: &mut GuestThreadRuntime<C>,
    cond: u64,
) -> Option<CondWake> {
    let waiter = runtime.cond_waiters.get_mut(&cond)?.pop_front()?;
    let remaining_waiters = runtime
        .cond_waiters
        .get(&cond)
        .map(|queue| queue.len())
        .unwrap_or(0);
    if remaining_waiters == 0 {
        runtime.cond_waiters.remove(&cond);
    }
    runtime.mutex_owners.insert(waiter.mutex, waiter.thread_id);
    let waiter_tid = waiter.thread_id;
    runtime.pending_threads.push_front(waiter.pending);
    Some(CondWake {
        cond,
        thread_id: waiter_tid,
        remaining_waiters,
    })
}

pub fn wake_one_cond_waiter<C>(runtime: &mut GuestThreadRuntime<C>) -> Option<(u64, u64)> {
    let cond = runtime
        .cond_waiters
        .iter()
        .find_map(|(cond, queue)| (!queue.is_empty()).then_some(*cond))?;
    wake_one_cond_waiter_for(runtime, cond).map(|wake| (wake.cond, wake.thread_id))
}

pub fn wake_cond_waiters_for<C>(
    runtime: &mut GuestThreadRuntime<C>,
    cond: u64,
    limit: usize,
) -> Vec<CondWake> {
    let mut woken = Vec::new();
    while woken.len() < limit {
        let Some(wake) = wake_one_cond_waiter_for(runtime, cond) else {
            break;
        };
        woken.push(wake);
    }
    woken
}

pub fn wake_cond_waiters<C>(runtime: &mut GuestThreadRuntime<C>, limit: usize) -> Vec<(u64, u64)> {
    let mut woken = Vec::new();
    while woken.len() < limit {
        let Some((cond, tid)) = wake_one_cond_waiter(runtime) else {
            break;
        };
        woken.push((cond, tid));
    }
    woken
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(thread_id: u64) -> PendingGuestThread<&'static str> {
        PendingGuestThread {
            thread_id,
            entry: 0,
            arg: 0,
            stack_top: 0,
            exit_pc: 0,
            resume: Some("ctx"),
        }
    }

    #[test]
    fn pending_threads_can_be_removed_by_id_without_reordering_others() {
        let mut runtime = GuestThreadRuntime::default();
        runtime.enqueue_pending(pending(2));
        runtime.enqueue_pending(pending(3));
        runtime.enqueue_pending(pending(4));

        let removed = runtime
            .remove_pending_by_id(3)
            .expect("thread should exist");

        assert_eq!(removed.thread_id, 3);
        assert_eq!(
            runtime
                .pending_threads
                .iter()
                .map(|thread| thread.thread_id)
                .collect::<Vec<_>>(),
            vec![2, 4]
        );
    }

    #[test]
    fn activate_thread_updates_current_thread_and_parent_context() {
        let mut runtime = GuestThreadRuntime::default();

        runtime.activate_thread(7, 1, "parent");

        assert_eq!(runtime.current_thread_id, 7);
        assert_eq!(
            runtime.active_thread.as_ref().map(|active| (
                active.thread_id,
                active.parent_thread_id,
                active.parent
            )),
            Some((7, 1, "parent"))
        );
    }

    #[test]
    fn activate_thread_can_store_custom_exit_action() {
        let mut runtime = GuestThreadRuntime::default();

        runtime.activate_thread_with_exit_action(
            7,
            1,
            "parent",
            GuestThreadExitAction::StoreResultAndReturn {
                result_addr: 0x4000,
                return_value: 0,
            },
        );

        assert_eq!(
            runtime
                .active_thread
                .as_ref()
                .map(|active| active.exit_action),
            Some(GuestThreadExitAction::StoreResultAndReturn {
                result_addr: 0x4000,
                return_value: 0
            })
        );
    }

    #[test]
    fn completed_thread_results_are_consumed_once() {
        let mut runtime: GuestThreadRuntime<&'static str> = GuestThreadRuntime::default();

        runtime.record_thread_completion(3, 0xCAFE);

        assert_eq!(runtime.take_thread_completion(3), Some(0xCAFE));
        assert_eq!(runtime.take_thread_completion(3), None);
    }

    #[test]
    fn waking_cond_waiter_requeues_thread_and_assigns_mutex_owner() {
        let mut runtime = GuestThreadRuntime::default();
        runtime
            .cond_waiters
            .entry(0x100)
            .or_default()
            .push_back(WaitingGuestThread {
                thread_id: 7,
                mutex: 0x200,
                pending: pending(7),
            });

        assert_eq!(wake_one_cond_waiter(&mut runtime), Some((0x100, 7)));
        assert_eq!(runtime.mutex_owners.get(&0x200), Some(&7));
        assert_eq!(
            runtime
                .pending_threads
                .front()
                .map(|thread| thread.thread_id),
            Some(7)
        );
        assert!(!runtime.cond_waiters.contains_key(&0x100));
    }

    #[test]
    fn wake_cond_waiters_obeys_limit() {
        let mut runtime = GuestThreadRuntime::default();
        for tid in [2, 3, 4] {
            runtime
                .cond_waiters
                .entry(0x100)
                .or_default()
                .push_back(WaitingGuestThread {
                    thread_id: tid,
                    mutex: 0x200 + tid,
                    pending: pending(tid),
                });
        }

        let woken = wake_cond_waiters(&mut runtime, 2);

        assert_eq!(woken, vec![(0x100, 2), (0x100, 3)]);
        assert_eq!(runtime.pending_threads.len(), 2);
        assert_eq!(runtime.cond_waiters.get(&0x100).map(VecDeque::len), Some(1));
    }

    #[test]
    fn waking_specific_cond_ignores_other_waiters() {
        let mut runtime = GuestThreadRuntime::default();
        runtime
            .cond_waiters
            .entry(0x100)
            .or_default()
            .push_back(WaitingGuestThread {
                thread_id: 2,
                mutex: 0x200,
                pending: pending(2),
            });
        runtime
            .cond_waiters
            .entry(0x101)
            .or_default()
            .push_back(WaitingGuestThread {
                thread_id: 3,
                mutex: 0x300,
                pending: pending(3),
            });

        assert_eq!(
            wake_one_cond_waiter_for(&mut runtime, 0x101),
            Some(CondWake {
                cond: 0x101,
                thread_id: 3,
                remaining_waiters: 0
            })
        );
        assert_eq!(
            runtime
                .pending_threads
                .front()
                .map(|thread| thread.thread_id),
            Some(3)
        );
        assert!(runtime.cond_waiters.contains_key(&0x100));
        assert!(!runtime.cond_waiters.contains_key(&0x101));
    }

    #[test]
    fn signal_cond_requeues_waiter_or_records_pending_signal() {
        let mut runtime = GuestThreadRuntime::default();
        runtime
            .cond_waiters
            .entry(0x100)
            .or_default()
            .push_back(WaitingGuestThread {
                thread_id: 2,
                mutex: 0x200,
                pending: pending(2),
            });

        assert_eq!(
            runtime.signal_cond(0x100),
            CondSignal {
                woken_thread_id: Some(2),
                pending_signals: 0
            }
        );
        assert_eq!(
            runtime.signal_cond(0x100),
            CondSignal {
                woken_thread_id: None,
                pending_signals: 1
            }
        );
    }

    #[test]
    fn consume_cond_signal_claims_one_count_and_mutex() {
        let mut runtime: GuestThreadRuntime<&'static str> = GuestThreadRuntime::default();
        runtime.cond_signal_counts.insert(0x100, 2);

        assert!(runtime.consume_cond_signal(0x100, 0x200, 7));
        assert_eq!(runtime.cond_signal_counts.get(&0x100), Some(&1));
        assert_eq!(runtime.mutex_owners.get(&0x200), Some(&7));

        assert!(!runtime.consume_cond_signal(0x101, 0x300, 8));
        assert!(!runtime.mutex_owners.contains_key(&0x300));
    }

    #[test]
    fn dispatch_next_marks_active_thread_and_preserves_parent() {
        let mut runtime = GuestThreadRuntime::default();
        runtime.current_thread_id = 1;
        runtime.enqueue_pending(pending(2));

        let dispatch = runtime
            .dispatch_next("parent")
            .expect("pending thread should dispatch");

        assert_eq!(dispatch.thread_id, 2);
        assert_eq!(dispatch.parent_thread_id, 1);
        assert_eq!(dispatch.next.thread_id, 2);
        assert_eq!(runtime.current_thread_id, 2);
        assert_eq!(
            runtime.active_thread.as_ref().map(|active| (
                active.thread_id,
                active.parent_thread_id,
                active.parent
            )),
            Some((2, 1, "parent"))
        );
    }

    #[test]
    fn yield_active_requeues_current_thread_and_switches_to_next() {
        let mut runtime = GuestThreadRuntime::default();
        runtime.activate_thread(2, 1, "parent");
        runtime.enqueue_pending(pending(3));

        let switch = runtime
            .yield_active_to_next(pending(2))
            .expect("active thread should yield");

        assert_eq!((switch.from_thread_id, switch.to_thread_id), (2, 3));
        assert_eq!(switch.next.thread_id, 3);
        assert_eq!(runtime.current_thread_id, 3);
        assert_eq!(
            runtime
                .pending_threads
                .iter()
                .map(|thread| thread.thread_id)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(
            runtime.active_thread.as_ref().map(|active| (
                active.thread_id,
                active.parent_thread_id,
                active.parent
            )),
            Some((3, 1, "parent"))
        );
    }

    #[test]
    fn block_active_moves_thread_to_cond_waiters_and_switches() {
        let mut runtime = GuestThreadRuntime::default();
        runtime.activate_thread(2, 1, "parent");
        runtime.enqueue_pending(pending(3));

        let switch = runtime
            .block_active_on_cond(0x100, 0x200, pending(2))
            .expect("active thread should block and switch");

        assert_eq!((switch.from_thread_id, switch.to_thread_id), (2, 3));
        assert_eq!(runtime.current_thread_id, 3);
        assert_eq!(
            runtime
                .cond_waiters
                .get(&0x100)
                .and_then(|waiters| waiters.front())
                .map(|waiter| (waiter.thread_id, waiter.mutex)),
            Some((2, 0x200))
        );
        assert_eq!(
            runtime.active_thread.as_ref().map(|active| (
                active.thread_id,
                active.parent_thread_id,
                active.parent
            )),
            Some((3, 1, "parent"))
        );
    }

    #[test]
    fn block_active_rolls_back_when_no_thread_can_run() {
        let mut runtime = GuestThreadRuntime::default();
        runtime.activate_thread(2, 1, "parent");

        assert!(runtime
            .block_active_on_cond(0x100, 0x200, pending(2))
            .is_none());
        assert!(!runtime.cond_waiters.contains_key(&0x100));
        assert_eq!(
            runtime.active_thread.as_ref().map(|active| (
                active.thread_id,
                active.parent_thread_id,
                active.parent
            )),
            Some((2, 1, "parent"))
        );
    }

    #[test]
    fn block_current_records_waiter_and_dispatches_next() {
        let mut runtime = GuestThreadRuntime::default();
        runtime.current_thread_id = 1;
        runtime.enqueue_pending(pending(2));

        let dispatch = runtime
            .block_current_on_cond_and_dispatch(0x100, 0x200, pending(1), "parent")
            .expect("pending thread should dispatch");

        assert_eq!(dispatch.thread_id, 2);
        assert_eq!(runtime.current_thread_id, 2);
        assert_eq!(
            runtime
                .cond_waiters
                .get(&0x100)
                .and_then(|waiters| waiters.front())
                .map(|waiter| (waiter.thread_id, waiter.mutex)),
            Some((1, 0x200))
        );
        assert_eq!(
            runtime.active_thread.as_ref().map(|active| (
                active.thread_id,
                active.parent_thread_id,
                active.parent
            )),
            Some((2, 1, "parent"))
        );
    }

    #[test]
    fn reserve_guest_thread_allocates_id_and_stack_range() {
        let mut runtime: GuestThreadRuntime<&'static str> = GuestThreadRuntime {
            next_thread_id: 2,
            next_stack_base: 0x3300_0000,
            ..Default::default()
        };

        let reservation = runtime
            .reserve_guest_thread(0x20_0000, 64)
            .expect("thread should fit synthetic limit");

        assert_eq!(
            reservation,
            GuestThreadReservation {
                thread_id: 2,
                stack_base: 0x3300_0000,
                stack_top: 0x331F_FF00
            }
        );
        assert_eq!(runtime.next_thread_id, 3);
        assert_eq!(runtime.next_stack_base, 0x3320_0000);
    }

    #[test]
    fn reserve_guest_thread_rejects_threads_after_limit() {
        let mut runtime: GuestThreadRuntime<&'static str> = GuestThreadRuntime {
            next_thread_id: 66,
            next_stack_base: 0x3300_0000,
            ..Default::default()
        };

        assert_eq!(
            runtime.reserve_guest_thread(0x20_0000, 64),
            Err(GuestThreadCreateError::ThreadLimitReached)
        );
        assert_eq!(runtime.next_thread_id, 66);
        assert_eq!(runtime.next_stack_base, 0x3300_0000);
    }

    #[test]
    fn reserve_thread_id_advances_without_allocating_stack() {
        let mut runtime: GuestThreadRuntime<&'static str> = GuestThreadRuntime {
            next_thread_id: 4,
            next_stack_base: 0x3300_0000,
            ..Default::default()
        };

        assert_eq!(runtime.reserve_thread_id(64), Ok(4));
        assert_eq!(runtime.next_thread_id, 5);
        assert_eq!(runtime.next_stack_base, 0x3300_0000);
    }

    #[test]
    fn enqueue_thread_start_records_entrypoint_and_argument() {
        let mut runtime: GuestThreadRuntime<&'static str> = GuestThreadRuntime::default();
        let reservation = GuestThreadReservation {
            thread_id: 7,
            stack_base: 0x3300_0000,
            stack_top: 0x331F_FF00,
        };

        runtime.enqueue_thread_start(reservation, 0x1000, 0xCAFE, 0x2000);

        let thread = runtime
            .pending_threads
            .front()
            .expect("thread should be queued");
        assert_eq!(thread.thread_id, 7);
        assert_eq!(thread.entry, 0x1000);
        assert_eq!(thread.arg, 0xCAFE);
        assert_eq!(thread.stack_top, 0x331F_FF00);
        assert_eq!(thread.exit_pc, 0x2000);
        assert!(thread.resume.is_none());
    }
}
