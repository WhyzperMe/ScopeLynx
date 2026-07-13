use std::{
    cmp::Ordering,
    collections::{BTreeSet, BinaryHeap},
};

use url::Url;

use crate::{engine::canonicalize::canonical_key, model::DiscoverySource};

#[derive(Debug, Clone)]
pub struct RequestTask {
    pub url: Url,
    pub source: DiscoverySource,
    pub depth: usize,
    pub priority: u8,
}

#[derive(Debug, Clone)]
struct QueueEntry {
    task: RequestTask,
    sequence: u64,
}

impl PartialEq for QueueEntry {
    fn eq(&self, other: &Self) -> bool {
        self.task.priority == other.task.priority
            && self.task.depth == other.task.depth
            && self.sequence == other.sequence
    }
}

impl Eq for QueueEntry {}

impl PartialOrd for QueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.task
            .priority
            .cmp(&other.task.priority)
            .then_with(|| other.task.depth.cmp(&self.task.depth))
            .then_with(|| other.sequence.cmp(&self.sequence))
            .then_with(|| other.task.url.as_str().cmp(self.task.url.as_str()))
    }
}

#[derive(Debug)]
pub struct RequestQueue {
    heap: BinaryHeap<QueueEntry>,
    seen: BTreeSet<String>,
    max_seen: usize,
    next_sequence: u64,
    peak: usize,
}

impl RequestQueue {
    #[must_use]
    pub fn new(max_seen: usize) -> Self {
        Self { heap: BinaryHeap::new(), seen: BTreeSet::new(), max_seen, next_sequence: 0, peak: 0 }
    }

    pub fn push(&mut self, task: RequestTask) -> bool {
        if self.seen.len() >= self.max_seen {
            return false;
        }
        let key = canonical_key(&task.url);
        if !self.seen.insert(key) {
            return false;
        }
        let entry = QueueEntry { task, sequence: self.next_sequence };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.heap.push(entry);
        self.peak = self.peak.max(self.heap.len());
        true
    }

    pub fn pop(&mut self) -> Option<RequestTask> {
        self.heap.pop().map(|entry| entry.task)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn peak(&self) -> usize {
        self.peak
    }

    #[must_use]
    pub fn at_capacity(&self) -> bool {
        self.seen.len() >= self.max_seen
    }
}
