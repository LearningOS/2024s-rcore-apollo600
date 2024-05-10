//!Implementation of [`TaskManager`]
use super::TaskControlBlock;
use crate::config::BIG_STRIDE;
use crate::sync::UPSafeCell;
use crate::task::TaskStatus;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use lazy_static::*;
///A array of `TaskControlBlock` that is thread-safe
pub struct TaskManager {
    ready_queue: VecDeque<Arc<TaskControlBlock>>,
}

/// A simple FIFO scheduler.
impl TaskManager {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    /// Add process back to ready queue
    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        self.ready_queue.push_back(task);
    }
    /// Take a process out of the ready queue
    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        // self.ready_queue.pop_front()
        let suitable_task: Arc<TaskControlBlock>;
        let mut min_stride = usize::MAX;
        let mut suitable_id = 0;

        if self.ready_queue.is_empty() {
            return None;
        }

        for (i, task) in self.ready_queue.iter().enumerate() {
            let task_inner = task.inner_exclusive_access();
            let status = task_inner.task_status;
            let stride = task_inner.stride;
            drop(task_inner);

            if status != TaskStatus::Ready {
                continue;
            }

            if stride < min_stride {
                suitable_id = i;
                min_stride = stride;
            }
        }

        if let Some(task) = self.ready_queue.remove(suitable_id) {
            suitable_task = task;
        } else {
            return None;
        }
        
        let mut task_inner = suitable_task.inner_exclusive_access();
        task_inner.stride += BIG_STRIDE / task_inner.prio;
        drop(task_inner);

        info!("choose pid {}, stride = {}", suitable_task.pid.0, min_stride);
        
        Some(suitable_task)
    }
}

lazy_static! {
    /// TASK_MANAGER instance through lazy_static!
    pub static ref TASK_MANAGER: UPSafeCell<TaskManager> =
        unsafe { UPSafeCell::new(TaskManager::new()) };
}

/// Add process to ready queue
pub fn add_task(task: Arc<TaskControlBlock>) {
    //trace!("kernel: TaskManager::add_task");
    TASK_MANAGER.exclusive_access().add(task);
}

/// Take a process out of the ready queue
pub fn fetch_task() -> Option<Arc<TaskControlBlock>> {
    //trace!("kernel: TaskManager::fetch_task");
    TASK_MANAGER.exclusive_access().fetch()
}
