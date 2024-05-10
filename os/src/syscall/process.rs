//! Process management syscalls
use alloc::sync::Arc;

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE},
    loader::get_app_data_by_name,
    mm::{translated_refmut, translated_str, MapPermission, VirtPageNum, VirtAddr},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, TaskStatus,
    }, timer::{get_time_ms, get_time_us},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!("kernel::pid[{}] sys_waitpid [{}]", current_task().unwrap().pid.0, pid);
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_get_time",
        current_task().unwrap().pid.0
    );
    
    let ts = translated_refmut(current_user_token(), _ts);
    let usec = get_time_us();
    (*ts).sec = usec / 1_000_000;
    (*ts).usec = usec % 1_000_000;

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!(
        "kernel:pid[{}] sys_task_info",
        current_task().unwrap().pid.0
    );

    let ti = translated_refmut(current_user_token(), _ti);

    // * access current TCB exclusively
    let task = current_task().unwrap();
    let current = task.inner_exclusive_access();
    (*ti).status = current.task_status;
    (*ti).syscall_times = current.syscall_times;
    (*ti).time = get_time_ms() - current.start_time;
    drop(current);
    // * release current TCB manually
    drop(task);

    0
}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_mmap",
        current_task().unwrap().pid.0
    );

    // check _start
    if _start % PAGE_SIZE != 0 {
        error!("_start is not aligned");
        return -1;
    }

    // check _port
    if (_port & !0x7) != 0 ||
        (_port & 0x7) == 0 {
        error!("_port is illegal");
        return -1;
    }

    // form prot
    let mut permission = MapPermission::U;
    if _port & 0x1 != 0 {
        permission |= MapPermission::R;
    }
    if _port & 0x2 != 0 {
        permission |= MapPermission::W;
    }
    if _port & 0x4 != 0 {
        permission |= MapPermission::X;
    }

    // * access task
    let task = current_task().unwrap();
    // * access TCB exclusively
    let mut current = task.inner_exclusive_access();
    let memory_set = &mut current.memory_set;

    // traverse va
    let mut start_addr = _start;
    let end_addr = _start + _len;
    while start_addr < end_addr {
        let vpn = VirtPageNum::from(VirtAddr::from(start_addr));

        // check remap
        if let Some(pte) = memory_set.translate(vpn) {
            if pte.is_valid() {
                error!("remap happened");
                return -1;
            }
        }

        start_addr += PAGE_SIZE;
    }

    // map va
    // mmap(_start.into(), end_addr.into(), permission);
    memory_set.insert_framed_area(_start.into(), end_addr.into(), permission);

    // * drop TCB manually
    drop(current);
    // * drop task manually
    drop(task);
    
    0
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_munmap",
        current_task().unwrap().pid.0
    );

    // check _start
    if _start % PAGE_SIZE != 0 {
        error!("_start is not aligned");
        return -1;
    }

    // * access task
    let task = current_task().unwrap();
    // * access TCB exclusively
    let mut current = task.inner_exclusive_access();
    let memory_set = &mut current.memory_set;    

    // traverse va
    let mut start_addr = _start;
    let end_addr = _start + _len;
    while start_addr < end_addr {
        let vpn = VirtPageNum::from(VirtAddr::from(start_addr));

        // check remap
        if let Some(pte) = memory_set.translate(vpn) {
            if !pte.is_valid() {
                error!("remap happened");
                return -1;
            }
        } else {
            return -1;
        }

        start_addr += PAGE_SIZE;
    }

    // unmap
    memory_set.shrink_to(_start.into(), _start.into());

    // * drop TCB manually
    drop(current);
    // * drop task manually
    drop(task);

    0
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(_path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_spawn",
        current_task().unwrap().pid.0
    );

    let current_task = current_task().unwrap();

    let token = current_user_token();
    let path = translated_str(token, _path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let new_task = current_task.spawn(data);
        let new_pid = new_task.pid.0;
        // modify trap context of new_task, because it returns immediately after switching
        let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
        // we do not have to move to next instruction since we have done it before
        // for child process, fork returns 0
        trap_cx.x[10] = 0;
        // add new task to scheduler
        add_task(new_task);
        new_pid as isize
    } else {
        -1
    }
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    -1
}
