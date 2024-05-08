//! Process management syscalls
use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE, PAGE_SIZE_BITS}, 
    mm::{PageTable, VirtPageNum}, 
    task::{
        change_program_brk, current_task_info, current_user_token, exit_current_and_run_next, suspend_current_and_run_next, TaskStatus
    },
    timer::{get_time_ms, get_time_us},
};

use core::mem::size_of;

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
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    // _ts is in U-Page, kernel should use Task's memory set to access
    // get token -> form page table -> map in kernel page -> access -> unmap

    // 1. get task page table
    let token = current_user_token();
    let user_pg_table = PageTable::from_token(token);
    // debug!("get user page table = {:?}", user_pg_table.root_ppn);
    
    // 2. get ppn
    let start_addr = _ts as usize;
    let end_addr = start_addr + size_of::<TimeVal>();
    let page_offset = start_addr % PAGE_SIZE;
    assert_eq!(start_addr >> PAGE_SIZE_BITS, end_addr >> PAGE_SIZE_BITS);
    let vpn = VirtPageNum(start_addr >> PAGE_SIZE_BITS);
    // debug!("try to map U {:?} => pte", vpn);
    let ppn = user_pg_table.translate(vpn).unwrap().ppn();
    // debug!("get ppn {:?}", ppn);

    // 3. turn to buffer in va
    let ts: *mut TimeVal = (ppn.get_mut() as *mut u8 as usize + page_offset) as *mut TimeVal;
    
    // 4. write to _ts
    let usec = get_time_us();
    unsafe {
        (*ts).sec = usec / 1_000_000;
        (*ts).usec = usec % 1_000_000;
    }

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    
    // 1. get user page table
    let token = current_user_token();
    let user_pg_table = PageTable::from_token(token);

    // 2. get ppn of _ti
    let start_addr = _ti as usize;
    let end_addr = start_addr + size_of::<TimeVal>();
    let page_offset = start_addr % PAGE_SIZE;
    assert_eq!(start_addr >> PAGE_SIZE_BITS, end_addr >> PAGE_SIZE_BITS);
    let vpn = VirtPageNum(start_addr >> PAGE_SIZE_BITS);
    // debug!("try to map U {:?} => pte", vpn);
    let ppn = user_pg_table.translate(vpn).unwrap().ppn();
    // debug!("get ppn {:?}", ppn);
    
    // 3. turn to buffer in va
    let ti: *mut TaskInfo = (ppn.get_mut() as *mut u8 as usize + page_offset) as *mut TaskInfo;

    // 4. write to _ti
    let (status, syscall_times, start_time) = current_task_info();
    unsafe {
        (*ti).status = status;
        (*ti).syscall_times = syscall_times;
        (*ti).time = get_time_ms() - start_time;
    }
    
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    -1
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    -1
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
