use std::collections::HashMap;

use crate::macos::Emulator;
use crate::macos::Heap;
use crate::macos::LogLevel;
use crate::macos::MacOsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MacOsEventType {
    EvCtlConnect,
    EvCtlDisconnect,
    EvCtlSend,
    EvCtlSetOpt,
    EvCtlGetOpt,
    EvSfltAttach,
    EvSfltDetach,
    EvSfltBind,
    EvSfltConnectOut,
    EvSfltConnectIn,
    EvSfltListen,
    EvSfltNotifyBound,
    EvSfltNotifyConnecting,
    EvSfltNotifyConnected,
    EvSfltNotifyClosing,
    EvSfltNotifyDisconnecting,
    EvSfltNotifyDisconnected,
    EvSfltDataOut,
    EvSfltDataIn,
    EvSfltSetOption,
    EvSfltGetOption,
    EvIpfOutput,
    EvIpfInput,
    EvIpfDetach,
    EvKauthGeneric,
    EvKauthProcess,
    EvKauthVnode,
    EvKauthFileop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KauthAction {
    KauthFileopOpen,
    KauthFileopClose,
    KauthFileopWillRename,
    KauthFileopRename,
    KauthFileopExchange,
    KauthFileopLink,
    KauthFileopExec,
    KauthFileopDelete,
}

#[derive(Debug, Clone)]
pub struct MacOsEvent {
    pub event_type: MacOsEventType,
    pub name: String,
    pub params: Vec<u64>,
    pub ev_index: isize,
    pub protocol: Option<u32>,
}

impl MacOsEvent {
    pub fn new(
        event_type: MacOsEventType,
        name: String,
        ev_index: isize,
        protocol: Option<u32>,
    ) -> Self {
        Self {
            event_type,
            name,
            params: Vec::new(),
            ev_index,
            protocol,
        }
    }

    pub fn set_params(&mut self, params: Vec<u64>) {
        if self.ev_index != -1 {
            let mut p = params.clone();
            p.insert(self.ev_index as usize, 0);
            self.params = p;
        } else {
            self.params = params;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct MacOsEventKey {
    event_type: MacOsEventType,
    name: String,
    protocol: Option<u32>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProcInfo {
    pid: u32,
    #[allow(dead_code)]
    name: String,
    addr: u64,
}

#[derive(Debug, Clone)]
struct SocketInfo {
    #[allow(dead_code)]
    addr: u64,
    #[allow(dead_code)]
    family: u8,
    #[allow(dead_code)]
    host: String,
    #[allow(dead_code)]
    port: u16,
}

pub struct MacOsEventManager {
    callbacks: HashMap<MacOsEventKey, Vec<u64>>,
    jobs: Vec<(u64, MacOsEvent)>,
    src_host: String,
    src_port: u16,
    src_mac: [u8; 6],
    dst_host: String,
    dst_port: u16,
    dst_mac: [u8; 6],
    current_proc: String,
    #[allow(dead_code)]
    cred: Option<u64>,
    #[allow(dead_code)]
    label: Option<u64>,
    #[allow(dead_code)]
    vnode: Option<u64>,
    target_pid: u32,
    my_procs: Vec<ProcInfo>,
    allproc: Option<u64>,
    #[allow(dead_code)]
    map_fd: HashMap<u32, u64>,
    #[allow(dead_code)]
    ipf_cookie: HashMap<String, u64>,
    #[allow(dead_code)]
    sockets: Vec<SocketInfo>,
    #[allow(dead_code)]
    deadcode: Option<u64>,
}

impl MacOsEventManager {
    pub fn new() -> Self {
        Self {
            callbacks: HashMap::new(),
            jobs: Vec::new(),
            src_host: "192.168.13.37".to_string(),
            src_port: 1337u16.to_be(),
            src_mac: [0xba, 0xbe, 0xc0, 0xde, 0xbe, 0x57],
            dst_host: "10.2.13.38".to_string(),
            dst_port: 1338u16.to_be(),
            dst_mac: [0xba, 0xbe, 0xfe, 0xed, 0xfa, 0xce],
            current_proc: String::new(),
            cred: None,
            label: None,
            vnode: None,
            target_pid: 0xdeadbeef,
            my_procs: Vec::new(),
            allproc: None,
            map_fd: HashMap::new(),
            ipf_cookie: HashMap::new(),
            sockets: Vec::new(),
            deadcode: None,
        }
    }

    pub fn set_current_proc(&mut self, name: &str) {
        self.current_proc = name.to_string();
    }

    pub fn get_current_proc(&self) -> &str {
        &self.current_proc
    }

    pub fn get_src_host(&self) -> &str {
        &self.src_host
    }

    pub fn get_src_port(&self) -> u16 {
        self.src_port
    }

    pub fn set_allproc(&mut self, addr: u64) {
        self.my_procs.clear();
        self.allproc = Some(addr);
    }

    pub fn set_target_pid(&mut self, pid: u32) {
        self.target_pid = pid;
    }

    pub fn add_process(
        &mut self,
        pid: u32,
        name: &str,
        heap: &mut Heap,
        emulator: &mut dyn Emulator,
    ) -> Result<(), MacOsError> {
        for p in &self.my_procs {
            if p.pid == pid {
                emulator.log(LogLevel::Info, "Duplicated process");
                return Ok(());
            }
        }

        let cur_proc_addr = heap.alloc(256);
        let p_comm = name.as_bytes().to_vec();
        let mut p_comm_padded = p_comm.clone();
        while p_comm_padded.len() < 17 {
            p_comm_padded.push(0);
        }
        let mut p_name = p_comm_padded.clone();
        while p_name.len() < 33 {
            p_name.push(0);
        }

        let _cred_addr = heap.alloc(128);

        let proc_info = ProcInfo {
            pid,
            name: name.to_string(),
            addr: cur_proc_addr,
        };

        if self.my_procs.is_empty() {
            if let Some(allproc_addr) = self.allproc {
                emulator.write_memory(allproc_addr, &cur_proc_addr.to_le_bytes())?;
            }
            self.my_procs.push(proc_info);
        } else {
            let prev_proc = self.my_procs.last().unwrap().clone();
            emulator.write_memory(prev_proc.addr + 0x10, &cur_proc_addr.to_le_bytes())?;
            emulator.write_memory(cur_proc_addr + 0x18, &prev_proc.addr.to_le_bytes())?;
            self.my_procs.push(proc_info);
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn proc_find(&self, pid: u32) -> Option<&ProcInfo> {
        self.my_procs.iter().find(|p| p.pid == pid)
    }

    pub fn register(
        &mut self,
        func_addr: u64,
        ev_name: &str,
        ev_type: MacOsEventType,
        protocol: Option<u32>,
    ) {
        let key = MacOsEventKey {
            event_type: ev_type,
            name: ev_name.to_string(),
            protocol,
        };
        self.callbacks
            .entry(key)
            .or_insert_with(Vec::new)
            .push(func_addr);
    }

    pub fn deregister(&mut self, ev_name: &str) {
        self.callbacks.retain(|key, _| key.name != ev_name);
    }

    #[allow(dead_code)]
    pub(crate) fn get_events_by_name(&self, ev_name: &str) -> Vec<&MacOsEventKey> {
        self.callbacks
            .keys()
            .filter(|k| k.name == ev_name)
            .collect()
    }

    pub(crate) fn get_events_by_type(&self, ev_type: MacOsEventType) -> Vec<&MacOsEventKey> {
        self.callbacks
            .keys()
            .filter(|k| k.event_type == ev_type)
            .collect()
    }

    pub(crate) fn get_events_by_type_and_proto(
        &self,
        ev_type: MacOsEventType,
        protocol: u32,
    ) -> Vec<&MacOsEventKey> {
        self.callbacks
            .keys()
            .filter(|k| k.event_type == ev_type && k.protocol == Some(protocol))
            .collect()
    }

    pub fn emit(
        &mut self,
        ev_name: &str,
        ev_type: MacOsEventType,
        params: Vec<u64>,
        run_flag: bool,
    ) {
        let key = MacOsEventKey {
            event_type: ev_type,
            name: ev_name.to_string(),
            protocol: None,
        };

        if let Some(callbacks) = self.callbacks.get(&key) {
            let mut event = MacOsEvent::new(ev_type, ev_name.to_string(), -1, None);
            event.set_params(params.clone());

            for &cb in callbacks {
                if run_flag {
                    self.jobs.push((cb, event.clone()));
                } else {
                    self.jobs.push((cb, event.clone()));
                }
            }
        }
    }

    pub fn emit_by_type(&mut self, ev_type: MacOsEventType, params: Vec<u64>, _run_flag: bool) {
        #[derive(Clone)]
        struct EventData {
            name: String,
            protocol: Option<u32>,
            callbacks: Vec<u64>,
        }

        let keys: Vec<_> = self.get_events_by_type(ev_type);
        let event_data: Vec<EventData> = keys
            .iter()
            .filter_map(|key| {
                let callbacks = self.callbacks.get(key).cloned().unwrap_or_default();
                if callbacks.is_empty() {
                    None
                } else {
                    Some(EventData {
                        name: key.name.clone(),
                        protocol: key.protocol,
                        callbacks,
                    })
                }
            })
            .collect();

        drop(keys);

        for data in event_data {
            let mut event = MacOsEvent::new(ev_type, data.name, -1, data.protocol);
            event.set_params(params.clone());
            for cb in data.callbacks {
                self.jobs.push((cb, event.clone()));
            }
        }
    }

    pub fn emit_by_type_and_proto(
        &mut self,
        ev_type: MacOsEventType,
        protocol: u32,
        params: Vec<u64>,
        _run_flag: bool,
    ) {
        #[derive(Clone)]
        struct EventData {
            name: String,
            callbacks: Vec<u64>,
        }

        let keys: Vec<_> = self.get_events_by_type_and_proto(ev_type, protocol);
        let event_data: Vec<EventData> = keys
            .iter()
            .filter_map(|key| {
                let callbacks = self.callbacks.get(key).cloned().unwrap_or_default();
                if callbacks.is_empty() {
                    None
                } else {
                    Some(EventData {
                        name: key.name.clone(),
                        callbacks,
                    })
                }
            })
            .collect();

        drop(keys);

        for data in event_data {
            let mut event = MacOsEvent::new(ev_type, data.name, -1, Some(protocol));
            event.set_params(params.clone());
            for cb in data.callbacks {
                self.jobs.push((cb, event.clone()));
            }
        }
    }

    pub fn trigger(&mut self, emulator: &mut dyn Emulator) -> Result<(), MacOsError> {
        let reg_list = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

        for (cb, ev) in self.jobs.drain(..) {
            let params = &ev.params;
            if params.len() <= 6 {
                for (idx, &p) in params.iter().enumerate() {
                    emulator.write_reg(reg_list[idx], p)?;
                }
            } else {
                for (idx, &p) in params.iter().take(6).enumerate() {
                    emulator.write_reg(reg_list[idx], p)?;
                }
                for &p in params.iter().skip(6) {
                    emulator.stack_push(p)?;
                }
            }

            emulator.run(cb, None)?;
        }

        Ok(())
    }

    pub fn clear_heap(&mut self, heap: &mut Heap) {
        heap.clear();
    }

    pub fn clear_sockets(&mut self) {
        self.sockets.clear();
    }

    pub fn set_src_host(&mut self, host: &str) {
        self.src_host = host.to_string();
    }

    pub fn set_src_port(&mut self, port: u16) {
        self.src_port = port.to_be();
    }

    pub fn set_src_mac(&mut self, mac: [u8; 6]) {
        self.src_mac = mac;
    }

    pub fn set_dst_host(&mut self, host: &str) {
        self.dst_host = host.to_string();
    }

    pub fn set_dst_port(&mut self, port: u16) {
        self.dst_port = port.to_be();
    }

    pub fn set_dst_mac(&mut self, mac: [u8; 6]) {
        self.dst_mac = mac;
    }
}
