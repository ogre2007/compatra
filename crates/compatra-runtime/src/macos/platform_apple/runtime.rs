//! Synthetic Apple framework object runtime shared across emulation hooks.

use std::collections::HashMap;

use crate::macos::byte_preview::lossy_data_preview;
use crate::macos::Emulator;

#[derive(Clone, Debug)]
pub enum AppleObject {
    String {
        data: Vec<u8>,
        encoding: u64,
    },
    Data {
        data: Vec<u8>,
    },
    Array {
        values: Vec<u64>,
        host_ptr: Option<u64>,
    },
    Set {
        values: Vec<u64>,
        host_ptr: Option<u64>,
    },
    Enumerator {
        values: Vec<u64>,
        index: usize,
    },
    Dictionary {
        entries: Vec<(u64, u64)>,
        host_ptr: Option<u64>,
    },
    Number {
        value: i64,
    },
    Boolean {
        value: bool,
    },
    Certificate {
        data_ref: u64,
    },
    PolicySsl {
        server: bool,
        hostname: u64,
    },
    Trust {
        certificates: u64,
        policies: u64,
    },
    Date {
        absolute_time: f64,
    },
    Error {
        code: i64,
        description: String,
    },
    Url {
        path: Vec<u8>,
        host_ptr: Option<u64>,
    },
    Bundle {
        path: Vec<u8>,
        host_ptr: Option<u64>,
    },
    ObjcClass {
        name: String,
        host_ptr: Option<u64>,
    },
    ObjcSelector {
        name: String,
        host_ptr: Option<u64>,
    },
    ObjcObject {
        kind: String,
        host_ptr: Option<u64>,
    },
    Opaque {
        kind: String,
        host_ptr: Option<u64>,
    },
}

#[derive(Debug)]
pub struct AppleRuntime {
    next_handle: u64,
    next_guest_buffer: u64,
    process_name: Option<String>,
    singletons: HashMap<String, u64>,
    pub objects: HashMap<u64, AppleObject>,
}

impl Default for AppleRuntime {
    fn default() -> Self {
        Self {
            next_handle: 0x6A11_0000_0000,
            next_guest_buffer: 0x5000_0000,
            process_name: None,
            singletons: HashMap::new(),
            objects: HashMap::new(),
        }
    }
}

impl AppleRuntime {
    const TYPE_ID_STRING: u64 = 0x1001;
    const TYPE_ID_DATA: u64 = 0x1002;
    const TYPE_ID_ARRAY: u64 = 0x1003;
    const TYPE_ID_DICTIONARY: u64 = 0x1004;
    const TYPE_ID_NUMBER: u64 = 0x1005;
    const TYPE_ID_CERTIFICATE: u64 = 0x1006;
    const TYPE_ID_POLICY_SSL: u64 = 0x1007;
    const TYPE_ID_TRUST: u64 = 0x1008;
    const TYPE_ID_DATE: u64 = 0x1009;
    const TYPE_ID_ERROR: u64 = 0x100A;
    const TYPE_ID_BOOLEAN: u64 = 0x100B;
    const TYPE_ID_SET: u64 = 0x100C;

    pub fn retain(&self, handle: u64) -> u64 {
        handle
    }

    pub fn release(&mut self, _handle: u64) {
        // We intentionally keep objects alive for the whole emulation session.
        // Malware samples often rely on loose ownership patterns, and premature
        // synthetic deallocation makes control flow less realistic than a leak.
    }

    pub fn set_process_name(&mut self, process_name: impl Into<String>) {
        self.process_name = Some(process_name.into());
    }

    pub fn process_name(&self) -> Option<&str> {
        self.process_name.as_deref()
    }

    pub fn alloc_string(&mut self, data: Vec<u8>, encoding: u64) -> u64 {
        self.alloc(AppleObject::String { data, encoding })
    }

    pub fn alloc_data(&mut self, data: Vec<u8>) -> u64 {
        self.alloc(AppleObject::Data { data })
    }

    pub fn alloc_array(&mut self) -> u64 {
        self.alloc(AppleObject::Array {
            values: Vec::new(),
            host_ptr: None,
        })
    }

    pub fn alloc_array_with_values(&mut self, values: Vec<u64>) -> u64 {
        self.alloc_array_with_values_and_host(values, None)
    }

    pub fn alloc_array_with_values_and_host(
        &mut self,
        values: Vec<u64>,
        host_ptr: Option<u64>,
    ) -> u64 {
        if let Some(host_ptr) = host_ptr.filter(|host_ptr| *host_ptr != 0) {
            self.objects.insert(
                host_ptr,
                AppleObject::Array {
                    values,
                    host_ptr: Some(host_ptr),
                },
            );
            host_ptr
        } else {
            self.alloc(AppleObject::Array {
                values,
                host_ptr: None,
            })
        }
    }

    pub fn alloc_set(&mut self) -> u64 {
        self.alloc(AppleObject::Set {
            values: Vec::new(),
            host_ptr: None,
        })
    }

    pub fn alloc_set_with_values(&mut self, values: Vec<u64>) -> u64 {
        let set_ref = self.alloc_set();
        for value in values {
            let _ = self.set_add(set_ref, value);
        }
        set_ref
    }

    pub fn alloc_dictionary(&mut self, entries: Vec<(u64, u64)>) -> u64 {
        self.alloc_dictionary_with_host(entries, None)
    }

    pub fn alloc_dictionary_with_host(
        &mut self,
        entries: Vec<(u64, u64)>,
        host_ptr: Option<u64>,
    ) -> u64 {
        if let Some(host_ptr) = host_ptr.filter(|host_ptr| *host_ptr != 0) {
            self.objects.insert(
                host_ptr,
                AppleObject::Dictionary {
                    entries,
                    host_ptr: Some(host_ptr),
                },
            );
            host_ptr
        } else {
            self.alloc(AppleObject::Dictionary {
                entries,
                host_ptr: None,
            })
        }
    }

    pub fn dictionary_get(&self, dict_ref: u64, key_ref: u64) -> Option<u64> {
        match self.objects.get(&dict_ref) {
            Some(AppleObject::Dictionary { entries, .. }) => entries
                .iter()
                .find(|(key, _)| *key == key_ref)
                .map(|(_, value)| *value),
            _ => None,
        }
    }

    fn dictionary_key_index(&self, dict_ref: u64, key_ref: u64) -> Option<usize> {
        let needle = self.object_data(key_ref);
        match self.objects.get(&dict_ref) {
            Some(AppleObject::Dictionary { entries, .. }) => entries.iter().position(|(key, _)| {
                if *key == key_ref {
                    return true;
                }
                let Some(needle) = needle.as_ref() else {
                    return false;
                };
                self.object_data(*key)
                    .map(|candidate| candidate == *needle)
                    .unwrap_or(false)
            }),
            _ => None,
        }
    }

    pub fn dictionary_set(&mut self, dict_ref: u64, key_ref: u64, value_ref: u64) -> bool {
        let existing_index = self.dictionary_key_index(dict_ref, key_ref);
        match self.objects.get_mut(&dict_ref) {
            Some(AppleObject::Dictionary { entries, host_ptr }) => {
                if let Some(index) = existing_index {
                    entries[index] = (key_ref, value_ref);
                } else {
                    entries.push((key_ref, value_ref));
                }
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn dictionary_add(&mut self, dict_ref: u64, key_ref: u64, value_ref: u64) -> bool {
        if self.dictionary_key_index(dict_ref, key_ref).is_some() {
            return false;
        }
        match self.objects.get_mut(&dict_ref) {
            Some(AppleObject::Dictionary { entries, host_ptr }) => {
                entries.push((key_ref, value_ref));
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn dictionary_replace(&mut self, dict_ref: u64, key_ref: u64, value_ref: u64) -> bool {
        let Some(existing_index) = self.dictionary_key_index(dict_ref, key_ref) else {
            return false;
        };
        match self.objects.get_mut(&dict_ref) {
            Some(AppleObject::Dictionary { entries, host_ptr }) => {
                entries[existing_index] = (key_ref, value_ref);
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn dictionary_remove(&mut self, dict_ref: u64, key_ref: u64) -> bool {
        let Some(existing_index) = self.dictionary_key_index(dict_ref, key_ref) else {
            return false;
        };
        match self.objects.get_mut(&dict_ref) {
            Some(AppleObject::Dictionary { entries, host_ptr }) => {
                entries.remove(existing_index);
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn dictionary_remove_all(&mut self, dict_ref: u64) -> bool {
        match self.objects.get_mut(&dict_ref) {
            Some(AppleObject::Dictionary { entries, host_ptr }) => {
                entries.clear();
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn dictionary_entries(&self, dict_ref: u64) -> Option<Vec<(u64, u64)>> {
        match self.objects.get(&dict_ref) {
            Some(AppleObject::Dictionary { entries, .. }) => Some(entries.clone()),
            _ => None,
        }
    }

    pub fn dictionary_len(&self, dict_ref: u64) -> Option<usize> {
        match self.objects.get(&dict_ref) {
            Some(AppleObject::Dictionary { entries, .. }) => Some(entries.len()),
            _ => None,
        }
    }

    pub fn alloc_number(&mut self, value: i64) -> u64 {
        self.alloc(AppleObject::Number { value })
    }

    pub fn number_value(&self, number_ref: u64) -> Option<i64> {
        match self.objects.get(&number_ref) {
            Some(AppleObject::Number { value }) => Some(*value),
            Some(AppleObject::Boolean { value }) => Some(*value as i64),
            _ => None,
        }
    }

    pub fn alloc_boolean(&mut self, value: bool) -> u64 {
        self.alloc(AppleObject::Boolean { value })
    }

    pub fn boolean_value(&self, boolean_ref: u64) -> Option<bool> {
        match self.objects.get(&boolean_ref) {
            Some(AppleObject::Boolean { value }) => Some(*value),
            Some(AppleObject::Number { value }) => Some(*value != 0),
            _ => None,
        }
    }

    pub fn array_append(&mut self, array_ref: u64, value: u64) -> bool {
        match self.objects.get_mut(&array_ref) {
            Some(AppleObject::Array { values, host_ptr }) => {
                values.push(value);
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn array_insert(&mut self, array_ref: u64, index: usize, value: u64) -> bool {
        match self.objects.get_mut(&array_ref) {
            Some(AppleObject::Array { values, host_ptr }) if index <= values.len() => {
                values.insert(index, value);
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn array_set(&mut self, array_ref: u64, index: usize, value: u64) -> bool {
        match self.objects.get_mut(&array_ref) {
            Some(AppleObject::Array { values, host_ptr }) if index < values.len() => {
                values[index] = value;
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn array_remove(&mut self, array_ref: u64, index: usize) -> bool {
        match self.objects.get_mut(&array_ref) {
            Some(AppleObject::Array { values, host_ptr }) if index < values.len() => {
                values.remove(index);
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn array_remove_all(&mut self, array_ref: u64) -> bool {
        match self.objects.get_mut(&array_ref) {
            Some(AppleObject::Array { values, host_ptr }) => {
                values.clear();
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn array_len(&self, array_ref: u64) -> Option<usize> {
        match self.objects.get(&array_ref) {
            Some(AppleObject::Array { values, .. }) => Some(values.len()),
            _ => None,
        }
    }

    pub fn array_get(&self, array_ref: u64, index: usize) -> Option<u64> {
        match self.objects.get(&array_ref) {
            Some(AppleObject::Array { values, .. }) => values.get(index).copied(),
            _ => None,
        }
    }

    pub fn array_contains(
        &self,
        array_ref: u64,
        location: usize,
        length: usize,
        value_ref: u64,
    ) -> Option<bool> {
        let values = match self.objects.get(&array_ref) {
            Some(AppleObject::Array { values, .. }) => values,
            _ => return None,
        };
        let needle = self.object_data(value_ref);
        let end = location.saturating_add(length).min(values.len());
        if location >= end {
            return Some(false);
        }
        Some(values[location..end].iter().any(|candidate| {
            if *candidate == value_ref {
                return true;
            }
            let Some(needle) = needle.as_ref() else {
                return false;
            };
            self.object_data(*candidate)
                .map(|candidate| candidate == *needle)
                .unwrap_or(false)
        }))
    }

    fn set_value_index(&self, set_ref: u64, value_ref: u64) -> Option<usize> {
        let needle = self.object_data(value_ref);
        match self.objects.get(&set_ref) {
            Some(AppleObject::Set { values, .. }) => values.iter().position(|candidate| {
                if *candidate == value_ref {
                    return true;
                }
                let Some(needle) = needle.as_ref() else {
                    return false;
                };
                self.object_data(*candidate)
                    .map(|candidate| candidate == *needle)
                    .unwrap_or(false)
            }),
            _ => None,
        }
    }

    pub fn set_add(&mut self, set_ref: u64, value_ref: u64) -> bool {
        if self.set_value_index(set_ref, value_ref).is_some() {
            return false;
        }
        match self.objects.get_mut(&set_ref) {
            Some(AppleObject::Set { values, host_ptr }) => {
                values.push(value_ref);
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn set_set(&mut self, set_ref: u64, value_ref: u64) -> bool {
        let existing_index = self.set_value_index(set_ref, value_ref);
        match self.objects.get_mut(&set_ref) {
            Some(AppleObject::Set { values, host_ptr }) => {
                if let Some(index) = existing_index {
                    values[index] = value_ref;
                } else {
                    values.push(value_ref);
                }
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn set_replace(&mut self, set_ref: u64, value_ref: u64) -> bool {
        let Some(index) = self.set_value_index(set_ref, value_ref) else {
            return false;
        };
        match self.objects.get_mut(&set_ref) {
            Some(AppleObject::Set { values, host_ptr }) => {
                values[index] = value_ref;
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn set_remove(&mut self, set_ref: u64, value_ref: u64) -> bool {
        let Some(index) = self.set_value_index(set_ref, value_ref) else {
            return false;
        };
        match self.objects.get_mut(&set_ref) {
            Some(AppleObject::Set { values, host_ptr }) => {
                values.remove(index);
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn set_remove_all(&mut self, set_ref: u64) -> bool {
        match self.objects.get_mut(&set_ref) {
            Some(AppleObject::Set { values, host_ptr }) => {
                values.clear();
                *host_ptr = None;
                true
            }
            _ => false,
        }
    }

    pub fn set_contains(&self, set_ref: u64, value_ref: u64) -> Option<bool> {
        match self.objects.get(&set_ref) {
            Some(AppleObject::Set { .. }) => {
                Some(self.set_value_index(set_ref, value_ref).is_some())
            }
            _ => None,
        }
    }

    pub fn set_get(&self, set_ref: u64, value_ref: u64) -> Option<u64> {
        let index = self.set_value_index(set_ref, value_ref)?;
        match self.objects.get(&set_ref) {
            Some(AppleObject::Set { values, .. }) => values.get(index).copied(),
            _ => None,
        }
    }

    pub fn set_len(&self, set_ref: u64) -> Option<usize> {
        match self.objects.get(&set_ref) {
            Some(AppleObject::Set { values, .. }) => Some(values.len()),
            _ => None,
        }
    }

    pub fn alloc_enumerator(&mut self, values: Vec<u64>) -> u64 {
        self.alloc(AppleObject::Enumerator { values, index: 0 })
    }

    pub fn enumerator_next(&mut self, enumerator_ref: u64) -> Option<u64> {
        match self.objects.get_mut(&enumerator_ref) {
            Some(AppleObject::Enumerator { values, index }) => {
                let value = values.get(*index).copied().unwrap_or(0);
                if value != 0 {
                    *index = index.saturating_add(1);
                }
                Some(value)
            }
            _ => None,
        }
    }

    pub fn enumerator_remaining(&mut self, enumerator_ref: u64) -> Option<Vec<u64>> {
        match self.objects.get_mut(&enumerator_ref) {
            Some(AppleObject::Enumerator { values, index }) => {
                let remaining = values.get(*index..).unwrap_or(&[]).to_vec();
                *index = values.len();
                Some(remaining)
            }
            _ => None,
        }
    }

    pub fn alloc_certificate(&mut self, data_ref: u64) -> u64 {
        self.alloc(AppleObject::Certificate { data_ref })
    }

    pub fn alloc_policy_ssl(&mut self, server: bool, hostname: u64) -> u64 {
        self.alloc(AppleObject::PolicySsl { server, hostname })
    }

    pub fn certificate_data(&self, cert_ref: u64) -> Option<u64> {
        match self.objects.get(&cert_ref) {
            Some(AppleObject::Certificate { data_ref }) => Some(*data_ref),
            _ => None,
        }
    }

    pub fn alloc_trust(&mut self, certificates: u64, policies: u64) -> u64 {
        self.alloc(AppleObject::Trust {
            certificates,
            policies,
        })
    }

    pub fn trust_certificate_count(&self, trust_ref: u64) -> Option<usize> {
        let certificates = match self.objects.get(&trust_ref) {
            Some(AppleObject::Trust { certificates, .. }) => *certificates,
            _ => return None,
        };
        match self.objects.get(&certificates) {
            Some(AppleObject::Array { values, .. }) => Some(values.len()),
            Some(AppleObject::Certificate { .. }) => Some(1),
            _ if certificates != 0 => Some(1),
            _ => Some(0),
        }
    }

    pub fn trust_certificate_at_index(&self, trust_ref: u64, index: usize) -> Option<u64> {
        let certificates = match self.objects.get(&trust_ref) {
            Some(AppleObject::Trust { certificates, .. }) => *certificates,
            _ => return None,
        };
        match self.objects.get(&certificates) {
            Some(AppleObject::Array { values, .. }) => values.get(index).copied(),
            Some(AppleObject::Certificate { .. }) if index == 0 => Some(certificates),
            _ if certificates != 0 && index == 0 => Some(certificates),
            _ => None,
        }
    }

    pub fn alloc_date(&mut self, absolute_time: f64) -> u64 {
        self.alloc(AppleObject::Date { absolute_time })
    }

    pub fn alloc_error(&mut self, code: i64, description: impl Into<String>) -> u64 {
        self.alloc(AppleObject::Error {
            code,
            description: description.into(),
        })
    }

    pub fn alloc_url(&mut self, path: Vec<u8>, host_ptr: Option<u64>) -> u64 {
        if let Some(host_ptr) = host_ptr.filter(|host_ptr| *host_ptr != 0) {
            self.objects.insert(
                host_ptr,
                AppleObject::Url {
                    path,
                    host_ptr: Some(host_ptr),
                },
            );
            host_ptr
        } else {
            self.alloc(AppleObject::Url {
                path,
                host_ptr: None,
            })
        }
    }

    pub fn alloc_bundle(&mut self, path: Vec<u8>, host_ptr: Option<u64>) -> u64 {
        if let Some(host_ptr) = host_ptr.filter(|host_ptr| *host_ptr != 0) {
            self.objects.insert(
                host_ptr,
                AppleObject::Bundle {
                    path,
                    host_ptr: Some(host_ptr),
                },
            );
            host_ptr
        } else {
            self.alloc(AppleObject::Bundle {
                path,
                host_ptr: None,
            })
        }
    }

    pub fn bundle_path(&self, handle: u64) -> Option<Vec<u8>> {
        match self.objects.get(&handle) {
            Some(AppleObject::Bundle { path, .. }) => Some(path.clone()),
            _ => None,
        }
    }

    pub fn alloc_opaque(&mut self, kind: impl Into<String>) -> u64 {
        self.alloc(AppleObject::Opaque {
            kind: kind.into(),
            host_ptr: None,
        })
    }

    pub fn opaque_singleton(&mut self, kind: impl Into<String>) -> u64 {
        let kind = kind.into();
        if let Some(handle) = self.singletons.get(&kind) {
            return *handle;
        }
        let handle = self.alloc(AppleObject::Opaque {
            kind: kind.clone(),
            host_ptr: None,
        });
        self.singletons.insert(kind, handle);
        handle
    }

    pub fn register_host_opaque(&mut self, kind: impl Into<String>, host_ptr: u64) -> u64 {
        if host_ptr == 0 {
            return self.alloc_opaque(kind);
        }
        self.objects.insert(
            host_ptr,
            AppleObject::Opaque {
                kind: kind.into(),
                host_ptr: Some(host_ptr),
            },
        );
        host_ptr
    }

    pub fn register_host_objc_class(&mut self, name: impl Into<String>, host_ptr: u64) -> u64 {
        let name = name.into();
        if host_ptr == 0 {
            return self.alloc(AppleObject::ObjcClass {
                name,
                host_ptr: None,
            });
        }
        if self.objects.contains_key(&host_ptr) {
            return host_ptr;
        }
        self.objects.insert(
            host_ptr,
            AppleObject::ObjcClass {
                name,
                host_ptr: Some(host_ptr),
            },
        );
        host_ptr
    }

    pub fn register_host_objc_selector(&mut self, name: impl Into<String>, host_ptr: u64) -> u64 {
        let name = name.into();
        if host_ptr == 0 {
            return self.alloc(AppleObject::ObjcSelector {
                name,
                host_ptr: None,
            });
        }
        if self.objects.contains_key(&host_ptr) {
            return host_ptr;
        }
        self.objects.insert(
            host_ptr,
            AppleObject::ObjcSelector {
                name,
                host_ptr: Some(host_ptr),
            },
        );
        host_ptr
    }

    pub fn register_host_objc_object(&mut self, kind: impl Into<String>, host_ptr: u64) -> u64 {
        let kind = kind.into();
        if host_ptr == 0 {
            return 0;
        }
        if self.objects.contains_key(&host_ptr) {
            return host_ptr;
        }
        self.objects.insert(
            host_ptr,
            AppleObject::ObjcObject {
                kind,
                host_ptr: Some(host_ptr),
            },
        );
        host_ptr
    }

    pub fn alloc_objc_object(&mut self, kind: impl Into<String>) -> u64 {
        self.alloc(AppleObject::ObjcObject {
            kind: kind.into(),
            host_ptr: None,
        })
    }

    pub fn objc_singleton(&mut self, kind: impl Into<String>) -> u64 {
        let kind = kind.into();
        if let Some(handle) = self.singletons.get(&kind) {
            return *handle;
        }
        let handle = self.alloc_objc_object(kind.clone());
        self.singletons.insert(kind, handle);
        handle
    }

    pub fn objc_class_name(&self, handle: u64) -> Option<String> {
        match self.objects.get(&handle) {
            Some(AppleObject::ObjcClass { name, .. }) => Some(name.clone()),
            _ => None,
        }
    }

    pub fn objc_selector_name(&self, handle: u64) -> Option<String> {
        match self.objects.get(&handle) {
            Some(AppleObject::ObjcSelector { name, .. }) => Some(name.clone()),
            _ => None,
        }
    }

    pub fn objc_object_kind(&self, handle: u64) -> Option<String> {
        match self.objects.get(&handle) {
            Some(AppleObject::ObjcObject { kind, .. }) => Some(kind.clone()),
            Some(AppleObject::ObjcClass { name, .. }) => Some(name.clone()),
            Some(AppleObject::String { .. }) => Some("NSString".to_string()),
            Some(AppleObject::Data { .. }) => Some("NSData".to_string()),
            Some(AppleObject::Array { .. }) => Some("NSArray".to_string()),
            Some(AppleObject::Set { .. }) => Some("NSSet".to_string()),
            Some(AppleObject::Enumerator { .. }) => Some("NSEnumerator".to_string()),
            Some(AppleObject::Dictionary { .. }) => Some("NSDictionary".to_string()),
            Some(AppleObject::Number { .. }) | Some(AppleObject::Boolean { .. }) => {
                Some("NSNumber".to_string())
            }
            Some(AppleObject::Url { .. }) => Some("NSURL".to_string()),
            Some(AppleObject::Bundle { .. }) => Some("NSBundle".to_string()),
            _ => None,
        }
    }

    pub fn opaque_host_ptr(&self, handle: u64) -> Option<u64> {
        self.host_ptr(handle)
    }

    pub fn host_ptr(&self, handle: u64) -> Option<u64> {
        match self.objects.get(&handle) {
            Some(AppleObject::Opaque {
                host_ptr: Some(host_ptr),
                ..
            })
            | Some(AppleObject::Url {
                host_ptr: Some(host_ptr),
                ..
            })
            | Some(AppleObject::Bundle {
                host_ptr: Some(host_ptr),
                ..
            })
            | Some(AppleObject::ObjcClass {
                host_ptr: Some(host_ptr),
                ..
            })
            | Some(AppleObject::ObjcSelector {
                host_ptr: Some(host_ptr),
                ..
            })
            | Some(AppleObject::ObjcObject {
                host_ptr: Some(host_ptr),
                ..
            })
            | Some(AppleObject::Array {
                host_ptr: Some(host_ptr),
                ..
            })
            | Some(AppleObject::Set {
                host_ptr: Some(host_ptr),
                ..
            })
            | Some(AppleObject::Dictionary {
                host_ptr: Some(host_ptr),
                ..
            }) => Some(*host_ptr),
            _ => None,
        }
    }

    pub fn host_ptr_or_raw_unknown(&self, handle: u64) -> Option<u64> {
        if handle == 0 {
            return None;
        }
        self.host_ptr(handle)
            .or_else(|| (!self.objects.contains_key(&handle)).then_some(handle))
    }

    pub fn url_path(&self, handle: u64) -> Option<Vec<u8>> {
        match self.objects.get(&handle) {
            Some(AppleObject::Url { path, .. }) => Some(path.clone()),
            _ => None,
        }
    }

    pub fn type_id(&self, handle: u64) -> u64 {
        match self.objects.get(&handle) {
            Some(AppleObject::String { .. }) => Self::TYPE_ID_STRING,
            Some(AppleObject::Data { .. }) => Self::TYPE_ID_DATA,
            Some(AppleObject::Array { .. }) => Self::TYPE_ID_ARRAY,
            Some(AppleObject::Set { .. }) => Self::TYPE_ID_SET,
            Some(AppleObject::Dictionary { .. }) => Self::TYPE_ID_DICTIONARY,
            Some(AppleObject::Number { .. }) => Self::TYPE_ID_NUMBER,
            Some(AppleObject::Boolean { .. }) => Self::TYPE_ID_BOOLEAN,
            Some(AppleObject::Certificate { .. }) => Self::TYPE_ID_CERTIFICATE,
            Some(AppleObject::PolicySsl { .. }) => Self::TYPE_ID_POLICY_SSL,
            Some(AppleObject::Trust { .. }) => Self::TYPE_ID_TRUST,
            Some(AppleObject::Date { .. }) => Self::TYPE_ID_DATE,
            Some(AppleObject::Error { .. }) => Self::TYPE_ID_ERROR,
            Some(AppleObject::Url { .. }) => 0,
            Some(AppleObject::Bundle { .. }) => 0,
            Some(AppleObject::Enumerator { .. }) => 0,
            Some(AppleObject::ObjcClass { .. }) => 0,
            Some(AppleObject::ObjcSelector { .. }) => 0,
            Some(AppleObject::ObjcObject { .. }) => 0,
            Some(AppleObject::Opaque { .. }) => 0,
            None => 0,
        }
    }

    pub fn number_type_id(&self) -> u64 {
        Self::TYPE_ID_NUMBER
    }

    pub fn string_type_id(&self) -> u64 {
        Self::TYPE_ID_STRING
    }

    pub fn data_type_id(&self) -> u64 {
        Self::TYPE_ID_DATA
    }

    pub fn array_type_id(&self) -> u64 {
        Self::TYPE_ID_ARRAY
    }

    pub fn set_type_id(&self) -> u64 {
        Self::TYPE_ID_SET
    }

    pub fn dictionary_type_id(&self) -> u64 {
        Self::TYPE_ID_DICTIONARY
    }

    pub fn boolean_type_id(&self) -> u64 {
        Self::TYPE_ID_BOOLEAN
    }

    pub fn error_code(&self, error_ref: u64) -> Option<i64> {
        match self.objects.get(&error_ref) {
            Some(AppleObject::Error { code, .. }) => Some(*code),
            _ => None,
        }
    }

    pub fn error_description(&self, error_ref: u64) -> Option<String> {
        match self.objects.get(&error_ref) {
            Some(AppleObject::Error { description, .. }) => Some(description.clone()),
            _ => None,
        }
    }

    pub fn object_data(&self, handle: u64) -> Option<Vec<u8>> {
        match self.objects.get(&handle) {
            Some(AppleObject::String { data, .. }) => Some(data.clone()),
            Some(AppleObject::Data { data }) => Some(data.clone()),
            Some(AppleObject::Certificate { data_ref }) => self.object_data(*data_ref),
            Some(AppleObject::Url { path, .. }) => Some(path.clone()),
            Some(AppleObject::Bundle { path, .. }) => Some(path.clone()),
            _ => None,
        }
    }

    pub fn object_len(&self, handle: u64) -> Option<usize> {
        self.object_data(handle).map(|data| data.len())
    }

    pub fn export_bytes(
        &mut self,
        emu: &mut crate::UnicornEmulator,
        data: &[u8],
    ) -> Result<u64, crate::macos::MacOsError> {
        let len = data.len().max(1) as u64;
        let size = (len + 0xFFF) & !0xFFF;
        let addr = self.next_guest_buffer;
        self.next_guest_buffer = self.next_guest_buffer.saturating_add(size);
        emu.map_data_memory(addr, size)?;
        emu.write_memory(addr, data)?;
        Ok(addr)
    }

    pub fn describe(&self, handle: u64) -> String {
        match self.objects.get(&handle) {
            Some(AppleObject::String { data, encoding }) => format!(
                "CFString(len={}, enc=0x{:X}, preview={})",
                data.len(),
                encoding,
                lossy_data_preview(data, 64)
            ),
            Some(AppleObject::Data { data }) => format!(
                "CFData(len={}, preview={})",
                data.len(),
                lossy_data_preview(data, 64)
            ),
            Some(AppleObject::Array { values, host_ptr }) => match host_ptr {
                Some(host_ptr) => format!("CFArray(count={}, host=0x{:X})", values.len(), host_ptr),
                None => format!("CFArray(count={})", values.len()),
            },
            Some(AppleObject::Set { values, host_ptr }) => match host_ptr {
                Some(host_ptr) => format!("CFSet(count={}, host=0x{:X})", values.len(), host_ptr),
                None => format!("CFSet(count={})", values.len()),
            },
            Some(AppleObject::Enumerator { values, index }) => {
                format!("NSEnumerator(index={}, count={})", index, values.len())
            }
            Some(AppleObject::Dictionary { entries, host_ptr }) => match host_ptr {
                Some(host_ptr) => {
                    format!(
                        "CFDictionary(count={}, host=0x{:X})",
                        entries.len(),
                        host_ptr
                    )
                }
                None => format!("CFDictionary(count={})", entries.len()),
            },
            Some(AppleObject::Number { value }) => format!("CFNumber({})", value),
            Some(AppleObject::Boolean { value }) => format!("CFBoolean({})", value),
            Some(AppleObject::Certificate { data_ref }) => {
                format!("SecCertificate(data=0x{:X})", data_ref)
            }
            Some(AppleObject::PolicySsl { server, hostname }) => {
                format!("SecPolicySSL(server={}, hostname=0x{:X})", server, hostname)
            }
            Some(AppleObject::Trust {
                certificates,
                policies,
            }) => format!(
                "SecTrust(certificates=0x{:X}, policies=0x{:X})",
                certificates, policies
            ),
            Some(AppleObject::Date { absolute_time }) => {
                format!("CFDate(abs={})", absolute_time)
            }
            Some(AppleObject::Error { code, description }) => {
                format!("CFError(code={}, desc={})", code, description)
            }
            Some(AppleObject::Url { path, host_ptr }) => {
                let preview = lossy_data_preview(path, 64);
                match host_ptr {
                    Some(host_ptr) => format!("CFURL(path={}, host=0x{:X})", preview, host_ptr),
                    None => format!("CFURL(path={})", preview),
                }
            }
            Some(AppleObject::Bundle { path, host_ptr }) => {
                let preview = lossy_data_preview(path, 64);
                match host_ptr {
                    Some(host_ptr) => format!("NSBundle(path={}, host=0x{:X})", preview, host_ptr),
                    None => format!("NSBundle(path={})", preview),
                }
            }
            Some(AppleObject::ObjcClass { name, host_ptr }) => match host_ptr {
                Some(host_ptr) => format!("ObjCClass({}, host=0x{:X})", name, host_ptr),
                None => format!("ObjCClass({})", name),
            },
            Some(AppleObject::ObjcSelector { name, host_ptr }) => match host_ptr {
                Some(host_ptr) => format!("ObjCSelector({}, host=0x{:X})", name, host_ptr),
                None => format!("ObjCSelector({})", name),
            },
            Some(AppleObject::ObjcObject { kind, host_ptr }) => match host_ptr {
                Some(host_ptr) => format!("ObjCObject({}, host=0x{:X})", kind, host_ptr),
                None => format!("ObjCObject({})", kind),
            },
            Some(AppleObject::Opaque { kind, host_ptr }) => match host_ptr {
                Some(host_ptr) => format!("Opaque({}, host=0x{:X})", kind, host_ptr),
                None => format!("Opaque({})", kind),
            },
            None => format!("0x{:X}", handle),
        }
    }

    fn alloc(&mut self, object: AppleObject) -> u64 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(0x100);
        self.objects.insert(handle, object);
        handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_objects_are_not_exposed_as_host_pointers() {
        let mut runtime = AppleRuntime::default();

        let opaque_ref = runtime.alloc_opaque("SyntheticBundle");
        let url_ref = runtime.alloc_url(b"/tmp/synthetic.app".to_vec(), None);
        let bundle_ref = runtime.alloc_bundle(b"/tmp/Test.app".to_vec(), None);

        assert_eq!(runtime.host_ptr(opaque_ref), None);
        assert_eq!(runtime.host_ptr_or_raw_unknown(opaque_ref), None);
        assert_eq!(runtime.host_ptr(url_ref), None);
        assert_eq!(runtime.host_ptr_or_raw_unknown(url_ref), None);
        assert_eq!(runtime.host_ptr(bundle_ref), None);
        assert_eq!(runtime.host_ptr_or_raw_unknown(bundle_ref), None);
        assert_eq!(
            runtime.bundle_path(bundle_ref),
            Some(b"/tmp/Test.app".to_vec())
        );

        let class_ref = runtime.register_host_objc_class("SyntheticClass", 0);
        let selector_ref = runtime.register_host_objc_selector("init", 0);
        assert_eq!(runtime.host_ptr(class_ref), None);
        assert_eq!(runtime.host_ptr_or_raw_unknown(class_ref), None);
        assert_eq!(runtime.host_ptr(selector_ref), None);
        assert_eq!(runtime.host_ptr_or_raw_unknown(selector_ref), None);
    }

    #[test]
    fn synthetic_objc_singletons_are_stable() {
        let mut runtime = AppleRuntime::default();

        runtime.set_process_name("guest-main");
        let process_info = runtime.objc_singleton("NSProcessInfo");
        let process_info_again = runtime.objc_singleton("NSProcessInfo");
        let file_manager = runtime.objc_singleton("NSFileManager");

        assert_eq!(runtime.process_name(), Some("guest-main"));
        assert_eq!(process_info, process_info_again);
        assert_ne!(process_info, file_manager);
        assert_eq!(
            runtime.objc_object_kind(process_info),
            Some("NSProcessInfo".to_string())
        );
        assert_eq!(runtime.host_ptr(process_info), None);
        assert_eq!(runtime.host_ptr_or_raw_unknown(process_info), None);
    }

    #[test]
    fn synthetic_opaque_singletons_are_stable() {
        let mut runtime = AppleRuntime::default();

        let run_loop = runtime.opaque_singleton("CFRunLoopCurrent");
        let run_loop_again = runtime.opaque_singleton("CFRunLoopCurrent");
        let other = runtime.opaque_singleton("OtherOpaque");

        assert_ne!(run_loop, 0);
        assert_eq!(run_loop, run_loop_again);
        assert_ne!(run_loop, other);
        assert_eq!(runtime.host_ptr(run_loop), None);
        assert_eq!(runtime.host_ptr_or_raw_unknown(run_loop), None);
    }

    #[test]
    fn host_backed_objects_keep_real_host_pointer_visible() {
        let mut runtime = AppleRuntime::default();

        let opaque_ref = runtime.register_host_opaque("HostBundle", 0x1234_5000);
        let url_ref = runtime.alloc_url(b"/Applications/Test.app".to_vec(), Some(0x1234_6000));
        let bundle_ref =
            runtime.alloc_bundle(b"/Applications/Test.app".to_vec(), Some(0x1234_6500));

        assert_eq!(opaque_ref, 0x1234_5000);
        assert_eq!(runtime.host_ptr(opaque_ref), Some(0x1234_5000));
        assert_eq!(
            runtime.host_ptr_or_raw_unknown(opaque_ref),
            Some(0x1234_5000)
        );

        assert_eq!(url_ref, 0x1234_6000);
        assert_eq!(runtime.host_ptr(url_ref), Some(0x1234_6000));
        assert_eq!(
            runtime.url_path(url_ref),
            Some(b"/Applications/Test.app".to_vec())
        );
        assert_eq!(
            runtime.object_data(url_ref),
            Some(b"/Applications/Test.app".to_vec())
        );
        assert_eq!(bundle_ref, 0x1234_6500);
        assert_eq!(runtime.host_ptr(bundle_ref), Some(0x1234_6500));
        assert_eq!(
            runtime.objc_object_kind(bundle_ref),
            Some("NSBundle".to_string())
        );
        assert_eq!(
            runtime.bundle_path(bundle_ref),
            Some(b"/Applications/Test.app".to_vec())
        );

        let class_ref = runtime.register_host_objc_class("NSString", 0x1234_7000);
        let selector_ref =
            runtime.register_host_objc_selector("stringWithUTF8String:", 0x1234_8000);
        let object_ref = runtime.register_host_objc_object("NSString", 0x1234_9000);

        assert_eq!(class_ref, 0x1234_7000);
        assert_eq!(runtime.host_ptr(class_ref), Some(0x1234_7000));
        assert_eq!(
            runtime.objc_class_name(class_ref),
            Some("NSString".to_string())
        );

        assert_eq!(selector_ref, 0x1234_8000);
        assert_eq!(runtime.host_ptr(selector_ref), Some(0x1234_8000));
        assert_eq!(
            runtime.objc_selector_name(selector_ref),
            Some("stringWithUTF8String:".to_string())
        );

        assert_eq!(object_ref, 0x1234_9000);
        assert_eq!(runtime.host_ptr(object_ref), Some(0x1234_9000));
    }

    #[test]
    fn host_backed_collections_keep_guest_values_and_host_pointer() {
        let mut runtime = AppleRuntime::default();

        let array_ref =
            runtime.alloc_array_with_values_and_host(vec![0x10, 0x20], Some(0x1234_A000));
        assert_eq!(array_ref, 0x1234_A000);
        assert_eq!(runtime.host_ptr(array_ref), Some(0x1234_A000));
        assert_eq!(runtime.array_len(array_ref), Some(2));
        assert_eq!(runtime.array_get(array_ref, 1), Some(0x20));

        let dict_ref = runtime.alloc_dictionary_with_host(vec![(0x30, 0x40)], Some(0x1234_B000));
        assert_eq!(dict_ref, 0x1234_B000);
        assert_eq!(runtime.host_ptr(dict_ref), Some(0x1234_B000));
        assert_eq!(runtime.dictionary_len(dict_ref), Some(1));
        assert_eq!(runtime.dictionary_get(dict_ref, 0x30), Some(0x40));
    }

    #[test]
    fn array_mutation_matches_string_values_and_invalidates_host_proxy() {
        let mut runtime = AppleRuntime::default();

        let alpha = runtime.alloc_string(b"alpha".to_vec(), 0x8000_0100);
        let beta = runtime.alloc_string(b"beta".to_vec(), 0x8000_0100);
        let beta_equivalent = runtime.alloc_string(b"beta".to_vec(), 0x8000_0100);
        let gamma = runtime.alloc_string(b"gamma".to_vec(), 0x8000_0100);
        let delta = runtime.alloc_string(b"delta".to_vec(), 0x8000_0100);
        let array_ref = runtime.alloc_array_with_values_and_host(vec![alpha], Some(0x1234_D000));

        assert_eq!(runtime.host_ptr(array_ref), Some(0x1234_D000));
        assert!(runtime.array_append(array_ref, beta));
        assert_eq!(runtime.host_ptr(array_ref), None);
        assert!(runtime.array_insert(array_ref, 1, gamma));
        assert_eq!(runtime.array_len(array_ref), Some(3));
        assert_eq!(runtime.array_get(array_ref, 1), Some(gamma));
        assert_eq!(
            runtime.array_contains(array_ref, 0, 3, beta_equivalent),
            Some(true)
        );
        assert!(runtime.array_set(array_ref, 2, delta));
        assert_eq!(runtime.array_contains(array_ref, 1, 1, gamma), Some(true));
        assert_eq!(
            runtime.array_contains(array_ref, 0, 3, beta_equivalent),
            Some(false)
        );
        assert!(runtime.array_remove(array_ref, 0));
        assert_eq!(runtime.array_get(array_ref, 0), Some(gamma));
        assert!(runtime.array_remove_all(array_ref));
        assert_eq!(runtime.array_len(array_ref), Some(0));
    }

    #[test]
    fn set_mutation_matches_string_values_and_keeps_unique_entries() {
        let mut runtime = AppleRuntime::default();

        let alpha = runtime.alloc_string(b"alpha".to_vec(), 0x8000_0100);
        let beta = runtime.alloc_string(b"beta".to_vec(), 0x8000_0100);
        let beta_equivalent = runtime.alloc_string(b"beta".to_vec(), 0x8000_0100);
        let gamma = runtime.alloc_string(b"gamma".to_vec(), 0x8000_0100);

        let set_ref = runtime.alloc_set();
        assert!(runtime.set_add(set_ref, alpha));
        assert!(runtime.set_add(set_ref, beta));
        assert!(!runtime.set_add(set_ref, beta_equivalent));
        assert_eq!(runtime.set_len(set_ref), Some(2));
        assert_eq!(runtime.set_contains(set_ref, beta_equivalent), Some(true));
        assert_eq!(runtime.set_get(set_ref, beta_equivalent), Some(beta));

        assert!(runtime.set_set(set_ref, beta_equivalent));
        assert_eq!(runtime.set_get(set_ref, beta), Some(beta_equivalent));
        assert!(!runtime.set_replace(set_ref, gamma));
        assert!(runtime.set_add(set_ref, gamma));
        assert_eq!(runtime.set_len(set_ref), Some(3));
        assert!(runtime.set_remove(set_ref, alpha));
        assert_eq!(runtime.set_contains(set_ref, alpha), Some(false));
        assert_eq!(runtime.set_len(set_ref), Some(2));
        assert!(runtime.set_remove_all(set_ref));
        assert_eq!(runtime.set_len(set_ref), Some(0));
    }

    #[test]
    fn dictionary_mutation_matches_string_keys_and_invalidates_host_proxy() {
        let mut runtime = AppleRuntime::default();

        let key = runtime.alloc_string(b"class".to_vec(), 0x8000_0100);
        let same_key = runtime.alloc_string(b"class".to_vec(), 0x8000_0100);
        let other_key = runtime.alloc_string(b"account".to_vec(), 0x8000_0100);
        let initial_value = runtime.alloc_string(b"generic".to_vec(), 0x8000_0100);
        let replacement_value = runtime.alloc_string(b"password".to_vec(), 0x8000_0100);
        let other_value = runtime.alloc_string(b"user".to_vec(), 0x8000_0100);
        let dict_ref =
            runtime.alloc_dictionary_with_host(vec![(key, initial_value)], Some(0x1234_C000));

        assert_eq!(runtime.host_ptr(dict_ref), Some(0x1234_C000));
        assert!(!runtime.dictionary_add(dict_ref, same_key, replacement_value));
        assert_eq!(runtime.dictionary_len(dict_ref), Some(1));
        assert!(runtime.dictionary_replace(dict_ref, same_key, replacement_value));
        assert_eq!(
            runtime.dictionary_entries(dict_ref),
            Some(vec![(same_key, replacement_value)])
        );
        assert_eq!(runtime.host_ptr(dict_ref), None);

        assert!(runtime.dictionary_set(dict_ref, other_key, other_value));
        assert_eq!(
            runtime.dictionary_get(dict_ref, other_key),
            Some(other_value)
        );
        assert!(runtime.dictionary_remove(dict_ref, key));
        assert_eq!(runtime.dictionary_len(dict_ref), Some(1));
        assert!(runtime.dictionary_remove_all(dict_ref));
        assert_eq!(runtime.dictionary_entries(dict_ref), Some(Vec::new()));
    }

    #[test]
    fn synthetic_enumerator_advances_once_per_next_object() {
        let mut runtime = AppleRuntime::default();

        let enumerator = runtime.alloc_enumerator(vec![0x10, 0x20]);

        assert_eq!(
            runtime.objc_object_kind(enumerator),
            Some("NSEnumerator".to_string())
        );
        assert_eq!(runtime.enumerator_next(enumerator), Some(0x10));
        assert_eq!(runtime.enumerator_remaining(enumerator), Some(vec![0x20]));
        assert_eq!(runtime.enumerator_next(enumerator), Some(0));
        assert_eq!(runtime.enumerator_next(enumerator), Some(0));
    }

    #[test]
    fn corefoundation_type_ids_track_synthetic_object_kinds() {
        let mut runtime = AppleRuntime::default();

        let string_ref = runtime.alloc_string(b"hello".to_vec(), 0x0800_0100);
        let data_ref = runtime.alloc_data(b"bytes".to_vec());
        let array_ref = runtime.alloc_array_with_values(vec![string_ref]);
        let set_ref = runtime.alloc_set_with_values(vec![string_ref]);
        let dict_ref = runtime.alloc_dictionary(vec![(string_ref, data_ref)]);
        let number_ref = runtime.alloc_number(42);
        let boolean_ref = runtime.alloc_boolean(true);

        assert_eq!(runtime.type_id(string_ref), runtime.string_type_id());
        assert_eq!(runtime.type_id(data_ref), runtime.data_type_id());
        assert_eq!(runtime.type_id(array_ref), runtime.array_type_id());
        assert_eq!(runtime.type_id(set_ref), runtime.set_type_id());
        assert_eq!(runtime.type_id(dict_ref), runtime.dictionary_type_id());
        assert_eq!(runtime.type_id(number_ref), runtime.number_type_id());
        assert_eq!(runtime.type_id(boolean_ref), runtime.boolean_type_id());
        assert_eq!(runtime.boolean_value(boolean_ref), Some(true));
        assert_eq!(runtime.number_value(boolean_ref), Some(1));
        assert_eq!(
            runtime.objc_object_kind(boolean_ref),
            Some("NSNumber".to_string())
        );
    }

    #[test]
    fn security_objects_preserve_certificate_and_trust_relationships() {
        let mut runtime = AppleRuntime::default();

        let cert_data = runtime.alloc_data(b"certificate-bytes".to_vec());
        let cert = runtime.alloc_certificate(cert_data);
        let policy = runtime.alloc_policy_ssl(true, 0);
        let single_trust = runtime.alloc_trust(cert, policy);

        assert_eq!(runtime.certificate_data(cert), Some(cert_data));
        assert_eq!(runtime.trust_certificate_count(single_trust), Some(1));
        assert_eq!(
            runtime.trust_certificate_at_index(single_trust, 0),
            Some(cert)
        );
        assert_eq!(runtime.trust_certificate_at_index(single_trust, 1), None);

        let certs = runtime.alloc_array_with_values(vec![cert, 0xCAFE]);
        let array_trust = runtime.alloc_trust(certs, policy);
        assert_eq!(runtime.trust_certificate_count(array_trust), Some(2));
        assert_eq!(
            runtime.trust_certificate_at_index(array_trust, 0),
            Some(cert)
        );
        assert_eq!(
            runtime.trust_certificate_at_index(array_trust, 1),
            Some(0xCAFE)
        );
    }

    #[test]
    fn unknown_nonzero_handles_can_be_treated_as_raw_host_pointers() {
        let runtime = AppleRuntime::default();

        assert_eq!(runtime.host_ptr_or_raw_unknown(0), None);
        assert_eq!(
            runtime.host_ptr_or_raw_unknown(0x7FFF_0000_1000),
            Some(0x7FFF_0000_1000)
        );
    }
}
