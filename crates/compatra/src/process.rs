//! Shared process-command fixtures for runtime paths that explicitly model
//! synthetic command output.
//!
//! These are compatibility aids, not analysis detections: they model common
//! sandbox inventory commands for paths that cannot or should not expose a
//! real host child process stream.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticProcessOutput {
    pub label: String,
    pub output: Vec<u8>,
    pub exit_status: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticLogStream {
    pub messages: Vec<String>,
    pub output: Vec<u8>,
}

pub fn synthetic_log_stream(path: &str, argv: &[String]) -> Option<SyntheticLogStream> {
    if command_basename(path) != "log" || !argv.iter().any(|arg| arg == "stream") {
        return None;
    }
    let mut messages = argv
        .iter()
        .flat_map(|arg| extract_log_stream_event_messages(arg))
        .collect::<Vec<_>>();
    messages.sort();
    messages.dedup();
    if messages.is_empty() {
        return None;
    }
    Some(SyntheticLogStream {
        output: synthetic_log_stream_output(&messages),
        messages,
    })
}

pub fn synthetic_process_output(command: &str) -> Option<SyntheticProcessOutput> {
    let command = command.trim();
    if command.is_empty() {
        return None;
    }

    let quiet_command = strip_trailing_stderr_redirect(command);
    for candidate in command_candidates(command, quiet_command.as_deref()) {
        if let Some((label, output)) = synthetic_process_output_exact(candidate) {
            return Some(synthetic_output(label, output));
        }
    }

    if command.contains("find ")
        && command.contains("Extensions")
        && command.contains("2>/dev/null")
    {
        return Some(synthetic_output(
            "browser-extensions",
            "/Users/analyst/Library/Application Support/Google/Chrome/Default/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn\n\
             /Users/analyst/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions/bfnaelmomeimhlpmgjnjophhpkkoljpa\n",
        ));
    }

    if command.contains("mdfind") && command.contains(".pem") {
        return Some(synthetic_output(
            "spotlight-pem-search",
            "/Users/analyst/Documents/client.pem\n\
             /Users/analyst/.ssh/id_rsa.pem\n",
        ));
    }

    if command.contains("security ") && command.contains("dump-keychain") {
        return Some(synthetic_output(
            "security-dump-keychain",
            "keychain: \"/Users/analyst/Library/Keychains/login.keychain-db\"\n\
             class: \"genp\"\n\
             attributes:\n\
                 \"acct\"<blob>=\"analyst@example.test\"\n\
                 \"svce\"<blob>=\"Compatra Synthetic Login\"\n",
        ));
    }

    if command.contains("security ") && command.contains("find-generic-password") {
        return Some(synthetic_output(
            "security-generic-password",
            "keychain: \"/Users/analyst/Library/Keychains/login.keychain-db\"\n\
             class: \"genp\"\n\
             attributes:\n\
                 \"acct\"<blob>=\"analyst@example.test\"\n\
                 \"svce\"<blob>=\"Compatra Synthetic Login\"\n\
             password: \"synthetic-password\"\n",
        ));
    }

    None
}

fn synthetic_process_output_exact(command: &str) -> Option<(&'static str, &'static str)> {
    match command {
        "whoami" | "/usr/bin/whoami" => Some(("whoami", "analyst\n")),
        "id" | "/usr/bin/id" => Some((
            "identity",
            "uid=501(analyst) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),701(com.apple.sharepoint.group.1)\n",
        )),
        "id -un" | "/usr/bin/id -un" => Some(("identity-user", "analyst\n")),
        "id -u" | "/usr/bin/id -u" => Some(("identity-uid", "501\n")),
        "id -g" | "/usr/bin/id -g" => Some(("identity-gid", "20\n")),
        "uname" | "uname -s" | "/bin/uname" | "/bin/uname -s" => {
            Some(("uname-kernel", "Darwin\n"))
        }
        "uname -m" | "/bin/uname -m" => Some(("uname-machine", "arm64\n")),
        "uname -r" | "/bin/uname -r" => Some(("uname-release", "24.6.0\n")),
        "uname -a" | "/bin/uname -a" => Some((
            "uname-all",
            "Darwin users-iMac.local 24.6.0 Darwin Kernel Version 24.6.0: Tue Apr 21 20:17:54 PDT 2026; root:xnu-11417.140.69.710.16~1/RELEASE_ARM64 arm64\n",
        )),
        "sw_vers" | "/usr/bin/sw_vers" => Some((
            "sw-vers",
            "ProductName:\t\tmacOS\nProductVersion:\t\t15.5\nBuildVersion:\t\t24F74\n",
        )),
        "sw_vers -productName" | "/usr/bin/sw_vers -productName" => {
            Some(("sw-vers-product", "macOS\n"))
        }
        "sw_vers -productVersion" | "/usr/bin/sw_vers -productVersion" => {
            Some(("sw-vers-version", "15.5\n"))
        }
        "sw_vers -buildVersion" | "/usr/bin/sw_vers -buildVersion" => {
            Some(("sw-vers-build", "24F74\n"))
        }
        "hostname" | "/bin/hostname" | "scutil --get HostName" => {
            Some(("hostname", "users-iMac.local\n"))
        }
        "scutil --get ComputerName" => Some(("computer-name", "users-iMac\n")),
        "scutil --get LocalHostName" => Some(("local-hostname", "users-iMac\n")),
        "scutil --dns" => Some((
            "dns-config",
            "DNS configuration\n\nresolver #1\n  search domain[0] : local\n  nameserver[0] : 10.0.2.3\n  if_index : 4 (en0)\n",
        )),
        "date +%Z" => Some(("timezone", "UTC\n")),
        "stat -f %SB / 2>/dev/null | head -1" => {
            Some(("root-birthtime", "Jan  1 00:00:00 2026\n"))
        }
        "sysctl -n kern.boottime 2>/dev/null | grep -oE '[0-9]+' | head -1" => {
            Some(("boot-time", "1735689600\n"))
        }
        "sysctl -n kern.boottime" => {
            Some(("boot-time-raw", "{ sec = 1735689600, usec = 0 } Wed Jan  1 00:00:00 2026\n"))
        }
        "sysctl -n machdep.cpu.brand_string" => Some(("cpu-brand", "Apple M2\n")),
        "sysctl -n hw.model" => Some(("hw-model", "Mac14,3\n")),
        "sysctl hw.model" => Some(("hw-model-kv", "hw.model: Mac14,3\n")),
        "ifconfig en0 2>/dev/null | awk '/ether/{print $2}'" => {
            Some(("en0-mac", "02:42:AC:10:00:02\n"))
        }
        "ifconfig en0 2>/dev/null | awk '/inet /{print $2}'" => {
            Some(("en0-ipv4", "10.0.2.15\n"))
        }
        "ifconfig en0" | "/sbin/ifconfig en0" => Some((
            "ifconfig-en0",
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tether 02:42:ac:10:00:02\n\
             \tinet 10.0.2.15 netmask 0xffffff00 broadcast 10.0.2.255\n\
             \tstatus: active\n",
        )),
        "ifconfig" | "/sbin/ifconfig" => Some((
            "ifconfig",
            "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
             \tinet 127.0.0.1 netmask 0xff000000\n\
             en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
             \tether 02:42:ac:10:00:02\n\
             \tinet 10.0.2.15 netmask 0xffffff00 broadcast 10.0.2.255\n",
        )),
        "route -n get default" | "/sbin/route -n get default" => Some((
            "default-route",
            "   route to: default\n destination: default\n       mask: default\n    gateway: 10.0.2.2\n  interface: en0\n",
        )),
        "netstat -rn" | "/usr/sbin/netstat -rn" => Some((
            "route-table",
            "Routing tables\n\nInternet:\nDestination        Gateway            Flags        Netif Expire\ndefault            10.0.2.2           UGScg          en0\n10.0.2/24          link#4             UCS            en0\n",
        )),
        "ps -eo pid,sess,command 2>/dev/null" | "ps -eo pid,sess,command" => Some((
            "process-list",
            "  PID  SESS COMMAND\n\
               1     1 /sbin/launchd\n\
             503   503 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n\
             742   742 /bin/zsh\n",
        )),
        "launchctl list" | "/bin/launchctl list" => Some((
            "launchctl-list",
            "PID\tStatus\tLabel\n-\t0\tcom.apple.Finder\n503\t0\tcom.google.Chrome\n742\t0\tcom.apple.Terminal\n",
        )),
        "system_profiler SPHardwareDataType" | "/usr/sbin/system_profiler SPHardwareDataType" => {
            Some((
                "hardware-profile",
                "Hardware:\n\n    Hardware Overview:\n\n      Model Name: iMac\n      Model Identifier: Mac14,3\n      Chip: Apple M2\n      Memory: 16 GB\n      Serial Number (system): C02SYNTHETIC\n",
            ))
        }
        _ => None,
    }
}

fn synthetic_output(label: &str, output: &str) -> SyntheticProcessOutput {
    SyntheticProcessOutput {
        label: label.to_string(),
        output: output.as_bytes().to_vec(),
        exit_status: 0,
    }
}

fn strip_trailing_stderr_redirect(command: &str) -> Option<String> {
    command
        .strip_suffix("2>/dev/null")
        .map(str::trim)
        .filter(|trimmed| !trimmed.is_empty())
        .map(ToOwned::to_owned)
}

fn command_candidates<'a>(
    command: &'a str,
    quiet_command: Option<&'a str>,
) -> impl Iterator<Item = &'a str> {
    std::iter::once(command).chain(
        quiet_command
            .into_iter()
            .filter(move |quiet| *quiet != command),
    )
}

fn command_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn extract_log_stream_event_messages(predicate: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let mut rest = predicate;
    while let Some(idx) = rest.find("eventMessage contains") {
        rest = &rest[idx + "eventMessage contains".len()..];
        let Some(start) = rest.find('"') else {
            break;
        };
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('"') else {
            break;
        };
        messages.push(after_start[..end].to_string());
        rest = &after_start[end + 1..];
    }
    messages
}

fn synthetic_log_stream_output(messages: &[String]) -> Vec<u8> {
    let mut output =
        "Timestamp                       Thread     Type        Activity             PID    TTL  \n"
            .as_bytes()
            .to_vec();
    for message in messages {
        output.extend_from_slice(
            format!(
                "2026-05-08 20:00:00.000000+0300 0x000000   Info        0x0                  0      0    {}\n",
                message
            )
            .as_bytes(),
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_process_output_covers_common_inventory_commands() {
        let whoami = synthetic_process_output("whoami").expect("whoami should be synthesized");
        assert_eq!(whoami.label, "whoami");
        assert_eq!(String::from_utf8_lossy(&whoami.output), "analyst\n");
        assert_eq!(whoami.exit_status, 0);

        let sw_vers = synthetic_process_output("sw_vers -productVersion 2>/dev/null")
            .expect("quiet sw_vers should be synthesized");
        assert_eq!(sw_vers.label, "sw-vers-version");
        assert_eq!(String::from_utf8_lossy(&sw_vers.output), "15.5\n");

        let ps = synthetic_process_output("ps -eo pid,sess,command 2>/dev/null")
            .expect("process list should be synthesized");
        assert!(String::from_utf8_lossy(&ps.output).contains("Google Chrome"));
    }

    #[test]
    fn synthetic_process_output_covers_malware_collection_helpers() {
        let extensions = synthetic_process_output(
            "find '/Users/analyst/Library/Application Support/Google/Chrome/Default/Extensions' -maxdepth 1 2>/dev/null",
        )
        .expect("browser extension discovery should be synthesized");
        assert_eq!(extensions.label, "browser-extensions");
        assert!(String::from_utf8_lossy(&extensions.output).contains("Extensions"));

        let keychain = synthetic_process_output("security dump-keychain -d login.keychain")
            .expect("keychain dump should be synthesized");
        assert_eq!(keychain.label, "security-dump-keychain");
        assert!(String::from_utf8_lossy(&keychain.output).contains("login.keychain"));

        let pem = synthetic_process_output("mdfind -name .pem")
            .expect("pem search should be synthesized");
        assert_eq!(pem.label, "spotlight-pem-search");
        assert!(String::from_utf8_lossy(&pem.output).contains(".pem"));
    }

    #[test]
    fn synthetic_log_stream_extracts_event_messages() {
        let argv = vec![
            "stream".to_string(),
            r#"eventMessage contains "restartInitiated" OR eventMessage contains "shutdownInitiated""#
                .to_string(),
        ];

        let stream =
            synthetic_log_stream("/usr/bin/log", &argv).expect("log stream should be synthesized");

        assert_eq!(
            stream.messages,
            vec![
                "restartInitiated".to_string(),
                "shutdownInitiated".to_string()
            ]
        );
        assert!(String::from_utf8_lossy(&stream.output).contains("restartInitiated"));
    }
}
