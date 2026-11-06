use crate::report::Violation;
use sysinfo::System;

const VM_PROCESSES: &[&str] = &[
    "vmtoolsd", "vmwaretray", "vmwareuser", "vmacthlp", "vboxservice", "vboxtray",
    "prl_tools", "prl_cc", "qemu-ga", "xenservice", "vmsrvc", "vmusrvc",
];

const VM_STRINGS: &[&str] = &[
    "vmware", "virtualbox", "innotek", "qemu", "kvm", "xen", "parallels",
    "bochs", "virtual machine", "bhyve", "hvm domu",
];

pub fn check(sys: &System) -> Vec<Violation> {
    let mut out = Vec::new();

    for p in sys.processes().values() {
        let name = p.name().to_lowercase();
        let name = name.trim_end_matches(".exe");
        if VM_PROCESSES.contains(&name) {
            out.push(Violation::new("VM_PROCESS", format!("guest tools process: {name}")));
        }
    }

    let smbios = smbios_strings().to_lowercase();
    if let Some(hit) = VM_STRINGS.iter().find(|s| smbios.contains(*s)) {
        out.push(Violation::new("VM_SMBIOS", format!("firmware string matches '{hit}'")));
    }

    #[cfg(target_arch = "x86_64")]
    if let Some(v) = cpuid_check(&smbios) {
        out.push(v);
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = std::process::Command::new("sysctl").args(["-n", "kern.hv_vmm_present"]).output() {
            if String::from_utf8_lossy(&o.stdout).trim() == "1" {
                out.push(Violation::new("VM_SYSCTL", "kern.hv_vmm_present=1"));
            }
        }
    }

    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for key in [
            r"SOFTWARE\VMware, Inc.\VMware Tools",
            r"SOFTWARE\Oracle\VirtualBox Guest Additions",
            r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
            r"SYSTEM\CurrentControlSet\Services\vmci",
            r"SYSTEM\CurrentControlSet\Services\vioscsi",
            r"SYSTEM\CurrentControlSet\Services\QEMU-GA",
        ] {
            if hklm.open_subkey(key).is_ok() {
                out.push(Violation::new("VM_REGISTRY", format!("HKLM\\{key}")));
            }
        }
    }

    out
}

/// SMBIOS-derived strings (manufacturer / product / BIOS vendor).
fn smbios_strings() -> String {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};
        if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"HARDWARE\DESCRIPTION\System\BIOS") {
            return ["SystemManufacturer", "SystemProductName", "BIOSVendor"]
                .iter()
                .filter_map(|n| k.get_value::<String, _>(n).ok())
                .collect::<Vec<_>>()
                .join(" ");
        }
        String::new()
    }
    #[cfg(target_os = "linux")]
    {
        ["sys_vendor", "product_name", "bios_vendor"]
            .iter()
            .filter_map(|n| std::fs::read_to_string(format!("/sys/class/dmi/id/{n}")).ok())
            .collect::<Vec<_>>()
            .join(" ")
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        String::new()
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)] // __cpuid is a safe fn on newer toolchains, unsafe on older ones
fn cpuid_check(smbios_lower: &str) -> Option<Violation> {
    use std::arch::x86_64::__cpuid;
    // SAFETY: CPUID is available on all x86_64 CPUs.
    let (hv_bit, vendor) = unsafe {
        let hv = __cpuid(1).ecx & (1 << 31) != 0;
        let l = __cpuid(0x4000_0000);
        let mut v = Vec::new();
        for r in [l.ebx, l.ecx, l.edx] {
            v.extend_from_slice(&r.to_le_bytes());
        }
        (hv, String::from_utf8_lossy(&v).trim_matches('\0').to_string())
    };
    if !hv_bit {
        return None;
    }
    // Windows with VBS/Memory Integrity runs the *host* under Hyper-V and
    // reports "Microsoft Hv" too. Only flag that vendor if SMBIOS confirms a guest.
    if vendor == "Microsoft Hv" && !smbios_lower.contains("virtual machine") {
        return None;
    }
    Some(Violation::new("VM_CPUID", format!("hypervisor bit set, vendor '{vendor}'")))
}
