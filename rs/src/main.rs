use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use nix::unistd;
use std::fs::File;
use std::io::{Read, Write};
use toml::Value;
#[macro_use]
extern crate derive_error;

#[derive(Error, Debug)]
enum Error {
    Nix(nix::Error),
    Io(std::io::Error),
    Nul(std::ffi::NulError),
    Toml(toml::de::Error),
    TomlMismatch,
    None,
}

fn enter_chroot(cfg: &Value) -> Result<(), Error> {
    let bind_cfg = &cfg["bind"];
    let new_root = bind_cfg["/"].as_str().ok_or(Error::TomlMismatch)?;
    unistd::chdir(new_root)?;

    let old_uid = unistd::getuid();
    let old_gid = unistd::getgid();

    let mut flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID;
    let euid = unistd::geteuid();
    if !euid.is_root() {
        // don't create user namepsace for root
        flags |= CloneFlags::CLONE_NEWUSER;
    }

    nix::sched::unshare(flags)?;

    if !euid.is_root() {
        // set up uid maps
        File::create("/proc/self/setgroups")?.write_all("deny".as_bytes())?;
        {
            let mut f = File::create("/proc/self/uid_map")?;
            let map = format!("{0} {0} 1", old_uid);
            f.write_all(map.as_bytes())?;
        }
        {
            let mut f = File::create("/proc/self/gid_map")?;
            let map = format!("{0} {0} 1", old_gid);
            f.write_all(map.as_bytes())?;
        }
    }

    // Make all mount point private
    nix::mount::mount::<str, _, str, str>(
        None,
        "/",
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )?;

    // Create mount points under new_root
    nix::mount::mount::<_, _, str, str>(
        Some(new_root),
        new_root,
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    )?;

    // chdir into the mount point, so after the move mount, we are actually under the new root
    unistd::chdir(new_root)?;

    // Bind some basic filesystems to the new_root
    let new_sys = std::path::Path::new(new_root).join("sys");
    nix::mount::mount::<_, _, str, str>(
        Some("/sys"),
        &new_sys,
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    )?;
    let new_sys = std::path::Path::new(new_root).join("dev");
    nix::mount::mount::<_, _, str, str>(
        Some("/dev"),
        &new_sys,
        None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None,
    )?;

    // Bind filesystems in config file
    for (k, v) in bind_cfg.as_table().ok_or(Error::TomlMismatch)? {
        if k == "/" {
            continue;
        }
        if k == "/proc" || k == "/sys" || k == "/dev" {
            eprintln!("Bind mount of {} will be ignored", k);
            continue;
        }

        let src = {
            if let Some(s) = v.as_str() {
                Ok(s)
            } else if v.as_integer().is_some() {
                Ok(k.as_str())
            } else {
                Err(Error::TomlMismatch)
            }
        }?;
        println!("Mounting {} to {}", src, k);

        nix::mount::mount::<_, _, str, str>(
            Some(src),
            k.as_str(),
            None,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None
        )?;
    }

    // Move mount the new_root to /
    nix::mount::mount::<_, _, str, str>(Some(new_root), "/", None, MsFlags::MS_MOVE, None)?;

    // chroot, so '/' actually refers to the new root
    unistd::chroot(".")?;

    Ok(())
}

fn spawn_shell() -> Result<unistd::Pid, Error> {
    use std::ffi::CString;
    match unistd::fork()? {
        unistd::ForkResult::Child => {
            unistd::execvp(&CString::new("sh")?, &[CString::new("sh")?]).unwrap();
            std::process::exit(1);
        }
        unistd::ForkResult::Parent { child } => Ok(child),
    }
}

fn start_pid1(cfg: &Value) -> Result<unistd::Pid, Error> {
    use nix::sys::wait::*;
    let pid = unistd::fork()?;
    match pid {
        unistd::ForkResult::Child => {
            // Mount new /proc
            // Have to do this here, since /proc can't be mounted
            // before pid 1 starts
            nix::mount::mount::<_, _, _, str>(
                Some("proc"),
                "/proc",
                Some("proc"),
                MsFlags::empty(),
                None,
            )
            .unwrap();
            let child = spawn_shell().unwrap();
            loop {
                let ws = wait();
                if let Ok(WaitStatus::Exited(pid, _)) = ws {
                    if pid == child {
                        std::process::exit(0);
                    }
                }
                if ws == Err(nix::Error::Sys(nix::errno::Errno::ECHILD)) {
                    // All child died?
                    std::process::exit(0);
                }
            }
        }
        unistd::ForkResult::Parent { child } => Ok(child),
    }
}

fn main() -> Result<(), Error> {
    let cfg = std::env::args().nth(1).ok_or(Error::None)?;
    let cfg = {
        let mut tmp = String::new();
        File::open(cfg)?.read_to_string(&mut tmp)?;
        tmp
    };

    let cfg = cfg.parse::<Value>()?;
    enter_chroot(&cfg)?;

    let child = start_pid1(&cfg)?;
    nix::sys::wait::waitpid(Some(child), None)?;
    nix::sys::signal::kill(child, Some(nix::sys::signal::Signal::SIGKILL)).ok();
    Ok(())
}
