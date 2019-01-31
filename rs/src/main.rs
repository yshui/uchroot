use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use nix::unistd;
use std::fs::File;
use std::io::Write;
#[macro_use]
extern crate derive_error;

#[derive(Error, Debug)]
enum Error {
    Nix(nix::Error),
    Io(std::io::Error),
}

fn enter_chroot(new_root: &str, cmd: &str, hostname: &str) -> Result<(), Error> {
    unistd::chdir("/")?;

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
        &Some("/"),
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )?;

    // Create mount points under new_root
    nix::mount::mount::<_, _, str, str>(
        Some(new_root),
        &Some(new_root),
        None,
        MsFlags::MS_BIND,
        None,
    )?;

    Ok(())
}
fn main() -> Result<(), Error> {
    enter_chroot("", "", "")?;
    Ok(())
}
