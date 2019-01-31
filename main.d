// Steps:
// 1) enter user,mount namespace
// 2) mount required file systems
// 3) move mount
// 4) enter pid namespace, mount /proc
// 4) execute, wait for it to quit
// 5) unmount everything
struct mntent {
	char* mnt_fsname;   /* name of mounted filesystem */
	char* mnt_dir;      /* filesystem path prefix */
	char* mnt_type;     /* mount type (see mntent.h) */
	char* mnt_opts;     /* mount options (see mntent.h) */
	int   mnt_freq;     /* dump frequency in days */
	int   mnt_passno;   /* pass number on parallel fsck */
}

struct cap_t;

import core.stdc.stdio : fopen, fclose, FILE;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;
import core.sys.posix.sys.wait;
import std.algorithm,
       std.conv,
       std.string;
import core.stdc.string;
import std.stdio : writeln, File;
extern(C) int unshare(int);
extern(C) mntent *getmntent(FILE*);
extern(C) int umount(const(char)*);
extern(C) int mount(const(char)*, const(char)*, const(char)*, ulong, const(void)*);
extern(C) int pivot_root(const(char)*, const(char)*);
extern(C) int sethostname(const(char)*, size_t);

enum CLONE_NEWNS = 0x20000;
enum CLONE_NEWUSER = 0x10000000;
enum CLONE_NEWPID = 0x20000000;
enum CLONE_NEWUTS = 0x04000000;
enum MS_NOSUID = 2;
enum MS_NODEV = 4;
enum MS_NOEXEC = 8;
enum MS_BIND = 4096;
enum MS_MOVE = 8192;
enum MS_REC = 16384;
enum MS_PRIVATE = 1<<18;
void start_chroot(string new_root, string cmd, string hostname) {
	import std.format;
	chdir("/");
	int old_uid = getuid, old_gid = getgid;

	auto flags = CLONE_NEWNS|CLONE_NEWPID;
	if (hostname && hostname != "")
		flags |= CLONE_NEWUTS;
	int uid = geteuid;
	if (uid)
		flags |= CLONE_NEWUSER;
	int ret = unshare(flags);

	if (uid) {
		int fd = open("/proc/self/setgroups", O_WRONLY);
		string map = "deny";
		write(fd, map.ptr, map.length);
		close(fd);

		fd = open("/proc/self/uid_map", O_WRONLY);
		map = format("%s %s %s", 0, old_uid, 1);
		write(fd, map.ptr, map.length);
		close(fd);

		fd = open("/proc/self/gid_map", O_WRONLY);
		map = format("%s %s %s", 0, old_gid, 1);
		write(fd, map.ptr, map.length);
		close(fd);
	}

	if (hostname && hostname != "")
		sethostname(hostname.ptr, hostname.length);

	FILE* mnt = fopen("/proc/mounts", "r");
	mntent* buf;

	string[] dirs;
	mntloop:while ((buf = getmntent(mnt)) !is null) {
		// we want to bind mount everything
		string mnt_dir = buf.mnt_dir[0..strlen(buf.mnt_dir)].to!string;
		if (mnt_dir != "/") {//&& mnt_dir != "/proc") {
			foreach(d; dirs) {
				// we are going to use recursive mount
				// so make sure to only keep top level
				if (mnt_dir.startsWith(d))
					continue mntloop;
			}
			dirs ~= mnt_dir;
		}
	}
	fclose(mnt);

	ret = mount(null, "/", null, MS_REC|MS_PRIVATE, null);
	assert(ret == 0);
	//ret = mount("/", "/", null, MS_REC|MS_BIND, null);
	//assert(ret == 0);
	foreach(d; dirs) {
		if (!new_root.startsWith(d))
			continue;
		import std.file : exists, isDir;
		assert(d[0] == '/');
		string new_path = new_root~d;
		if (new_path.exists && new_path.isDir) {
			ret = mount(d.toStringz, new_path.toStringz, null, MS_BIND|MS_REC, null);
			assert(ret == 0);
		}
	}
	foreach(d; dirs) {
		if (new_root.startsWith(d))
			continue;
		import std.file : exists, isDir;
		assert(d[0] == '/');
		string new_path = new_root~d;
		if (new_path.exists && new_path.isDir) {
			ret = mount(d.toStringz, new_path.toStringz, null, MS_BIND|MS_REC, null);
			assert(ret == 0);
		}
	}

	ret = mount(new_root.toStringz, new_root.toStringz, null, MS_REC|MS_BIND, null);
	assert(ret == 0);
	{
		auto f = File("/proc/self/mountinfo");
		foreach(l; f.byLine)
			writeln(l);
	}

	version(none) {
	ret = mount (new_root.toStringz, "/", null, MS_MOVE, null);
	assert(ret == 0);
	}

	pivot_root(new_root.toStringz, (new_root~"/tmp/old_root").toStringz);

	import core.stdc.signal : raise;
	raise(SIGSTOP);
	assert(ret == 0);
	//ret = mount("none", "/proc", "proc", 0xc0ed0000, null);
	//assert(ret == 0);

	//ret = umount("/tmp/old_root");
	//assert(ret == 0);
	//rmdir("/tmp/old_root");
	auto pid = fork();
	if (pid) {
		int status;
		waitpid(pid, &status, 0);
	} else {
		ret = mount("/proc", (new_root~"/proc").toStringz, null, MS_MOVE, null);
		assert(ret == 0);
		ret = mount("none", "/proc", "proc", 0xc0ed0000, null);
		assert(ret == 0);
		//ret = umount((new_root~"/proc").toStringz);
		//assert(ret == 0);
		execlp(cmd.toStringz, null);
	}
}
void main(string[] args) {
	import std.file : mkdir, rmdir;
	import std.path, std.array;
	assert(args.length >= 2);
	mkdir("/tmp/old_root");
	auto pid = fork();
	if (pid) {
		enum WSTOPPED = 2;
		int status;
		waitpid(pid, &status, WSTOPPED);
		rmdir("/tmp/old_root");
		kill(pid, SIGCONT);
		waitpid(pid, &status, 0);
	} else {
		start_chroot(args[1].asAbsolutePath.asNormalizedPath.array, args.length > 2 ? args[2] : "sh", args.length > 3 ? args[3] : []);
	}
}
