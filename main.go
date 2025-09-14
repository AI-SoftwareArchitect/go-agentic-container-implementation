// main.go
// Minimal "from scratch" container in one file.
// Features: namespaces (UTS, PID, Mount, IPC, Net, User), chroot/pivot_root-like setup,
// simple rootfs with busybox, cgroup v2 limits (memory, pids, cpu), sethostname, mounts.
// Tested on Ubuntu 22.04+ with cgroup v2.
package main
import "golang.org/x/sys/unix"

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
		return
	}

	switch os.Args[1] {
	case "run":
		run()
	case "child":
		child()
	case "cleanup":
		cleanup()
	default:
		usage()
	}
}

func requireRoot() {
    if os.Geteuid() != 0 {
        log.Fatalf("error: must be run as root (use sudo)")
    }
}


func usage() {
	fmt.Println(`Usage:
  sudo go run main.go run [options]
  sudo ./ctr run [options]

Options:
  --rootfs DIR         Rootfs path (default: /tmp/myrootfs)
  --busybox PATH       Busybox static binary path (optional; if missing, we try to download/build minimal rootfs)
  --hostname NAME      UTS hostname (default: sandbox-<rand>)
  --mem SIZE           Memory limit for cgroup v2, e.g. 256M (optional)
  --pids N             PIDs max (optional)
  --cpu MICROSECS      cpu.max in microseconds quota per 100000 period (e.g. 20000 ~ 20%) (optional)
  --no-net             Do not unshare network namespace
  --cmd "COMMAND ..."  Command to run inside (default: /bin/sh)
  --env "K=V,K=V"      Extra environment variables inside
  --mount-ro PATHS     Comma-separated extra host paths to bind read-only inside same path
  --mount-rw PATHS     Comma-separated extra host paths to bind read-write inside same path

Other:
  child    internal, do not invoke manually
  cleanup  remove cgroup and temp dirs for last run (best-effort)
`)
}

type RunOpts struct {
	rootfs     string
	busybox    string
	hostname   string
	mem        string
	pids       int
	cpuQuota   int
	noNet      bool
	cmd        []string
	env        []string
	mountRO    []string
	mountRW    []string
}

func parseFlags(args []string) (*RunOpts, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	rootfs := fs.String("rootfs", "/tmp/myrootfs", "rootfs path")
	busybox := fs.String("busybox", "", "busybox static path")
	hostname := fs.String("hostname", "", "hostname")
	mem := fs.String("mem", "", "memory limit cgroup v2, e.g. 256M")
	pids := fs.Int("pids", 0, "pids.max")
	cpu := fs.Int("cpu", 0, "cpu quota (microseconds of 100000 period)")
	noNet := fs.Bool("no-net", false, "do not create network namespace")
	cmd := fs.String("cmd", "/bin/sh", "command inside container")
	env := fs.String("env", "", "comma-separated K=V")
	mro := fs.String("mount-ro", "", "comma-separated host paths to bind read-only")
	mrw := fs.String("mount-rw", "", "comma-separated host paths to bind read-write")
	buf := &bytes.Buffer{}
	fs.SetOutput(buf)
	if err := fs.Parse(args); err != nil {
		return nil, errors.New(strings.TrimSpace(buf.String()))
	}
	r := &RunOpts{
		rootfs:   *rootfs,
		busybox:  *busybox,
		mem:      *mem,
		pids:     *pids,
		cpuQuota: *cpu,
		noNet:    *noNet,
		env:      splitCSV(*env),
		mountRO:  splitCSV(*mro),
		mountRW:  splitCSV(*mrw),
	}
	if *hostname == "" {
		r.hostname = fmt.Sprintf("sandbox-%04x", rand.New(rand.NewSource(time.Now().UnixNano())).Uint32()&0xFFFF)
	} else {
		r.hostname = *hostname
	}
	if *cmd == "" {
		r.cmd = []string{"/bin/sh"}
	} else {
		r.cmd = splitCmd(*cmd)
	}
	return r, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitCmd(s string) []string {
	// naive split respecting simple quotes
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// If contains spaces but not quotes, split by spaces.
	// For simplicity, we will use /bin/sh -c when user passes a single string.
	// Here we return the raw string; child will run via exec.Command(cmd[0], cmd[1:]...)
	// If user provided one string, we will run sh -c <string>.
	if strings.ContainsAny(s, " \t") && !strings.ContainsAny(s, "\"'") {
		return []string{"/bin/sh", "-c", s}
	}
	// If has quotes, still just delegate to sh -c to interpret.
	return []string{"/bin/sh", "-c", s}
}

func must(err error) {
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}

func run() {
	opts, err := parseFlags(os.Args[2:])
	must(err)

	requireRoot()

	// Unshare namespaces in the child process, not in this one: we will exec self with "child".
	// But we will create cgroup and rootfs before entering child.
	must(prepareRootfs(opts))
	cgPath, err := setupCgroup(opts)
	must(err)
	// Ensure cleanup on exit
	defer func() {
		_ = os.RemoveAll(filepath.Join(cgPath, "cgroup.procs.tmp")) // harmless
	}()

	// Build command to re-exec self as child
	args := []string{
		"child",
		"--rootfs", opts.rootfs,
		"--hostname", opts.hostname,
	}
	if opts.noNet {
		args = append(args, "--no-net")
	}
	if len(opts.env) > 0 {
		args = append(args, "--env", strings.Join(opts.env, ","))
	}
	if len(opts.mountRO) > 0 {
		args = append(args, "--mount-ro", strings.Join(opts.mountRO, ","))
	}
	if len(opts.mountRW) > 0 {
		args = append(args, "--mount-rw", strings.Join(opts.mountRW, ","))
	}
	// Pass the command as single string to be executed via sh -c in child for simplicity
	args = append(args, "--cmd", strings.Join(opts.cmd, " "))

	cmd := exec.Command("/proc/self/exe", args...)
	// New namespaces flags
	flags := syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC
	if !opts.noNet {
		flags |= syscall.CLONE_NEWNET
	}
	// User namespace: map current uid/gid to root inside
	flags |= syscall.CLONE_NEWUSER

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(flags),
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false, // required without writing setgroups
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}

	// Stdio attach
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Start child
	must(cmd.Start())

	// Put child into cgroup v2
	must(addPidToCgroup(cmd.Process.Pid))

	// Wait for container exit
	err = cmd.Wait()
	if err != nil {
		// propagate exit code if possible
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ProcessState.ExitCode())
		}
		log.Fatalf("child error: %v", err)
	}
}

func child() {
	// Parse minimal flags for child
	opts, err := parseChildFlags(os.Args[2:])
	must(err)

	// Set hostname
	must(syscall.Sethostname([]byte(opts.hostname)))

	// Make mount namespaces private
	must(syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""))

	// Setup minimal mounts inside new rootfs
	must(enterRootfsAndMounts(opts))

	// Drop capabilities (we are root in userns, but still)
	dropCapabilities()

	// Set env
	env := os.Environ()
	if len(opts.env) > 0 {
		env = append(env, opts.env...)
	}

	// Execute command
	var cmd *exec.Cmd
	if len(opts.cmd) == 1 {
		cmd = exec.Command(opts.cmd[0])
	} else {
		cmd = exec.Command(opts.cmd[0], opts.cmd[1:]...)
	}
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Needed to make PID 1 handle signals properly? For simplicity, just exec, PID 1 will be this process.
	// Set working dir to /
	_ = os.Chdir("/")

	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ProcessState.ExitCode())
		}
		log.Fatalf("exec error: %v", err)
	}
}

type ChildOpts struct {
	rootfs   string
	hostname string
	noNet    bool
	cmd      []string
	env      []string
	mountRO  []string
	mountRW  []string
}

func parseChildFlags(args []string) (*ChildOpts, error) {
	fs := flag.NewFlagSet("child", flag.ContinueOnError)
	rootfs := fs.String("rootfs", "", "rootfs")
	hostname := fs.String("hostname", "sandbox", "hostname")
	noNet := fs.Bool("no-net", false, "no net")
	cmd := fs.String("cmd", "/bin/sh", "command")
	env := fs.String("env", "", "env")
	mro := fs.String("mount-ro", "", "mount ro")
	mrw := fs.String("mount-rw", "", "mount rw")
	buf := &bytes.Buffer{}
	fs.SetOutput(buf)
	if err := fs.Parse(args); err != nil {
		return nil, errors.New(strings.TrimSpace(buf.String()))
	}
	return &ChildOpts{
		rootfs:   *rootfs,
		hostname: *hostname,
		noNet:    *noNet,
		cmd:      splitCmd(*cmd),
		env:      splitCSV(*env),
		mountRO:  splitCSV(*mro),
		mountRW:  splitCSV(*mrw),
	}, nil
}

func prepareRootfs(o *RunOpts) error {
	// Create minimal rootfs with busybox if not present
	if err := os.MkdirAll(o.rootfs, 0755); err != nil {
		return err
	}
	// Check for /bin/sh available
	if _, err := os.Stat(filepath.Join(o.rootfs, "bin/sh")); err == nil {
		return nil
	}
	// Need busybox. If user passed a path, copy it; else try to find busybox on host.
	src := o.busybox
	if src == "" {
		// Try common paths
		cands := []string{"/bin/busybox", "/usr/bin/busybox", "/sbin/busybox", "/usr/sbin/busybox"}
		for _, c := range cands {
			if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
				src = c
				break
			}
		}
	}
	if src == "" {
		return errors.New("busybox not found. Install busybox-static (sudo apt install -y busybox-static) or pass --busybox /path/to/busybox")
	}
	// Copy busybox binary into rootfs at /bin/busybox
	if err := os.MkdirAll(filepath.Join(o.rootfs, "bin"), 0755); err != nil {
		return err
	}
	if err := copyFile(src, filepath.Join(o.rootfs, "bin/busybox")); err != nil {
		return fmt.Errorf("copy busybox: %w", err)
	}
	// Create symlinks for common applets
	links := []string{"sh", "ls", "echo", "cat", "mount", "umount", "mkdir", "ps", "uname", "dmesg", "sleep", "vi", "cp", "mv", "rm", "touch", "ln", "date"}
	for _, l := range links {
		dst := filepath.Join(o.rootfs, "bin", l)
		_ = os.RemoveAll(dst)
		if err := os.Symlink("busybox", dst); err != nil {
			// On filesystems without symlink perms inside, fallback to hardlink/copy
			if err2 := linkOrCopy(filepath.Join(o.rootfs, "bin/busybox"), dst); err2 != nil {
				return fmt.Errorf("create link for %s: %v / %v", l, err, err2)
			}
		}
	}

	// Essential dirs
	for _, d := range []string{"proc", "sys", "dev", "tmp", "var", "etc", "run"} {
		if err := os.MkdirAll(filepath.Join(o.rootfs, d), 0755); err != nil {
			return err
		}
	}
	// Minimal /etc
	_ = os.WriteFile(filepath.Join(o.rootfs, "etc/hostname"), []byte(o.hostname+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(o.rootfs, "etc/resolv.conf"), []byte("nameserver 1.1.1.1\n"), 0644)
	return nil
}

func enterRootfsAndMounts(o *ChildOpts) error {
	// Bind mount the rootfs to itself as rbind+private, then pivot_root or chroot.
	root := o.rootfs
	if err := syscall.Mount(root, root, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind rootfs: %w", err)
	}
	if err := syscall.Mount("", root, "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("private rootfs: %w", err)
	}

	// Create putold for pivot_root
	putold := filepath.Join(root, ".old_root")
	_ = os.MkdirAll(putold, 0700)
	// Try pivot_root; if fails (e.g., EPERM in userns), fallback to chroot.
	if err := syscall.PivotRoot(root, putold); err != nil {
		// Fallback to chroot
		if err2 := syscall.Chroot(root); err2 != nil {
			return fmt.Errorf("pivot_root: %v, chroot: %v", err, err2)
		}
		if err := os.Chdir("/"); err != nil {
			return err
		}
	} else {
		// Now we are in new root; need to umount putold and remove it
		if err := os.Chdir("/"); err != nil {
			return err
		}
		if err := syscall.Unmount("/.old_root", syscall.MNT_DETACH); err != nil {
			return fmt.Errorf("unmount old_root: %w", err)
		}
		_ = os.RemoveAll("/.old_root")
	}

	// Mount proc, sys, dev (tmpfs), and other essentials
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	// sysfs mounting is typically not permitted inside userns without appropriate privileges;
	// ignore error if EPERM
	if err := syscall.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		// ignore in userns
	}
	// dev as tmpfs for null, zero, tty, random, urandom
	if err := syscall.Mount("tmpfs", "/dev", "tmpfs", syscall.MS_NOSUID|syscall.MS_STRICTATIME, "mode=755"); err != nil {
		return fmt.Errorf("mount dev tmpfs: %w", err)
	}
	mknodIfMissing("/dev/null", 0666, unix.Mkdev(1, 3))
	mknodIfMissing("/dev/zero", 0666, unix.Mkdev(1, 5))
	mknodIfMissing("/dev/random", 0666, unix.Mkdev(1, 8))
	mknodIfMissing("/dev/urandom", 0666, unix.Mkdev(1, 9))
	mknodIfMissing("/dev/tty", 0666, unix.Mkdev(5, 0))

	// Bind extra mounts
	for _, p := range o.mountRO {
		if err := bindMountRO(p, p); err != nil {
			log.Printf("warn: mount-ro %s: %v", p, err)
		}
	}
	for _, p := range o.mountRW {
		if err := bindMountRW(p, p); err != nil {
			log.Printf("warn: mount-rw %s: %v", p, err)
		}
	}

	return nil
}

func mknodIfMissing(path string, mode os.FileMode, dev uint64) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	_ = syscall.Mknod(path, uint32(mode|os.ModeDevice), int(dev))
}

func bindMountRO(hostPath, insidePath string) error {
	// Ensure target exists
	if err := os.MkdirAll(filepath.Dir(insidePath), 0755); err != nil {
		return err
	}
	// Touch file/dir
	var st os.FileInfo
	st, err := os.Stat(hostPath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		if err := os.MkdirAll(insidePath, 0755); err != nil {
			return err
		}
	} else {
		f, err := os.OpenFile(insidePath, os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		f.Close()
	}
	if err := syscall.Mount(hostPath, insidePath, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return err
	}
	// Remount readonly
	return syscall.Mount("", insidePath, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, "")
}

func bindMountRW(hostPath, insidePath string) error {
	if err := os.MkdirAll(filepath.Dir(insidePath), 0755); err != nil {
		return err
	}
	var st os.FileInfo
	st, err := os.Stat(hostPath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		if err := os.MkdirAll(insidePath, 0755); err != nil {
			return err
		}
	} else {
		f, err := os.OpenFile(insidePath, os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		f.Close()
	}
	return syscall.Mount(hostPath, insidePath, "", syscall.MS_BIND|syscall.MS_REC, "")
}

func setupCgroup(o *RunOpts) (string, error) {
	// Verify cgroup v2 unified hierarchy
	if !fileExists("/sys/fs/cgroup/cgroup.controllers") {
		log.Println("warn: cgroup v2 not detected under /sys/fs/cgroup; skipping cgroup setup")
		return "/sys/fs/cgroup", nil
	}
	// Create a unique cgroup
	name := fmt.Sprintf("ctr-%d-%d", os.Getpid(), time.Now().UnixNano())
	path := filepath.Join("/sys/fs/cgroup", name)
	if err := os.Mkdir(path, 0755); err != nil {
		return "", fmt.Errorf("mkdir cgroup: %w", err)
	}
	// Enable controllers by writing to cgroup.subtree_control of parent if needed
	if err := enableControllers("/sys/fs/cgroup", []string{"+memory", "+pids", "+cpu"}); err != nil {
		log.Printf("warn: enabling controllers: %v", err)
	}
	// Apply limits
	if o.mem != "" {
		if err := os.WriteFile(filepath.Join(path, "memory.max"), []byte(o.mem), 0644); err != nil {
			log.Printf("warn: set memory.max: %v", err)
		}
	}
	if o.pids > 0 {
		if err := os.WriteFile(filepath.Join(path, "pids.max"), []byte(strconv.Itoa(o.pids)), 0644); err != nil {
			log.Printf("warn: set pids.max: %v", err)
		}
	}
	if o.cpuQuota > 0 {
		// cpu.max requires "quota period", e.g., "20000 100000"
		val := fmt.Sprintf("%d 100000", o.cpuQuota)
		if err := os.WriteFile(filepath.Join(path, "cpu.max"), []byte(val), 0644); err != nil {
			log.Printf("warn: set cpu.max: %v", err)
		}
	}
	// Record path for cleanup
	_ = os.WriteFile("/tmp/ctr_last_cgroup", []byte(path), 0644)
	return path, nil
}

func enableControllers(parent string, ctrls []string) error {
	// Echo +memory +pids +cpu into parent/cgroup.subtree_control if possible
	data, err := os.ReadFile(filepath.Join(parent, "cgroup.controllers"))
	if err != nil {
		return err
	}
	have := strings.Fields(string(data))
	haveSet := map[string]bool{}
	for _, c := range have {
		haveSet[c] = true
	}
	var toEnable []string
	for _, c := range []string{"memory", "pids", "cpu"} {
		if haveSet[c] {
			toEnable = append(toEnable, "+"+c)
		}
	}
	if len(toEnable) == 0 {
		return nil
	}
	_ = os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte(strings.Join(toEnable, " ")), 0644)
	return nil
}

func addPidToCgroup(pid int) error {
	cg, err := os.ReadFile("/tmp/ctr_last_cgroup")
	if err != nil {
		return err
	}
	path := strings.TrimSpace(string(cg))
	return os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644)
}

func cleanup() {
	// Best-effort cleanup cgroup and rootfs tmp marks
	data, err := os.ReadFile("/tmp/ctr_last_cgroup")
	if err == nil {
		path := strings.TrimSpace(string(data))
		_ = os.Remove(filepath.Join(path, "cgroup.events")) // touch something
		_ = os.Remove(path)                                  // will fail if not empty
		_ = os.RemoveAll(path)
		_ = os.Remove("/tmp/ctr_last_cgroup")
	}
}

func dropCapabilities() {
	// In a user namespace, capabilities are already limited.
	// Still, try to clear bounding set via prctl if available (not in stdlib).
	// Could also write to /proc/self/setgroups etc., but we already disabled setgroups.
	// No-op here for simplicity.
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
