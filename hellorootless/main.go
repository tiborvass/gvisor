package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/rand"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"gvisor.googlesource.com/gvisor/pkg/sentry/loader"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ptrace"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/hostinet"
	//"gvisor.googlesource.com/gvisor/runsc/boot"
)

const debug = true

var (
	// Flags that control sandbox runtime behavior.
	platform       = flag.String("platform", "ptrace", "specifies which platform to use: ptrace (default), kvm")
	network        = flag.String("network", "sandbox", "specifies which network to use: sandbox (default), host, none. Using network inside the sandbox is more secure because it's isolated from the host network.")
	fileAccess     = flag.String("file-access", "exclusive", "specifies which filesystem to use for the root mount: exclusive (default), shared. Volume mounts are always shared.")
	overlay        = flag.Bool("overlay", false, "wrap filesystem mounts with writable overlay. All modifications are stored in memory inside the sandbox.")
	watchdogAction = flag.String("watchdog-action", "log", "sets what action the watchdog takes when triggered: log (default), panic.")
	panicSignal    = flag.Int("panic-signal", -1, "register signal handling that panics. Usually set to SIGUSR2(12) to troubleshoot hangs. -1 disables it.")
)

func init() {
}

func main() {
	/*
		flag.Parse()

		platformType, err := boot.MakePlatformType(*platform)
		if err != nil {
			log.Fatalf("%v", err)
		}

		fsAccess, err := boot.MakeFileAccessType(*fileAccess)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if fsAccess == boot.FileAccessShared && *overlay {
			log.Fatalf("overlay flag is incompatible with shared file access")
		}

		netType, err := boot.MakeNetworkType(*network)
		if err != nil {
			log.Fatalf("%v", err)
		}

		wa, err := boot.MakeWatchdogAction(*watchdogAction)
		if err != nil {
			log.Fatalf("%v", err)
		}

		// Create a new Config from the flags.
		conf := &boot.Config{
			RootDir:        "",
			Debug:          debug,
			FileAccess:     fsAccess,
			Overlay:        *overlay,
			Network:        netType,
			Platform:       platformType,
			WatchdogAction: wa,
			PanicSignal:    *panicSignal,
		}

		_ = conf

		/*
			// Setup rootfs and mounts. It returns a new mount list with destination
			// paths resolved. Replace the original spec with new mount list and start
			// container.
			cleanMounts, err := setupFS(c.Spec, conf, c.BundleDir)
			if err != nil {
				return fmt.Errorf("setup mounts: %v", err)
			}
			c.Spec.Mounts = cleanMounts

			// Create the gofer process.
			ioFiles, err := c.createGoferProcess(c.Spec, conf, c.BundleDir)
			if err != nil {
				return err
			}
			if err := c.Sandbox.Start(c.Spec, conf, c.ID, ioFiles); err != nil {
				return err
			}
			if err := c.Sandbox.AddGoferToCgroup(c.GoferPid); err != nil {
				return err
			}
	*/

	if err := func() error {
		// We initialize the rand package now to make sure /dev/urandom is pre-opened
		// on kernels that do not support getrandom(2).
		if err := rand.Init(); err != nil {
			return fmt.Errorf("error setting up rand: %v", err)
		}

		if err := usage.Init(); err != nil {
			return fmt.Errorf("error setting up memory usage: %v", err)
		}

		p, err := ptrace.New()
		if err != nil {
			return err
		}

		k := &kernel.Kernel{
			Platform: p,
		}

		// Create VDSO.
		//
		// Pass k as the platform since it is savable, unlike the actual platform.
		vdso, err := loader.PrepareVDSO(k)
		if err != nil {
			return err
		}

		// Create timekeeper.
		tk, err := kernel.NewTimekeeper(k, vdso.ParamPage.FileRange())
		if err != nil {
			return fmt.Errorf("error creating timekeeper: %v", err)
		}
		tk.SetClocks(time.NewCalibratedClocks())

		// Create an empty network stack because the network namespace may be empty at
		// this point. Netns is configured before Run() is called. Netstack is
		// configured using a control uRPC message. Host network is configured inside
		// Run().
		networkStack, err := newEmptyNetworkStack()
		if err != nil {
			return fmt.Errorf("failed to create network: %v", err)
		}

		// Create capabilities.
		/*
		caps, err := specutils.Capabilities(args.Spec.Process.Capabilities)
		if err != nil {
			return fmt.Errorf("error creating capabilities: %v", err)
		}
		*/

		// Convert the spec's additional GIDs to KGIDs.
		/*
		extraKGIDs := make([]auth.KGID, 0, len(args.Spec.Process.User.AdditionalGids))
		for _, GID := range args.Spec.Process.User.AdditionalGids {
			extraKGIDs = append(extraKGIDs, auth.KGID(GID))
		}
		*/

		// Create credentials.
		uid := 0 // os.Getuid() // args.Spec.Process.User.UID
		gid := 0 // os.Getgid() // args.Spec.Process.User.GID
		creds := auth.NewUserCredentials(
			auth.KUID(uid),
			auth.KGID(gid),
			[]auth.KGID{}, // extraKGIDs,
			nil, //caps,
			auth.NewRootUserNamespace())

		numCPU := runtime.NumCPU()

		/*
		if args.TotalMem > 0 {
			// Adjust the total memory returned by the Sentry so that applications that
			// use /proc/meminfo can make allocations based on this limit.
			usage.MinimumTotalMemoryBytes = args.TotalMem
			log.Infof("Setting total memory to %.2f GB", float64(args.TotalMem)/(2^30))
		}
		*/

		hostname, err := os.Hostname()
		if err != nil {
			return err
		}

		// Initiate the Kernel object, which is required by the Context passed
		// to createVFS in order to mount (among other things) procfs.
		if err = k.Init(kernel.InitKernelArgs{
			FeatureSet:                  cpuid.HostFeatureSet(),
			Timekeeper:                  tk,
			RootUserNamespace:           creds.UserNamespace,
			NetworkStack:                networkStack,
			ApplicationCores:            uint(numCPU),
			Vdso:                        vdso,
			RootUTSNamespace:            kernel.NewUTSNamespace(hostname, "", creds.UserNamespace),
			RootIPCNamespace:            kernel.NewIPCNamespace(creds.UserNamespace),
			RootAbstractSocketNamespace: kernel.NewAbstractSocketNamespace(),
		}); err != nil {
			fmt.Errorf("error initializing kernel: %v", err)
		}

		return nil
	}(); err != nil {
		log.Fatal(err)
	}

	Main()
}

func Main() {
	showmounts()

	if err := mount("/tmp/hello", 4*1024); err != nil {
		log.Fatal(err)
	}
	defer syscall.Unmount("/tmp/hello", 0)

	showmounts()
}

func mount(path string, size int64) error {
	os.MkdirAll(path, 0755)
	var flags uintptr
	flags = syscall.MS_NOATIME | syscall.MS_SILENT
	flags |= syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID
	options := ""
	if size >= 0 {
		options = "size=" + strconv.FormatInt(size, 10)
	}

	fmt.Println("Mounting tmpfs to", path)
	return syscall.Mount("tmpfs", path, "tmpfs", flags, options)
}

func showmounts() {
	b, err := ioutil.ReadFile("/proc/mounts")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}

//func newEmptyNetworkStack(conf *Config, clock tcpip.Clock) (inet.Stack, error) {
func newEmptyNetworkStack() (inet.Stack, error) {
	return hostinet.NewStack(), nil
}


