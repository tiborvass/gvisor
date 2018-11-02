package main

import (
	"fmt"
	"os"
	"runtime"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"gvisor.googlesource.com/gvisor/pkg/rand"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/loader"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ptrace"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/hostinet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	//"gvisor.googlesource.com/gvisor/runsc/boot"
)

const debug = true

func Boot() (func(), error) {
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

	// We initialize the rand package now to make sure /dev/urandom is pre-opened
	// on kernels that do not support getrandom(2).
	if err := rand.Init(); err != nil {
		return nil, fmt.Errorf("error setting up rand: %v", err)
	}

	if err := usage.Init(); err != nil {
		return nil, fmt.Errorf("error setting up memory usage: %v", err)
	}

	p, err := ptrace.New()
	if err != nil {
		return nil, err
	}

	k := &kernel.Kernel{
		Platform: p,
	}

	// Create VDSO.
	//
	// Pass k as the platform since it is savable, unlike the actual platform.
	vdso, err := loader.PrepareVDSO(k)
	if err != nil {
		return nil, err
	}

	// Create timekeeper.
	tk, err := kernel.NewTimekeeper(k, vdso.ParamPage.FileRange())
	if err != nil {
		return nil, fmt.Errorf("error creating timekeeper: %v", err)
	}
	tk.SetClocks(time.NewCalibratedClocks())

	// Create an empty network stack because the network namespace may be empty at
	// this point. Netns is configured before Run() is called. Netstack is
	// configured using a control uRPC message. Host network is configured inside
	// Run().
	networkStack := hostinet.NewStack()

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
		nil,           //caps,
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
		return nil, err
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
		return nil, fmt.Errorf("error initializing kernel: %v", err)
	}

	// run

	if err := networkStack.Configure(); err != nil {
		return nil, err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	procArgs := kernel.CreateProcessArgs{
		Argv:             os.Args,
		Envv:             os.Environ(),
		WorkingDirectory: cwd, // Defaults to '/' if empty.
		Credentials:      creds,
		Umask:            0022,
		//Limits:                  ls,
		MaxSymlinkTraversals:    linux.MaxSymlinkTraversals,
		UTSNamespace:            k.RootUTSNamespace(),
		IPCNamespace:            k.RootIPCNamespace(),
		AbstractSocketNamespace: k.RootAbstractSocketNamespace(),
		ContainerID:             "1234567890",
	}

	rootCtx := procArgs.NewContext(k)
	rootMns := k.RootMountNamespace()
	if err := setExecutablePath(rootCtx, rootMns, &procArgs); err != nil {
		return nil, fmt.Errorf("error setting executable path for %+v: %v", procArgs, err)
	}

	// Create the root container init task.
	_, _, err = k.CreateProcess(procArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to create init process: %v", err)
	}

	// CreateProcess takes a reference on FDMap if successful.
	procArgs.FDMap.DecRef()

	//watchdog.Start()
	if err := k.Start(); err != nil {
		return nil, err
	}

	return func() {
	}, nil
}

// setExecutablePath sets the procArgs.Filename by searching the PATH for an
// executable matching the procArgs.Argv[0].
func setExecutablePath(ctx context.Context, mns *fs.MountNamespace, procArgs *kernel.CreateProcessArgs) error {
	paths := fs.GetPath(procArgs.Envv)
	f, err := mns.ResolveExecutablePath(ctx, procArgs.WorkingDirectory, procArgs.Argv[0], paths)
	if err != nil {
		return err
	}
	procArgs.Filename = f
	return nil
}

/*
// setupContainerFS is used to set up the file system and amend the procArgs accordingly.
// procArgs are passed by reference and the FDMap field is modified. It dups stdioFDs.
func setupContainerFS(procArgs *kernel.CreateProcessArgs, spec *specs.Spec, conf *Config, stdioFDs, goferFDs []int, console bool, creds *auth.Credentials, ls *limits.LimitSet, k *kernel.Kernel, cid string) error {
	ctx := procArgs.NewContext(k)

	// Create the FD map, which will set stdin, stdout, and stderr.  If
	// console is true, then ioctl calls will be passed through to the host
	// fd.
	fdm, err := createFDMap(ctx, k, ls, console, stdioFDs)
	if err != nil {
		return fmt.Errorf("error importing fds: %v", err)
	}

	// CreateProcess takes a reference on FDMap if successful. We
	// won't need ours either way.
	procArgs.FDMap = fdm

	// Use root user to configure mounts. The current user might not have
	// permission to do so.
	rootProcArgs := kernel.CreateProcessArgs{
		WorkingDirectory:     "/",
		Credentials:          auth.NewRootCredentials(creds.UserNamespace),
		Umask:                0022,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
	}
	rootCtx := rootProcArgs.NewContext(k)

	// If this is the root container, we also need to setup the root mount
	// namespace.
	mns := k.RootMountNamespace()
	if mns == nil {
		// Setup the root container.

		// Create the virtual filesystem.
		mns, err := createMountNamespace(ctx, rootCtx, spec, conf, goferFDs)
		if err != nil {
			return fmt.Errorf("error creating mounts: %v", err)
		}
		k.SetRootMountNamespace(mns)

		// We're done with root container.
		return nil
	}

	// Setup a child container.

	// Create the container's root filesystem mount.
	log.Infof("Creating new process in child container.")
	fds := &fdDispenser{fds: append([]int{}, goferFDs...)}
	rootInode, err := createRootMount(rootCtx, spec, conf, fds, nil)
	if err != nil {
		return fmt.Errorf("error creating filesystem for container: %v", err)
	}

	globalRoot := mns.Root()
	defer globalRoot.DecRef()

	// Create mount point for the container's rootfs.
	contDir, err := mns.FindInode(ctx, globalRoot, nil, ChildContainersDir, 0 /* TraversalLimit */ /*)
	if err != nil {
		return fmt.Errorf("couldn't find child container dir %q: %v", ChildContainersDir, err)
	}
	if err := contDir.CreateDirectory(ctx, globalRoot, cid, fs.FilePermsFromMode(0755)); err != nil {
		return fmt.Errorf("create directory %q: %v", cid, err)
	}
	containerRoot, err := contDir.Walk(ctx, globalRoot, cid)
	if err != nil {
		return fmt.Errorf("walk to %q failed: %v", cid, err)
	}
	defer containerRoot.DecRef()

	// Mount the container's root filesystem to the newly created mount point.
	if err := mns.Mount(ctx, containerRoot, rootInode); err != nil {
		return fmt.Errorf("mount container root: %v", err)
	}

	// We have to re-walk to the dirent to find the mounted
	// directory. The old dirent is invalid at this point.
	containerRoot, err = contDir.Walk(ctx, globalRoot, cid)
	if err != nil {
		return fmt.Errorf("find container mount point %q: %v", cid, err)
	}

	log.Infof("Mounted child's root fs to %q", filepath.Join(ChildContainersDir, cid))

	// Mount all submounts.
	mounts := compileMounts(spec)
	for _, m := range mounts {
		if err := mountSubmount(rootCtx, conf, k.RootMountNamespace(), containerRoot, fds, m, mounts); err != nil {
			containerRoot.DecRef()
			return fmt.Errorf("error mounting filesystem for container: %v", err)
		}
	}

	// Set the procArgs root directory.
	procArgs.Root = containerRoot
	return nil
}
*/
