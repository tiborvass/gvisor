package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "hellorootless",
    srcs = [
        "main.go",
    ],
    pure = "on",
    visibility = [
        "//visibility:public",
    ],
    x_defs = {"main.gitRevision": "{GIT_REVISION}"},
    deps = [
        #"//pkg/log",
	"//pkg/sentry/loader",
	"//pkg/rand",
	"//pkg/abi/linux",
	"//pkg/cpuid",
	"//pkg/sentry/kernel",
	"//pkg/sentry/usage",
	"//pkg/sentry/platform/ptrace",
	"//pkg/sentry/time",
	#"//pkg/sentry/inet",
	"//pkg/sentry/kernel/auth",
	"//pkg/sentry/socket/hostinet",
        #"//runsc/boot",
        #"//runsc/cmd",
        #"//runsc/specutils",
        #"@com_github_google_subcommands//:go_default_library",
    ],
)


