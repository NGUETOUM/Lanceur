
compiler_flags = [
    "-Wno-sign-compare",
    "-DGHOST_LOGGING",
]

cc_binary(
  name = "launcher",
  copts = compiler_flags,
  deps = ["@com_google_absl//absl/time",
          "@com_google_absl//absl/base",
          "@com_google_absl//absl/container:node_hash_map",
          "@com_google_absl//absl/container:flat_hash_map",
          "@com_google_absl//absl/container:flat_hash_set",
          "@com_google_absl//absl/debugging:stacktrace",
          "@com_google_absl//absl/debugging:symbolize",
          "@com_google_absl//absl/strings",
          "@com_google_absl//absl/flags:flag",
          "@com_google_absl//absl/strings:str_format",
          "@com_google_absl//absl/memory",
          "@com_google_absl//absl/synchronization",
          "@com_google_absl//absl/functional:bind_front",
          ],
  srcs = ["launcher.cc",
          "shared/prio_table.cc",
          "shared/shmem.cc",
          "shared/base.cc",
          "shared/ghost.cc",
          "experiments/ghost.cc",
          "experiments/prio_table_helper.cc",
          "shared/topology.cc",
          "shared/ghost_uapi.h",
          "shared/base.h",
          "shared/logging.h",
          "shared/prio_table.h",
          "shared/shmem.h",
          "shared/ghost.h",
          "experiments/ghost.h",
          "experiments/prio_table_helper.h",
          "shared/topology.h",
         ],
)