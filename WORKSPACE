workspace(name = "com_google_ghost")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")


http_archive(
  name = "rules_cc",
  url = "https://github.com/bazelbuild/rules_cc/archive/262ebec3c2296296526740db4aefce68c80de7fa.zip",
  sha256 = "9a446e9dd9c1bb180c86977a8dc1e9e659550ae732ae58bd2e8fd51e15b2c91d",
  strip_prefix = "rules_cc-262ebec3c2296296526740db4aefce68c80de7fa",
)

http_archive(
    name = "rules_foreign_cc",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/99ea7e75c2a48cc233ff5e7682c1a31516faa84b.tar.gz",
    sha256 = "06fb31803fe3d2552f988f3c2fee430b10d566bc77dd7688897eca5388107883",
    strip_prefix = "rules_foreign_cc-99ea7e75c2a48cc233ff5e7682c1a31516faa84b",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

http_archive(
  name = "com_google_absl",
  url = "https://github.com/abseil/abseil-cpp/archive/2e9532cc6c701a8323d0cffb468999ab804095ab.zip",
  sha256 = "542dee3a6692cf7851329f4f9f4de463bb6305c7e0439946d4ba750852e4d71c",
  strip_prefix = "abseil-cpp-2e9532cc6c701a8323d0cffb468999ab804095ab",
)


