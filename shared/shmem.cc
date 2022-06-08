// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "shmem.h"

#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <filesystem>
#include <string>
#include "prio_table.h"
#include "absl/strings/str_cat.h"

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001 /* prevent further seals from being set */
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002 /* prevent file from shrinking */
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004 /* prevent file from growing */
#endif

namespace fs = std::filesystem;

namespace ghost {

constexpr size_t kHugepageSize = 2 * 1024 * 1024;
static const char* kMemFdPrefix = "ghost-shmem-";

#define MFD_GOOGLE_SPECIFIC_BASE 0x0200U
#define MFD_HUGEPAGE (MFD_GOOGLE_SPECIFIC_BASE << 0)

// Please don't use "0" as a header version, it's not distinguishable from
// an uninitialized header.
static constexpr int64_t kHeaderVersion = 1;

// This currently occupies the first page of every mapping (from offset zero).
struct GhostShmem::InternalHeader {
  int64_t header_version;

  size_t mapping_size;
  size_t header_size;
  size_t client_size;

  std::atomic<bool> ready, finished;

  int owning_pid;
  int64_t client_version;
};

int file_decriptor = -1;

GhostShmem::GhostShmem(int64_t client_version, const char* name, size_t size) {
  CreateShmem(client_version, name, size);
}

GhostShmem::GhostShmem(int64_t client_version, const char* name, size_t size, int fd) {
  CreateShmem(client_version, name, size, fd);
}

/*GhostShmem::GhostShmem(int64_t client_version, const char* name, size_t size) {
  int fd = 0;
  CreateShmem(client_version, name, size, remote, fd);
}*/
int GhostShmem::Attach(int64_t client_version, const char* name, pid_t pid) {
  return ConnectShmem(client_version, name, pid);
}

int GhostShmem::Attach(int64_t client_version, const char* name, pid_t pid, int fd) {
  return ConnectShmem(client_version, name, pid, fd);
}

/*int GhostShmem::Attach(int64_t client_version, const char* name, pid_t pid, int fd, uint32_t sched_items, uint32_t work_classes,
                         uint32_t stream_capacity){
  return ConnectShmem(client_version, name, pid, fd, sched_items, work_classes, stream_capacity);
}*/

GhostShmem::~GhostShmem() {
  if (hdr_) {
    hdr_->finished.store(true);
  }
  if (shmem_) {
    munmap(shmem_, map_size_);
  }
  if (memfd_ >= 0) {
    close(memfd_);
  }
}


static size_t shmem_size(uint32_t sched_items, uint32_t work_classes,
                         uint32_t stream_capacity) {
  size_t sz = 0;

  sz += sizeof(struct legorch_shmem_hdr);
  sz += sizeof(struct sched_item) * sched_items;
  sz += sizeof(struct work_class) * work_classes;
  // Check that 'sz' is a multiple of the cacheline size so that the stream
  // starts on a new cacheline
  // The three structs above are each aligned to a cacheline, so this check
  // should succeed
  CHECK_ZERO(sz % ABSL_CACHELINE_SIZE);
  sz += sizeof(struct ghost::PrioTable::stream) +
        sizeof(std::atomic<int>) * stream_capacity;

  return sz;
}



void GhostShmem::MarkReady() { hdr_->ready.store(true); }

void GhostShmem::WaitForReady() {
  // TODO: Use a shared futex here.
  while (!hdr_->ready.load()) {
  }
}

size_t GhostShmem::size() {
  // We apply internal adjustments, e.g. our header, hugepages, etc.
  return hdr_->client_size;
}



void GhostShmem::CreateShmem(int64_t client_version, const char* suffix,
                             size_t size) {
  int MFD_FLAGS = MFD_CLOEXEC | MFD_ALLOW_SEALING;
  const int MFD_SEALS = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  std::string name;

  // Suffixes must currently be unique for the hosting process.
  CHECK_EQ(OpenGhostShmemFd(suffix, Gtid::Current().tid()), -1);

  name = kMemFdPrefix;
  name.append(suffix);
  memfd_ = memfd_create(name.c_str(), MFD_FLAGS);
  CHECK_GE(memfd_, 0);

  // Prepend our header to the mapping.
  map_size_ = roundup2(size + kHeaderReservedBytes, kHugepageSize);
  CHECK_LE(map_size_, UINT32_MAX);
  CHECK_ZERO(ftruncate(memfd_, map_size_));
  CHECK_ZERO(fcntl(memfd_, F_ADD_SEALS, MFD_SEALS));

  shmem_ =
      mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_, 0);
  CHECK_NE(shmem_, MAP_FAILED);

  // At this point the shmem_ is created, our header is initialized, but the
  // region is not yet ready.  Clients must call MarkReady() before we'll allow
  // connections against it to proceed.
  hdr_ = static_cast<InternalHeader*>(shmem_);
  char* bytes = static_cast<char*>(shmem_);
  data_ = bytes + kHeaderReservedBytes;

  // We can safely initialize InternalHeader data fields after this point, as
  // MarkReady() cannot yet proceed.
  hdr_->header_version = kHeaderVersion;
  hdr_->mapping_size = map_size_;
  hdr_->client_size = map_size_ - kHeaderReservedBytes;
  hdr_->header_size = kHeaderReservedBytes;
  hdr_->owning_pid = getpid();  // Should probably be process.
  //printf("\n *************OpenGhostShmemFd SECONDLY *************** \n");
  int fdd = OpenGhostShmemFd(suffix, Gtid::Current().tid());
  //printf("\n FD in create shared memory: %d \n", fdd);
}





void GhostShmem::CreateShmem(int64_t client_version, const char* suffix,
                             size_t size, int fd) {
  int MFD_FLAGS = MFD_CLOEXEC | MFD_ALLOW_SEALING;
  const int MFD_SEALS = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  std::string name;

  // Suffixes must currently be unique for the hosting process.
  CHECK_EQ(OpenGhostShmemFd(suffix, Gtid::Current().tid(), fd), -1);

  name = kMemFdPrefix;
  name.append(suffix);
  name.append("-"+std::to_string(fd));
  memfd_ = memfd_create(name.c_str(), MFD_FLAGS);
  CHECK_GE(memfd_, 0);

  // Prepend our header to the mapping.
  map_size_ = roundup2(size + kHeaderReservedBytes, kHugepageSize);
  CHECK_LE(map_size_, UINT32_MAX);
  CHECK_ZERO(ftruncate(memfd_, map_size_));
  CHECK_ZERO(fcntl(memfd_, F_ADD_SEALS, MFD_SEALS));

  shmem_ =
      mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_, 0);
  CHECK_NE(shmem_, MAP_FAILED);

  // At this point the shmem_ is created, our header is initialized, but the
  // region is not yet ready.  Clients must call MarkReady() before we'll allow
  // connections against it to proceed.
  hdr_ = static_cast<InternalHeader*>(shmem_);
  char* bytes = static_cast<char*>(shmem_);
  data_ = bytes + kHeaderReservedBytes;

  // We can safely initialize InternalHeader data fields after this point, as
  // MarkReady() cannot yet proceed.
  hdr_->header_version = kHeaderVersion;
  hdr_->mapping_size = map_size_;
  hdr_->client_size = map_size_ - kHeaderReservedBytes;
  hdr_->header_size = kHeaderReservedBytes;
  hdr_->owning_pid = getpid();  // Should probably be process.
  //printf("\n *************OpenGhostShmemFd SECONDLY *************** \n");
  int fdd = OpenGhostShmemFd(suffix, Gtid::Current().tid(), fd);
  //printf("\n FD in create shared memory: %d \n", fdd);
}

/*void GhostShmem::CreateShmem(int64_t client_version, const char* suffix,
                             size_t size, pid_t remote, int fd) {
  int MFD_FLAGS = MFD_CLOEXEC | MFD_ALLOW_SEALING;
  const int MFD_SEALS = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
  std::string name;
  std::string path = "/proc/" + std::to_string(remote) + "/fd";
  //std::string str = "/memfd:/";
  //name.append(path);
  //name.append(str);
  name.append(kMemFdPrefix);
  //name = kMemFdPrefix;
  name.append(suffix);
  name.append("-"+std::to_string(fd));

//  printf("\n suffix: %s \n", suffix);
  //printf("\n *************OpenGhostShmemFd FIRTSLY *************** \n");
  // Suffixes must currently be unique for the hosting process.
  CHECK_EQ(OpenGhostShmemFd(suffix, remote, fd), -1);


  printf("\n name: %s \n", name.c_str());
  memfd_ = memfd_create(name.c_str(), MFD_FLAGS);
  CHECK_GE(memfd_, 0);
  printf("\n name: %d \n", memfd_);
  // Prepend our header to the mapping.
  map_size_ = roundup2(size + kHeaderReservedBytes, kHugepageSize);
  CHECK_LE(map_size_, UINT32_MAX);
  CHECK_ZERO(ftruncate(memfd_, map_size_));
  CHECK_ZERO(fcntl(memfd_, F_ADD_SEALS, MFD_SEALS));

  shmem_ =
      mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_, 0);
  CHECK_NE(shmem_, MAP_FAILED);

  // At this point the shmem_ is created, our header is initialized, but the
  // region is not yet ready.  Clients must call MarkReady() before we'll allow
  // connections against it to proceed.
  hdr_ = static_cast<InternalHeader*>(shmem_);
  char* bytes = static_cast<char*>(shmem_);
  data_ = bytes + kHeaderReservedBytes;

  // We can safely initialize InternalHeader data fields after this point, as
  // MarkReady() cannot yet proceed.
  hdr_->header_version = kHeaderVersion;
  hdr_->mapping_size = map_size_;
  hdr_->client_size = map_size_ - kHeaderReservedBytes;
  hdr_->header_size = kHeaderReservedBytes;
  hdr_->owning_pid = getpid();  // Should probably be process.
  //printf("\n *************OpenGhostShmemFd SECONDLY *************** \n");
  //file_decriptor = OpenGhostShmemFd(suffix, Gtid::Current().tid(), fd);
  //printf("\n FD in create shared memory: %d \n", file_decriptor);
}*/


int GhostShmem::ConnectShmem(int64_t client_version, const char* suffix,
                              pid_t pid) {
  memfd_ = OpenGhostShmemFd(suffix, Gtid::Current().tid());
  //printf("\n FD: %d \n", memfd_);
  if (memfd_ < 0) {
    return false;
  }

  struct stat sb;
  CHECK_ZERO(fstat(memfd_, &sb));

  map_size_ = sb.st_size;
  shmem_ =
      mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_, 0);
  CHECK_NE(shmem_, MAP_FAILED);

  // Avoid deadlock between agent and the task it is scheduling. This happens
  // if both tasks (agent and non-agent) fault on the same page in shared mem
  // concurrently. Subsequently when the page is ready then it is possible that
  // the non-agent task is woken up first but doesn't get a chance to run
  // because the agent (that is responsible for scheduling it) is also blocked
  // on the same page.
  //
  // See b/173811264 for details.
  CHECK_ZERO(mlock(shmem_, map_size_));

  // Setup internal fields.
  hdr_ = static_cast<InternalHeader*>(shmem_);
  char* bytes = static_cast<char*>(shmem_);
  data_ = bytes + kHeaderReservedBytes;

  // Ensure we synchronize on the remote side marking that content is ready
  // before trying to validate.
  WaitForReady();

  CHECK_EQ(hdr_->header_version, kHeaderVersion);
  CHECK_EQ(hdr_->client_version, client_version);
  CHECK_EQ(hdr_->mapping_size, map_size_);
  CHECK_EQ(hdr_->header_size, kHeaderReservedBytes);
  return memfd_;
}


int GhostShmem::ConnectShmem(int64_t client_version, const char* suffix,
                              pid_t pid, int fd) {
  memfd_ = OpenGhostShmemFd(suffix, Gtid::Current().tid(), fd);
  //printf("\n FD: %d \n", memfd_);
  if (memfd_ < 0) {
    return false;
  }

  struct stat sb;
  CHECK_ZERO(fstat(memfd_, &sb));

  map_size_ = sb.st_size;
  shmem_ =
      mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_, 0);
  CHECK_NE(shmem_, MAP_FAILED);

  // Avoid deadlock between agent and the task it is scheduling. This happens
  // if both tasks (agent and non-agent) fault on the same page in shared mem
  // concurrently. Subsequently when the page is ready then it is possible that
  // the non-agent task is woken up first but doesn't get a chance to run
  // because the agent (that is responsible for scheduling it) is also blocked
  // on the same page.
  //
  // See b/173811264 for details.
  CHECK_ZERO(mlock(shmem_, map_size_));

  // Setup internal fields.
  hdr_ = static_cast<InternalHeader*>(shmem_);
  char* bytes = static_cast<char*>(shmem_);
  data_ = bytes + kHeaderReservedBytes;

  // Ensure we synchronize on the remote side marking that content is ready
  // before trying to validate.
  WaitForReady();

  CHECK_EQ(hdr_->header_version, kHeaderVersion);
  CHECK_EQ(hdr_->client_version, client_version);
  CHECK_EQ(hdr_->mapping_size, map_size_);
  CHECK_EQ(hdr_->header_size, kHeaderReservedBytes);
  return memfd_;
}


/*int GhostShmem::ConnectShmem(int64_t client_version, const char* suffix,
                              pid_t pid, int fd, uint32_t sched_items, uint32_t work_classes,
                                                       uint32_t stream_capacity) {
  //memfd_ = OpenGhostShmemFd(suffix, pid);


  //printf("\n FD in connect function is %d \n", fd);

  size_t size = shmem_size(sched_items, work_classes, stream_capacity);

  CreateShmem(client_version, suffix, size, pid, fd);

  memfd_ = OpenGhostShmemFd(suffix, Gtid::Current().tid(), fd);
  if (memfd_ < 0) {
    return false;
  }

  printf("\n memfd_  in connect function is %d \n", memfd_);
  struct stat sb;
  CHECK_ZERO(fstat(memfd_, &sb));

  map_size_ = sb.st_size;
  shmem_ =
      mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED, memfd_, 0);
  CHECK_NE(shmem_1, MAP_FAILED);

  // Avoid deadlock between agent and the task it is scheduling. This happens
  // if both tasks (agent and non-agent) fault on the same page in shared mem
  // concurrently. Subsequently when the page is ready then it is possible that
  // the non-agent task is woken up first but doesn't get a chance to run
  // because the agent (that is responsible for scheduling it) is also blocked
  // on the same page.
  //
  // See b/173811264 for details.
  CHECK_ZERO(mlock(shmem_, map_size_));

  // Setup internal fields.
  hdr_ = static_cast<InternalHeader*>(shmem_);
  char* bytes = static_cast<char*>(shmem_);
  data_ = bytes + kHeaderReservedBytes;

  // Ensure we synchronize on the remote side marking that content is ready
  // before trying to validate.
  WaitForReady();

  CHECK_EQ(hdr_->header_version, kHeaderVersion);
  CHECK_EQ(hdr_->client_version, client_version);
  CHECK_EQ(hdr_->mapping_size, map_size_);
  CHECK_EQ(hdr_->header_size, kHeaderReservedBytes);
  return memfd_;
}*/


// static
int GhostShmem::OpenGhostShmemFd(const char* suffix, pid_t pid) {
  std::string path = "/proc/" + std::to_string(pid) + "/fd";
  std::string needle("/memfd:");
  needle.append(kMemFdPrefix);
  needle.append(suffix);
  for (auto& f : fs::directory_iterator(path)) {
    CHECK(fs::is_symlink(f));
    std::string p = fs::read_symlink(f);
    if (p.rfind(needle, 0) == 0) {
      std::string path = fs::path(f);
      int fd = open(path.c_str(), O_RDWR | O_CLOEXEC);
      CHECK_GE(fd, 0);
      return fd;
    }
  }
  return -1;
}

// static
int GhostShmem::OpenGhostShmemFd(const char* suffix, pid_t pid, int fd) {
  std::string path = "/proc/" + std::to_string(pid) + "/fd";
  std::string needle("/memfd:");
  needle.append(kMemFdPrefix);
  needle.append(suffix);
  needle.append("-"+std::to_string(fd));
  //printf("\n Needle: %s \n", needle.c_str());
  for (auto& f : fs::directory_iterator(path)) {
    CHECK(fs::is_symlink(f));
    std::string p = fs::read_symlink(f);
    //printf("\n p: %s \n", p.c_str());
    //std::string path = fs::path(f);
    //printf("\n path: %s \n", path.c_str());
     //printf("\n needle: %s \n", needle.c_str());
    if (p.rfind(needle, 0) == 0) {
      std::string path = fs::path(f);
      int fd = open(path.c_str(), O_RDWR | O_CLOEXEC);
      CHECK_GE(fd, 0);
      return fd;
    }
  }
  return -1;
}

// static
GhostShmem* GhostShmem::GetShmemBlob(size_t size, int fd) {
  static std::atomic<int> unique = 0;
  std::string blob = absl::StrCat(
      "blob-", std::to_string(unique.fetch_add(1, std::memory_order_relaxed)));
  // GhostShmem needs a unique name per process for the memfd
  ghost::GhostShmem* shmem =
      new ghost::GhostShmem(/* client_version = */ 0, blob.data(), size, fd);
  shmem->MarkReady();

  return shmem;
}

}  // namespace ghost
