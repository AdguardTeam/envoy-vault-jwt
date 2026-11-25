// Regression test for the HTTP stream reset identifier.
//
// Envoy assigns the stream handle and returns it as the second element of
// startHttpStream(). resetHttpStream() must receive that handle. A module-local
// request id is not a valid stream handle. This test runs the real
// src/filter.cc Vault transport against a fake host that deliberately returns a
// stream handle (1000) different from the first local request id (1).
//
// With the original code, resetHttpStream() receives 1 and the stream is not
// reset. With the fix it receives 1000.
//
// The fake SDK surface is in tests/unit/fake_sdk/sdk.h. It models the contract
// of Envoy v1.40.2 and is not part of the module build.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "filter.cc"

namespace Envoy::DynamicModules {
namespace {

class FakeScheduler : public Scheduler {
public:
  void schedule(std::function<void()> func) override { tasks_.push_back(std::move(func)); }

  void run_all() {
    while (!tasks_.empty()) {
      auto current = std::move(tasks_);
      tasks_.clear();
      for (auto& task : current) {
        task();
      }
    }
  }

private:
  std::vector<std::function<void()>> tasks_;
};

class FakeHeaderMap : public HeaderMap {
public:
  std::string_view getOne(std::string_view key) const override {
    const auto it = values.find(std::string(key));
    if (it == values.end()) {
      return {};
    }
    return it->second;
  }

  void set(std::string_view key, std::string_view value) override {
    values[std::string(key)] = std::string(value);
  }

  void remove(std::string_view key) override { values.erase(std::string(key)); }

  std::map<std::string, std::string> values;
};

class FakeConfigHandle : public HttpFilterConfigHandle {
public:
  explicit FakeConfigHandle(std::shared_ptr<Scheduler> scheduler)
      : scheduler_(std::move(scheduler)) {}

  std::pair<HttpCalloutInitResult, uint64_t>
  startHttpStream(std::string_view, std::span<const HeaderView>, std::string_view, bool,
                  uint64_t, HttpStreamCallback& callback) override {
    ++starts;
    callback_ = &callback;
    return {HttpCalloutInitResult::Success, stream_id};
  }

  void resetHttpStream(uint64_t id) override {
    resets.push_back(id);
    if (id == stream_id && callback_ != nullptr) {
      HttpStreamCallback* callback = callback_;
      callback_ = nullptr;
      callback->onHttpStreamReset(id, HttpStreamResetReason::LocalReset);
    }
  }

  std::shared_ptr<Scheduler> getScheduler() override { return scheduler_; }
  std::pair<MetricID, MetricsResult> defineCounter(std::string_view) override {
    return {1, MetricsResult::Success};
  }
  std::pair<MetricID, MetricsResult> defineGauge(std::string_view) override {
    return {1, MetricsResult::Success};
  }
  std::pair<MetricID, MetricsResult> defineHistogram(std::string_view) override {
    return {1, MetricsResult::Success};
  }
  MetricsResult recordHistogramValue(MetricID, uint64_t) override {
    return MetricsResult::Success;
  }
  MetricsResult setGaugeValue(MetricID, uint64_t) override { return MetricsResult::Success; }
  MetricsResult incrementCounterValue(MetricID, uint64_t) override {
    return MetricsResult::Success;
  }

  const uint64_t stream_id{1000};
  int starts{0};
  HttpStreamCallback* callback_{nullptr};
  std::vector<uint64_t> resets;

private:
  std::shared_ptr<Scheduler> scheduler_;
};

class FakeFilterHandle : public HttpFilterHandle {
public:
  FakeFilterHandle(std::shared_ptr<Scheduler> scheduler, const RouteSpecificConfig* route)
      : scheduler_(std::move(scheduler)), route_(route) {}

  HeaderMap& requestHeaders() override { return headers; }
  void sendLocalResponse(uint32_t status, std::span<const HeaderView>, std::string_view,
                         std::string_view) override {
    local_status = status;
  }
  void continueRequest() override { continued = true; }
  std::shared_ptr<Scheduler> getScheduler() override { return scheduler_; }
  const RouteSpecificConfig* getMostSpecificConfig() override { return route_; }
  MetricsResult incrementCounterValue(MetricID, uint64_t) override {
    return MetricsResult::Success;
  }
  MetricsResult setGaugeValue(MetricID, uint64_t) override { return MetricsResult::Success; }

  FakeHeaderMap headers;
  int local_status{0};
  bool continued{false};

private:
  std::shared_ptr<Scheduler> scheduler_;
  const RouteSpecificConfig* route_;
};

std::string base64url(std::string_view value) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  uint32_t accumulator = 0;
  int bits = 0;
  for (const char c : value) {
    accumulator = (accumulator << 8) | static_cast<uint8_t>(c);
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push_back(kAlphabet[(accumulator >> bits) & 0x3f]);
    }
  }
  if (bits > 0) {
    out.push_back(kAlphabet[(accumulator << (6 - bits)) & 0x3f]);
  }
  return out;
}

std::string projected_token() {
  const std::string payload = R"({"exp":4102444800})";
  return base64url(R"({"alg":"RS256"})") + "." + base64url(payload) + ".c2ln";
}

bool write_file(const std::string& path, std::string_view content) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    return false;
  }
  const ssize_t written = ::write(fd, content.data(), content.size());
  ::close(fd);
  return written == static_cast<ssize_t>(content.size());
}

int run_test() {
  char directory[] = "/tmp/vault-jwt-stream-reset-XXXXXX";
  char* created = ::mkdtemp(directory);
  if (created == nullptr) {
    std::printf("FAIL cannot create a temporary directory\n");
    return 1;
  }
  const std::string token_path = std::string(created) + "/token";
  if (!write_file(token_path, projected_token())) {
    std::printf("FAIL cannot write the projected token\n");
    ::rmdir(created);
    return 1;
  }

  const std::string config =
      R"({"vaultCluster":"vault","vaultAuthority":"vault.example.com:8200",)"
      R"("authMount":"kubernetes","authRole":"workload","tokenRole":"machine",)"
      R"("kubernetesTokenPath":")" + token_path +
      R"(","expectedIssuer":"https://vault.example.com/v1/identity/oidc",)"
      R"("expectedAudience":"payments-api","maxVaultResponseBytes":1024})";

  VaultJwtConfigFactory factory;
  auto route = factory.createPerRoute(R"({"enabled":true})");
  auto scheduler = std::make_shared<FakeScheduler>();
  auto config_handle = std::make_shared<FakeConfigHandle>(scheduler);
  auto filter_factory = factory.create(*config_handle, config);
  if (!route || !filter_factory) {
    std::printf("FAIL cannot build the filter from a valid configuration\n");
    ::unlink(token_path.c_str());
    ::rmdir(created);
    return 1;
  }

  FakeFilterHandle filter_handle(scheduler, route.get());
  auto filter = filter_factory->create(filter_handle);
  if (!filter) {
    std::printf("FAIL cannot create the filter\n");
    ::unlink(token_path.c_str());
    ::rmdir(created);
    return 1;
  }
  if (filter->onRequestHeaders(filter_handle.requestHeaders(), false) !=
      HttpFilter::HeadersStatus::Stop) {
    std::printf("FAIL a cold-cache request did not wait for a token\n");
    ::unlink(token_path.c_str());
    ::rmdir(created);
    return 1;
  }
  scheduler->run_all();
  if (config_handle->callback_ == nullptr) {
    std::printf("FAIL the Vault login stream did not start\n");
    ::unlink(token_path.c_str());
    ::rmdir(created);
    return 1;
  }

  const HeaderView response_headers[] = {HeaderView(":status", "200")};
  config_handle->callback_->onHttpStreamHeaders(config_handle->stream_id, response_headers,
                                                false);
  const std::string oversized(2048, 'a');
  const BufferView chunks[] = {BufferView(oversized)};
  config_handle->callback_->onHttpStreamData(config_handle->stream_id, chunks, false);
  scheduler->run_all();

  bool ok = true;
  if (config_handle->starts != 1) {
    std::printf("FAIL expected one Vault stream, got %d\n", config_handle->starts);
    ok = false;
  }
  if (config_handle->resets.size() != 1 || config_handle->resets[0] != config_handle->stream_id) {
    std::printf("FAIL resetHttpStream received the wrong handle:");
    for (const uint64_t id : config_handle->resets) {
      std::printf(" %llu", static_cast<unsigned long long>(id));
    }
    std::printf(" (expected %llu)\n",
                static_cast<unsigned long long>(config_handle->stream_id));
    ok = false;
  }
  if (config_handle->callback_ != nullptr) {
    std::printf("FAIL the stream callback remained registered after the oversized response\n");
    ok = false;
  }
  if (filter_handle.local_status != 503) {
    std::printf("FAIL oversized response did not fail closed, status=%d\n",
                filter_handle.local_status);
    ok = false;
  }
  if (ok) {
    std::printf("PASS stream reset used the ABI stream handle %llu, not the local request id\n",
                static_cast<unsigned long long>(config_handle->stream_id));
  }

  filter.reset();
  filter_factory.reset();
  config_handle.reset();
  scheduler.reset();
  ::unlink(token_path.c_str());
  ::rmdir(created);
  return ok ? 0 : 1;
}

} // namespace

int run_stream_reset_test() { return run_test(); }

} // namespace Envoy::DynamicModules

int main() { return Envoy::DynamicModules::run_stream_reset_test(); }
