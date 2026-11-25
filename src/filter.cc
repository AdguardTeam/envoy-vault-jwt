#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "config.h"
#include "coordinator.h"
#include "exchange.h"
#include "kubernetes_token.h"
#include "vault_api.h"
#include "waiter_registry.h"

#include "sdk.h"

namespace Envoy {
namespace DynamicModules {

namespace {

using vault_jwt::CacheState;
using vault_jwt::Coordinator;
using vault_jwt::Credential;
using vault_jwt::FetchDecision;
using vault_jwt::FilterConfig;
using vault_jwt::KubernetesTokenReader;
using vault_jwt::PerRouteConfig;
using vault_jwt::ProjectedTokenFileReader;
using vault_jwt::VaultExchange;
using vault_jwt::VaultHttpResponse;
using vault_jwt::VaultTransport;
using vault_jwt::WaiterRegistry;

constexpr std::string_view kDefaultHeaderName = "x-machine-token";

int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

int64_t now_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

struct Metrics {
  MetricID cache_hit{0};
  MetricID cache_miss{0};
  MetricID fetch_success{0};
  MetricID fetch_failure{0};
  MetricID refresh_success{0};
  MetricID refresh_failure{0};
  MetricID login_success{0};
  MetricID login_failure{0};
  MetricID reauth_attempts{0};
  MetricID requests_rejected{0};
  MetricID requests_waiting{0};
  MetricID token_seconds_remaining{0};
  MetricID fetch_latency_ms{0};
};

struct Waiter {
  std::mutex mutex;
  uint64_t id{0};
  HttpFilterHandle* handle{nullptr};
  std::shared_ptr<Scheduler> scheduler;
};

class PerRoute : public RouteSpecificConfig {
public:
  explicit PerRoute(PerRouteConfig config) : config_(std::move(config)) {}
  const PerRouteConfig& config() const { return config_; }

private:
  PerRouteConfig config_;
};

int parse_status(std::string_view value) {
  if (value.empty() || value.size() > 3) {
    return 0;
  }
  int status = 0;
  for (const char c : value) {
    if (c < '0' || c > '9') {
      return 0;
    }
    status = status * 10 + (c - '0');
  }
  return status >= 100 && status <= 599 ? status : 0;
}

class VaultRequest : public HttpStreamCallback {
public:
  VaultRequest(uint32_t max_body_bytes, VaultTransport::Completion completion)
      : max_body_bytes_(max_body_bytes), completion_(std::move(completion)) {}

  void set_reset(std::function<void()> reset) { reset_ = std::move(reset); }

  void onHttpStreamHeaders(uint64_t, std::span<const HeaderView> headers, bool) override {
    if (status_ != 0) {
      return;
    }
    for (const auto& header : headers) {
      if (header.key() == ":status") {
        status_ = parse_status(header.value());
        return;
      }
    }
  }

  void onHttpStreamData(uint64_t, std::span<const BufferView> chunks, bool) override {
    if (oversized_) {
      return;
    }
    for (const auto& chunk : chunks) {
      if (body_.size() + chunk.size() > max_body_bytes_) {
        oversized_ = true;
        body_.clear();
        if (reset_) {
          reset_();
        }
        finish();
        return;
      }
      body_.append(chunk.toStringView());
    }
  }

  void onHttpStreamTrailers(uint64_t, std::span<const HeaderView>) override {}

  void onHttpStreamComplete(uint64_t) override { finish(); }

  void onHttpStreamReset(uint64_t, HttpStreamResetReason) override {
    if (finished_) {
      return;
    }
    finished_ = true;
    VaultHttpResponse response;
    response.ok = false;
    response.error = "Vault request was reset";
    completion_(std::move(response));
  }

private:
  void finish() {
    if (finished_) {
      return;
    }
    finished_ = true;
    VaultHttpResponse response;
    if (oversized_) {
      response.ok = false;
      response.error = "Vault response exceeded the size limit";
    } else if (status_ == 0) {
      response.ok = false;
      response.error = "Vault response has no usable HTTP status";
    } else {
      response.ok = true;
      response.http_status = status_;
      response.body = std::move(body_);
    }
    completion_(std::move(response));
  }

  const uint32_t max_body_bytes_;
  VaultTransport::Completion completion_;
  std::function<void()> reset_;
  std::string body_;
  int status_{0};
  bool oversized_{false};
  bool finished_{false};
};

// Envoy-owned asynchronous HTTP client for Vault. All methods and callbacks run
// on the config scheduler thread. The transport keeps each request object alive
// until its callback returns and then erases it on the next scheduler turn.
class VaultHttpTransport : public VaultTransport,
                           public std::enable_shared_from_this<VaultHttpTransport> {
public:
  VaultHttpTransport(HttpFilterConfigHandle* handle, const FilterConfig* config,
                     std::shared_ptr<Scheduler> scheduler)
      : handle_(handle), config_(config), scheduler_(std::move(scheduler)) {}

  bool login(std::string_view request_body, Completion completion) override {
    return start("POST", vault_jwt::login_path(config_->auth_mount), {}, request_body,
                 std::move(completion));
  }

  bool fetch_identity_token(std::string_view session_token, Completion completion) override {
    return start("GET", vault_jwt::identity_token_path(config_->token_role), session_token, {},
                 std::move(completion));
  }

private:
  bool start(std::string_view method, const std::string& path, std::string_view session_token,
             std::string_view body, Completion completion) {
    const uint64_t id = ++next_id_;
    auto wrapped = [self = shared_from_this(), id,
                    completion = std::move(completion)](VaultHttpResponse response) mutable {
      if (completion) {
        completion(std::move(response));
      }
      self->erase_later(id);
    };
    auto request = std::make_unique<VaultRequest>(config_->max_vault_response_bytes,
                                                  std::move(wrapped));
    VaultRequest* raw = request.get();
    requests_.emplace(id, std::move(request));

    std::vector<HeaderView> headers;
    headers.reserve(8);
    headers.emplace_back(":method", method);
    headers.emplace_back(":path", path);
    headers.emplace_back(":scheme", "https");
    headers.emplace_back(":authority", config_->vault_authority);
    headers.emplace_back("accept", "application/json");
    headers.emplace_back("user-agent", "envoy-vault-jwt/1");
    if (!session_token.empty()) {
      headers.emplace_back("x-vault-token", session_token);
    } else {
      headers.emplace_back("content-type", "application/json");
    }

    const auto result =
        handle_->startHttpStream(config_->vault_cluster, headers, body, true,
                                 config_->request_timeout_ms, *raw);
    if (result.first != HttpCalloutInitResult::Success) {
      requests_.erase(id);
      return false;
    }
    raw->set_reset([self = shared_from_this(), id]() {
      self->scheduler_->schedule([self, id]() { self->handle_->resetHttpStream(id); });
    });
    return true;
  }

  void erase_later(uint64_t id) {
    auto self = shared_from_this();
    scheduler_->schedule([self, id]() { self->requests_.erase(id); });
  }

  HttpFilterConfigHandle* handle_;
  const FilterConfig* config_;
  std::shared_ptr<Scheduler> scheduler_;
  uint64_t next_id_{0};
  std::map<uint64_t, std::unique_ptr<VaultRequest>> requests_;
};

void send_unavailable(HttpFilterHandle& handle, const Metrics& metrics, uint32_t pending,
                      std::string_view detail) {
  handle.incrementCounterValue(metrics.requests_rejected, 1);
  const auto content_type = handle.requestHeaders().getOne("content-type");
  if (content_type.starts_with("application/grpc")) {
    const HeaderView headers[] = {
        HeaderView("content-type", "application/grpc"),
        HeaderView("grpc-status", "14"),
        HeaderView("grpc-message", "machine token unavailable"),
    };
    handle.sendLocalResponse(200, headers, "", detail);
  } else {
    const HeaderView headers[] = {HeaderView("content-type", "text/plain")};
    handle.sendLocalResponse(503, headers, "machine token unavailable\n", detail);
  }
  handle.setGaugeValue(metrics.requests_waiting, pending);
}

class SharedState : public std::enable_shared_from_this<SharedState> {
public:
  SharedState(FilterConfig config, HttpFilterConfigHandle* handle, Metrics metrics,
              std::shared_ptr<Scheduler> main_scheduler)
      : config_(std::move(config)), coordinator_(config_), handle_(handle), metrics_(metrics),
        main_scheduler_(std::move(main_scheduler)) {
    transport_ = std::make_shared<VaultHttpTransport>(handle_, &config_, main_scheduler_);
    token_reader_ = std::make_unique<ProjectedTokenFileReader>(config_.kubernetes_token_path,
                                                               config_.max_kubernetes_token_bytes);
  }

  const FilterConfig& config() const { return config_; }
  const Metrics& metrics() const { return metrics_; }
  uint32_t pending() const { return coordinator_.pending(); }

  CacheState lookup(std::shared_ptr<const Credential>& out) const {
    return coordinator_.lookup(now_seconds(), out);
  }

  // Worker thread.
  bool request(const std::shared_ptr<Waiter>& waiter) {
    const uint64_t id = registry_.add(waiter);
    waiter->id = id;
    if (!coordinator_.admit(id)) {
      registry_.erase(id);
      std::lock_guard lock(waiter->mutex);
      waiter->handle = nullptr;
      return false;
    }
    post_fetch();
    post_waiting_gauge();
    return true;
  }

  // Worker thread.
  void forget(const std::shared_ptr<Waiter>& waiter) {
    registry_.erase(waiter->id);
    coordinator_.cancel(waiter->id);
    post_waiting_gauge();
  }

  // Worker thread. Refresh a credential that is still valid.
  void request_refresh() { post_fetch(); }

private:
  void post_fetch() {
    auto self = shared_from_this();
    main_scheduler_->schedule([self]() { self->on_ensure_fetch(); });
  }

  void on_ensure_fetch() {
    const FetchDecision decision = coordinator_.start_fetch(now_ms(), now_seconds());
    for (const uint64_t id : decision.wake_now) {
      wake(id);
    }
    if (decision.start) {
      start_exchange(decision.refresh);
    }
  }

  void start_exchange(bool refresh) {
    auto self = shared_from_this();
    auto exchange = std::make_shared<VaultExchange>(config_, *transport_, *token_reader_,
                                                    coordinator_, []() { return now_seconds(); });
    exchange_ = exchange;
    const int64_t started_ms = now_ms();
    exchange->start(refresh, [self, exchange, started_ms](VaultExchange::Result result) {
      self->on_exchange_done(exchange, started_ms, std::move(result));
    });
  }

  void on_exchange_done(const std::shared_ptr<VaultExchange>& exchange, int64_t started_ms,
                        VaultExchange::Result result) {
    handle_->recordHistogramValue(
        metrics_.fetch_latency_ms, static_cast<uint64_t>(std::max<int64_t>(0, now_ms() - started_ms)));
    if (result.success) {
      handle_->incrementCounterValue(metrics_.fetch_success, 1);
      if (result.refresh) {
        handle_->incrementCounterValue(metrics_.refresh_success, 1);
      }
      handle_->setGaugeValue(metrics_.token_seconds_remaining,
                             static_cast<uint64_t>(result.remaining_seconds));
    } else {
      handle_->incrementCounterValue(metrics_.fetch_failure, 1);
      if (result.refresh) {
        handle_->incrementCounterValue(metrics_.refresh_failure, 1);
      }
      DYM_LOG((*handle_), LogLevel::Warn, "vault_jwt: {}", result.error);
    }
    if (result.login_attempted) {
      handle_->incrementCounterValue(
          result.login_succeeded ? metrics_.login_success : metrics_.login_failure, 1);
    }
    if (result.reauth_attempted) {
      handle_->incrementCounterValue(metrics_.reauth_attempts, 1);
    }

    const auto ids = coordinator_.finish_fetch(result.success, now_ms());
    for (const uint64_t id : ids) {
      wake(id);
    }

    auto self = shared_from_this();
    main_scheduler_->schedule([self, exchange]() {
      if (self->exchange_ == exchange) {
        self->exchange_.reset();
      }
    });
  }

  void wake(uint64_t id) {
    auto waiter = registry_.take(id);
    if (!waiter) {
      return;
    }
    auto scheduler = (*waiter)->scheduler;
    if (!scheduler) {
      return;
    }
    auto self = shared_from_this();
    scheduler->schedule([self, waiter]() { self->resume(*waiter); });
  }

  void resume(const std::shared_ptr<Waiter>& waiter) {
    HttpFilterHandle* handle = nullptr;
    {
      std::lock_guard lock(waiter->mutex);
      handle = waiter->handle;
      waiter->handle = nullptr;
    }
    if (handle == nullptr) {
      return;
    }
    std::shared_ptr<const Credential> credential;
    if (coordinator_.lookup(now_seconds(), credential) == CacheState::Missing) {
      send_unavailable(*handle, metrics_, coordinator_.pending(), "no_machine_token");
      return;
    }
    const std::string& header = config_.header_name;
    handle->requestHeaders().remove(header);
    if (header != kDefaultHeaderName) {
      handle->requestHeaders().remove(kDefaultHeaderName);
    }
    handle->requestHeaders().set(header, credential->token);
    handle->incrementCounterValue(metrics_.cache_hit, 1);
    handle->setGaugeValue(metrics_.requests_waiting, coordinator_.pending());
    handle->continueRequest();
  }

  void post_waiting_gauge() {
    auto self = shared_from_this();
    main_scheduler_->schedule([self]() {
      self->handle_->setGaugeValue(self->metrics_.requests_waiting, self->coordinator_.pending());
    });
  }

  FilterConfig config_;
  Coordinator coordinator_;
  HttpFilterConfigHandle* handle_;
  Metrics metrics_;
  std::shared_ptr<Scheduler> main_scheduler_;
  std::shared_ptr<VaultHttpTransport> transport_;
  std::unique_ptr<KubernetesTokenReader> token_reader_;
  std::shared_ptr<VaultExchange> exchange_;
  WaiterRegistry<std::shared_ptr<Waiter>> registry_;
};

class VaultJwtFilter : public HttpFilter {
public:
  VaultJwtFilter(HttpFilterHandle& handle, std::shared_ptr<SharedState> state)
      : handle_(handle), state_(std::move(state)) {}

  HeadersStatus onRequestHeaders(HeaderMap& headers, bool) override {
    const auto* route = dynamic_cast<const PerRoute*>(handle_.getMostSpecificConfig());
    if (route == nullptr || !route->config().enabled) {
      return HeadersStatus::Continue;
    }
    const std::string& header = state_->config().header_name;
    headers.remove(header);
    if (header != kDefaultHeaderName) {
      headers.remove(kDefaultHeaderName);
    }

    std::shared_ptr<const Credential> credential;
    const CacheState state = state_->lookup(credential);
    if (state != CacheState::Missing) {
      handle_.incrementCounterValue(state_->metrics().cache_hit, 1);
      headers.set(header, credential->token);
      if (state == CacheState::Stale) {
        state_->request_refresh();
      }
      return HeadersStatus::Continue;
    }

    handle_.incrementCounterValue(state_->metrics().cache_miss, 1);
    auto waiter = std::make_shared<Waiter>();
    waiter->handle = &handle_;
    waiter->scheduler = handle_.getScheduler();
    if (!state_->request(waiter)) {
      send_unavailable(handle_, state_->metrics(), state_->pending(), "pending_limit_exceeded");
      return HeadersStatus::Stop;
    }
    handle_.setGaugeValue(state_->metrics().requests_waiting, state_->pending());
    waiter_ = std::move(waiter);
    return HeadersStatus::Stop;
  }

  BodyStatus onRequestBody(BodyBuffer&, bool) override { return BodyStatus::Continue; }
  TrailersStatus onRequestTrailers(HeaderMap&) override { return TrailersStatus::Continue; }
  HeadersStatus onResponseHeaders(HeaderMap&, bool) override { return HeadersStatus::Continue; }
  BodyStatus onResponseBody(BodyBuffer&, bool) override { return BodyStatus::Continue; }
  TrailersStatus onResponseTrailers(HeaderMap&) override { return TrailersStatus::Continue; }
  void onStreamComplete() override {}

  void onDestroy() override {
    if (!waiter_) {
      return;
    }
    {
      std::lock_guard lock(waiter_->mutex);
      waiter_->handle = nullptr;
    }
    state_->forget(waiter_);
    waiter_.reset();
  }

private:
  HttpFilterHandle& handle_;
  std::shared_ptr<SharedState> state_;
  std::shared_ptr<Waiter> waiter_;
};

class VaultJwtFilterFactory : public HttpFilterFactory {
public:
  explicit VaultJwtFilterFactory(std::shared_ptr<SharedState> state) : state_(std::move(state)) {}
  std::unique_ptr<HttpFilter> create(HttpFilterHandle& handle) override {
    return std::make_unique<VaultJwtFilter>(handle, state_);
  }

private:
  std::shared_ptr<SharedState> state_;
};

class VaultJwtConfigFactory : public HttpFilterConfigFactory {
public:
  std::unique_ptr<HttpFilterFactory> create(HttpFilterConfigHandle& handle,
                                            std::string_view config_view) override {
    FilterConfig config;
    std::string error;
    if (!vault_jwt::parse_filter_config(config_view, config, error)) {
      DYM_LOG(handle, LogLevel::Error, "vault_jwt: invalid filter config: {}", error);
      return nullptr;
    }
    auto main_scheduler = handle.getScheduler();
    if (!main_scheduler) {
      DYM_LOG(handle, LogLevel::Error, "vault_jwt: no main thread scheduler available");
      return nullptr;
    }
    Metrics metrics;
    metrics.cache_hit = handle.defineCounter("cache_hit").first;
    metrics.cache_miss = handle.defineCounter("cache_miss").first;
    metrics.fetch_success = handle.defineCounter("fetch_success").first;
    metrics.fetch_failure = handle.defineCounter("fetch_failure").first;
    metrics.refresh_success = handle.defineCounter("refresh_success").first;
    metrics.refresh_failure = handle.defineCounter("refresh_failure").first;
    metrics.login_success = handle.defineCounter("login_success").first;
    metrics.login_failure = handle.defineCounter("login_failure").first;
    metrics.reauth_attempts = handle.defineCounter("reauth_attempts").first;
    metrics.requests_rejected = handle.defineCounter("requests_rejected").first;
    metrics.requests_waiting = handle.defineGauge("requests_waiting").first;
    metrics.token_seconds_remaining = handle.defineGauge("token_seconds_remaining").first;
    metrics.fetch_latency_ms = handle.defineHistogram("fetch_latency_ms").first;
    auto state = std::make_shared<SharedState>(std::move(config), &handle, metrics,
                                               std::move(main_scheduler));
    return std::make_unique<VaultJwtFilterFactory>(std::move(state));
  }

  std::unique_ptr<RouteSpecificConfig> createPerRoute(std::string_view config_view) override {
    PerRouteConfig config;
    std::string error;
    if (!vault_jwt::parse_per_route_config(config_view, config, error)) {
      return nullptr;
    }
    return std::make_unique<PerRoute>(std::move(config));
  }
};

REGISTER_HTTP_FILTER_CONFIG_FACTORY(VaultJwtConfigFactory, "vault_jwt");

} // namespace
} // namespace DynamicModules
} // namespace Envoy
