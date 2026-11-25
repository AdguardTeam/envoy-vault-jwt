// Test-only model of the Envoy dynamic modules C++ SDK surface used by
// src/filter.cc. It exists only to drive the real filter and Vault transport
// with a fake host. It is not linked into libvault_jwt.so.
//
// The stream contract modelled here is the one in Envoy v1.40.2:
//   * startHttpStream() returns {result, host-assigned stream handle};
//   * resetHttpStream() takes that same host-assigned handle.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Envoy::DynamicModules {

enum class LogLevel : uint32_t { Trace, Debug, Info, Warn, Error, Critical, Off };

enum class HttpCalloutInitResult : uint32_t {
  Success,
  MissingRequiredHeaders,
  ClusterNotFound,
  DuplicateCalloutId,
  CannotCreateRequest
};

enum class HttpStreamResetReason : uint32_t {
  ConnectionFailure,
  ConnectionTermination,
  LocalReset,
  LocalRefusedStreamReset,
  Overflow,
  RemoteReset,
  RemoteRefusedStreamReset,
  ProtocolError
};

using MetricID = uint64_t;
enum class MetricsResult : uint32_t { Success, NotFound, InvalidTags, Frozen };

class HeaderView {
public:
  HeaderView() = default;
  HeaderView(std::string_view key, std::string_view value) : key_(key), value_(value) {}
  std::string_view key() const { return key_; }
  std::string_view value() const { return value_; }

private:
  std::string key_;
  std::string value_;
};

class BufferView {
public:
  explicit BufferView(std::string_view value) : value_(value) {}
  std::string_view toStringView() const { return value_; }
  size_t size() const { return value_.size(); }

private:
  std::string_view value_;
};

class HeaderMap {
public:
  virtual ~HeaderMap() = default;
  virtual std::string_view getOne(std::string_view key) const = 0;
  virtual void set(std::string_view key, std::string_view value) = 0;
  virtual void remove(std::string_view key) = 0;
};

class HttpStreamCallback {
public:
  virtual ~HttpStreamCallback() = default;
  virtual void onHttpStreamHeaders(uint64_t stream_id, std::span<const HeaderView> headers,
                                   bool end_stream) = 0;
  virtual void onHttpStreamData(uint64_t stream_id, std::span<const BufferView> body,
                                bool end_stream) = 0;
  virtual void onHttpStreamTrailers(uint64_t stream_id,
                                    std::span<const HeaderView> trailers) = 0;
  virtual void onHttpStreamComplete(uint64_t stream_id) = 0;
  virtual void onHttpStreamReset(uint64_t stream_id, HttpStreamResetReason reason) = 0;
};

class Scheduler {
public:
  virtual ~Scheduler() = default;
  virtual void schedule(std::function<void()> func) = 0;
};

class RouteSpecificConfig {
public:
  virtual ~RouteSpecificConfig() = default;
};

class HttpFilterConfigHandle {
public:
  virtual ~HttpFilterConfigHandle() = default;
  virtual std::pair<HttpCalloutInitResult, uint64_t>
  startHttpStream(std::string_view cluster, std::span<const HeaderView> headers,
                  std::string_view body, bool end_of_stream, uint64_t timeout_ms,
                  HttpStreamCallback& callback) = 0;
  virtual void resetHttpStream(uint64_t stream_id) = 0;
  virtual std::shared_ptr<Scheduler> getScheduler() = 0;
  virtual std::pair<MetricID, MetricsResult> defineCounter(std::string_view name) = 0;
  virtual std::pair<MetricID, MetricsResult> defineGauge(std::string_view name) = 0;
  virtual std::pair<MetricID, MetricsResult> defineHistogram(std::string_view name) = 0;
  virtual MetricsResult recordHistogramValue(MetricID id, uint64_t value) = 0;
  virtual MetricsResult setGaugeValue(MetricID id, uint64_t value) = 0;
  virtual MetricsResult incrementCounterValue(MetricID id, uint64_t value) = 0;
};

class BodyBuffer {};

class HttpFilterHandle {
public:
  virtual ~HttpFilterHandle() = default;
  virtual HeaderMap& requestHeaders() = 0;
  virtual void sendLocalResponse(uint32_t status, std::span<const HeaderView> headers,
                                 std::string_view body, std::string_view detail) = 0;
  virtual void continueRequest() = 0;
  virtual std::shared_ptr<Scheduler> getScheduler() = 0;
  virtual const RouteSpecificConfig* getMostSpecificConfig() = 0;
  virtual MetricsResult incrementCounterValue(MetricID id, uint64_t value) = 0;
  virtual MetricsResult setGaugeValue(MetricID id, uint64_t value) = 0;
};

class HttpFilter {
public:
  virtual ~HttpFilter() = default;
  enum class HeadersStatus { Continue, Stop };
  enum class BodyStatus { Continue, Stop };
  enum class TrailersStatus { Continue, Stop };

  virtual HeadersStatus onRequestHeaders(HeaderMap& headers, bool end_stream) = 0;
  virtual BodyStatus onRequestBody(BodyBuffer& body, bool end_stream) = 0;
  virtual TrailersStatus onRequestTrailers(HeaderMap& trailers) = 0;
  virtual HeadersStatus onResponseHeaders(HeaderMap& headers, bool end_stream) = 0;
  virtual BodyStatus onResponseBody(BodyBuffer& body, bool end_stream) = 0;
  virtual TrailersStatus onResponseTrailers(HeaderMap& trailers) = 0;
  virtual void onStreamComplete() = 0;
  virtual void onDestroy() = 0;
};

class HttpFilterFactory {
public:
  virtual ~HttpFilterFactory() = default;
  virtual std::unique_ptr<HttpFilter> create(HttpFilterHandle& handle) = 0;
};

class HttpFilterConfigFactory {
public:
  virtual ~HttpFilterConfigFactory() = default;
  virtual std::unique_ptr<HttpFilterFactory> create(HttpFilterConfigHandle& handle,
                                                    std::string_view config) = 0;
  virtual std::unique_ptr<RouteSpecificConfig> createPerRoute(std::string_view config) = 0;
};

} // namespace Envoy::DynamicModules

#define DYM_LOG(HANDLE, LEVEL, FORMAT_STRING, ...)                                                 \
  do {                                                                                             \
  } while (0)

#define REGISTER_HTTP_FILTER_CONFIG_FACTORY(CLASS, NAME)
