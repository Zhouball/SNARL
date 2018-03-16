#pragma once

namespace SNARLService {
class SNARLStats {
 public:
  virtual ~SNARLStats() {
  }

  virtual void recordRequest() {
    ++reqCount_;
  }

  virtual uint64_t getRequestCount() {
    return reqCount_;
  }

 private:
  uint64_t reqCount_{0};
};

}
