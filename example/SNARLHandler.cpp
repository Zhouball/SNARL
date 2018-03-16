#include "SNARLHandler.h"

#include <proxygen/httpserver/RequestHandler.h>
#include <proxygen/httpserver/ResponseBuilder.h>

#include "SNARLStats.h"

using namespace proxygen;

namespace SNARLService {

SNARLHandler::SNARLHandler(SNARLStats* stats): stats_(stats) {
}

void SNARLHandler::onRequest(std::unique_ptr<HTTPMessage> /*headers*/) noexcept {
  stats_->recordRequest();
}

void SNARLHandler::onBody(std::unique_ptr<folly::IOBuf> body) noexcept {
  if (body_) {
    body_->prependChain(std::move(body));
  } else {
    body_ = std::move(body);
  }
}

void SNARLHandler::onEOM() noexcept {
  ResponseBuilder(downstream_)
    .status(200, "OK")
    .header("Request-Number",
            folly::to<std::string>(stats_->getRequestCount()))
    .body(std::move(body_))
    .sendWithEOM();
}

void SNARLHandler::onUpgrade(UpgradeProtocol /*protocol*/) noexcept {
  // handler doesn't support upgrades
}

void SNARLHandler::requestComplete() noexcept {
  delete this;
}

void SNARLHandler::onError(ProxygenError /*err*/) noexcept { delete this; }
}
