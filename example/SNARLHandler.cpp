#include "SNARLHandler.h"

#include <proxygen/httpserver/RequestHandler.h>
#include <proxygen/httpserver/ResponseBuilder.h>
#include <string>

#include "SNARLStats.h"

using namespace proxygen;

namespace SNARLService {

SNARLHandler::SNARLHandler(SNARLStats* stats): stats_(stats) {
}

void SNARLHandler::onRequest(std::unique_ptr<HTTPMessage> headers) noexcept {
  stats_->recordRequest();
  if (headers->getMethod() != HTTPMethod::GET) {
    ResponseBuilder(downstream_)
      .status(400, "Bad method")
      .body("In this example, we're looking for GET requests\n")
      .sendWithEOM();
    return;
  }

  std::string requestType = "weapons";
  // std::string requestType = headers->getPath().c_str() + 1; // +1 to remove the beginning '/'
  if (!requestType.compare("weapons") != 0) {
    ResponseBuilder(downstream_)
      .status(400, "Bad method")
      .body("Try looking for /weapons\n")
      .sendWithEOM();
    return;
  }

  // Return an OK status message first
  ResponseBuilder(downstream_)
    .status(200, "Ok")
    .send();

  // Then query the object manager for database objects and perform computations
  // ResponseBuilder(downstream_)
  //   .status(200, "Ok")
  //   .body(/* object information */)
  //   .send();
}

void SNARLHandler::onBody(std::unique_ptr<folly::IOBuf> body) noexcept {
}

void SNARLHandler::onEOM() noexcept {
}

void SNARLHandler::onUpgrade(UpgradeProtocol /*protocol*/) noexcept {
  // handler doesn't support upgrades
}

void SNARLHandler::requestComplete() noexcept {
  delete this;
}

void SNARLHandler::onError(ProxygenError /*err*/) noexcept { delete this; }
}
