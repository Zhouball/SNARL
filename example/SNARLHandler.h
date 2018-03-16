#pragma once

#include <folly/Memory.h>
#include <proxygen/httpserver/RequestHandler.h>

namespace proxygen {
class ResponseHandler;
}

namespace SNARLService {

class SNARLStats;

class SNARLHandler : public proxygen::RequestHandler {
	public:
		explicit SNARLHandler(SNARLStats* stats);

	void onRequest(std::unique_ptr<proxygen::HTTPMessage> headers)
			noexcept override;

	void onBody(std::unique_ptr<folly::IOBuf> body) noexcept override;

	void onEOM() noexcept override;

	void onUpgrade(proxygen::UpgradeProtocol proto) noexcept override;

	void requestComplete() noexcept override;

	void onError(proxygen::ProxygenError err) noexcept override;

	private:
		SNARLStats* const stats_{nullptr};

		std::unique_ptr<folly::IOBuf> body_;
};

}
