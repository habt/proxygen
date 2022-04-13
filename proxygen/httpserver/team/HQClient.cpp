/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <proxygen/httpserver/team/HQClient.h>

#include <iostream>
#include <fstream>
#include <ostream>
#include <string>
#include <thread>
#include <future>
#include <chrono>

#include <folly/io/async/AsyncTimeout.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/json.h>
#include <folly/net/NetworkSocket.h>


#include <proxygen/httpserver/team/FizzContext.h>
#include <proxygen/httpserver/team/HQLoggerHelper.h>
#include <proxygen/httpserver/team/InsecureVerifierDangerousDoNotUseInProduction.h>
#include <proxygen/httpserver/team/PartiallyReliableCurlClient.h>
#include <proxygen/lib/http/codec/HTTP1xCodec.h>
#include <proxygen/lib/utils/UtilInl.h>
#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/logging/FileQLogger.h>


namespace quic { namespace team {

std::mutex pathMtx; 

HQClient::HQClient(const HQParams& params) : params_(params) {
  if (params_.transportSettings.pacingEnabled) {
    pacingTimer_ = TimerHighRes::newTimer(
        &evb_, params_.transportSettings.pacingTimerTickInterval);
  }
}

void HQClient::handlerReady(uint16_t events) noexcept {
    std::string newPath;
    std::cout << "Handler ready: before getline" << std::endl;
    std::getline (std::cin,newPath);
    std::string token = newPath.substr(0, newPath.find("\n"));
    std::cout << "fd: " << fd_ << " message: " << token << std::endl;
    std::vector<std::string> strVec;
    strVec.push_back(token);    
    addNewHttpPaths(strVec);

  }

//static std::function<void()> sendToPipe;

void HQClient::sendToPipe(proxygen::URL url) {
	std::chrono::microseconds srtt = session_->getQuicSocket()->getState()->lossState.srtt;
	double receiveRate = session_->getQuicSocket()->getState()->lossState.localReceiveRate;
	double filteredRate = session_->getQuicSocket()->getState()->lossState.localFilteredRate;
	std::chrono::microseconds lrtt = session_->getQuicSocket()->getState()->lossState.lrtt;
	std::cout << url.getUrl() << "," << filteredRate << "," << receiveRate <<  "," << lrtt.count() << ","<< srtt.count() << "," <<"EOM" << std::endl; // temporary solution to notify end of segment download
}

void HQClient::start() {
std::cout << "HellO\n";
  initializeQuicClient();
  initializeQLogger();

  this->disableSequential = true;
  fd_= 0; //STDIN_FILENO;
  //setEventBase(&evb_); 
  initHandler(&evb_,folly::NetworkSocket(fd_));
  registerHandler(
      folly::EventHandler::READ | folly::EventHandler::PERSIST);

  // TODO: turn on cert verification
  wangle::TransportInfo tinfo;
  session_ = new proxygen::HQUpstreamSession(params_.txnTimeout,
                                             std::chrono::milliseconds(5000),
                                             nullptr, // controller
                                             tinfo,
                                             nullptr); // codecfiltercallback

  // Need this for Interop since we use HTTP0.9
  session_->setForceUpstream1_1(false);

  // TODO: this could now be moved back in the ctor
  session_->setSocket(quicClient_);
  session_->setConnectCallback(this);

  LOG(INFO) << "HQClient connecting to " << params_.remoteAddress->describe();
  session_->startNow();
  quicClient_->start(session_);

  // This is to flush the CFIN out so the server will see the handshake as
  // complete.
  evb_.loopForever();
  if (params_.migrateClient) {
    quicClient_->onNetworkSwitch(
        std::make_unique<folly::AsyncUDPSocket>(&evb_));
    sendRequests(true);
  }
  evb_.loop();
}

proxygen::HTTPTransaction* FOLLY_NULLABLE
HQClient::sendRequest(const proxygen::URL& requestUrl) {
  std::unique_ptr<CurlService::CurlClient> client =
      std::make_unique<CurlService::CurlClient>(&evb_,
                                                params_.httpMethod,
                                                requestUrl,
                                                nullptr,
                                                params_.httpHeaders,
                                                params_.httpBody,
                                                false,
                                                params_.httpVersion.major,
                                                params_.httpVersion.minor);

  client->setLogging(params_.logResponse);
  //client->setHeadersLogging(params_.logResponseHeaders);
  auto txn = session_->newTransaction(client.get());
  //VLOG(0) << "before txn check " << std::endl;
  if (!txn) {
    return nullptr;
  }
  if (!params_.outdir.empty()) {
    bool canWrite = false;
    // default output file name
    std::string filename = "hq.out";
    // try to get the name from the path
    folly::StringPiece path = requestUrl.getPath();
    size_t offset = proxygen::findLastOf(path, '/');
    if (offset != std::string::npos && (offset + 1) != path.size()) {
      filename = std::string(path.subpiece(offset + 1));
    }
    filename = folly::to<std::string>(params_.outdir, "/", filename);
    canWrite = client->saveResponseToFile(filename);
    if (!canWrite) {
      LOG(ERROR) << "Can not write output to file '" << filename
                 << "' printing to stdout instead";
    }
  }
  client->sendRequest(txn);
  std::cout << "sent curl request for ===========> " << requestUrl.getUrl() << std::endl;
  curls_.emplace_back(std::move(client));

  // Binding sendToPipe ( a non-static member function with arguements) as callable
  std::function<void(proxygen::URL)> f = [=](proxygen::URL url) {
    this->sendToPipe(url);
  };
  curls_.back()->setEOMFunc(f);
  return txn;
}

static std::function<void()> sendOneMoreRequest;

void HQClient::sendRequests(bool closeSession) {
  VLOG(10) << "http-version:" << params_.httpVersion;
  numOpenableStreams = quicClient_->getNumOpenableBidirectionalStreams();
  std::cout << "sendRequest: Httppaths size: " << httpPaths_.size() << std::endl;
  //for (int i=0; i<httpPaths_.size(); ++i) {
    //      std::cout << httpPaths_[i] << ' ';
 // }
  //std::cout << std::endl;
  while (!httpPaths_.empty() && numOpenableStreams > 0) {
    proxygen::URL requestUrl(httpPaths_.front(), /*secure=*/true);
    std::cout << "sendReuest: Before sending request" << std::endl;
    sendRequest(requestUrl);
    std::cout  << "URL is " << httpPaths_.front() << std::endl;
    httpPaths_.pop_front();
    numOpenableStreams--;
    //std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  // If there are still pending requests to be sent sequentially, schedule a
  // callback on the first EOM to try to make one more request. That callback
  // will keep scheduling itself until there are no more requests.
  //if (params_.sendRequestsSequentially && !httpPaths_.empty()) {
  if(!disableSequential){
    auto sendOneMoreRequest = [&]() {
      uint64_t numOpenable = quicClient_->getNumOpenableBidirectionalStreams();
      if (numOpenable > 0) {
        sendRequests(true);
      };
    };
    CHECK(!curls_.empty());
    //curls_.back()->setEOMFunc(sendOneMoreRequest);
  }
  
  if (closeSession && httpPaths_.empty() && disableSequential ) { 
    session_->drain(); 
    session_->closeWhenIdle();
  }
}
static std::function<void()> selfSchedulingRequestRunner;

void HQClient::connectSuccess() {
  numOpenableStreams =
      quicClient_->getNumOpenableBidirectionalStreams();
  CHECK_GT(numOpenableStreams, 0);
  // Lock mutex here
  pathMtx.lock();
  httpPaths_.insert(
      httpPaths_.end(), params_.httpPaths.begin(), params_.httpPaths.end());
  //Unlock mutex here
  pathMtx.unlock();


  //sendRequests(!params_.migrateClient);
  sendRequests(false);

  // If there are still pending requests, schedule a callback on the first EOM
  // to try to make some more. That callback will keep scheduling itself until
  // there are no more requests.
  if (!httpPaths_.empty()) {
    selfSchedulingRequestRunner = [&]() {
      //uint64_t numOpenable = quicClient_->getNumOpenableBidirectionalStreams();
      if (numOpenableStreams > 0) {
        sendRequests(true);
      };
      if (!httpPaths_.empty()) {
        auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
            quicClient_->getTransportInfo().srtt);
        evb_.timer().scheduleTimeoutFn(
            selfSchedulingRequestRunner,
            std::max(rtt, std::chrono::milliseconds(1)));
      }
    };
    CHECK(!curls_.empty());
    //folly::StringPiece endString = "continue";
    //if(endString != "none"){
      //curls_.back()->setEOMFunc(selfSchedulingRequestRunner);
    //}
  }
}


void HQClient::onReplaySafe() {
  VLOG(10) << "Transport replay safe";
  evb_.terminateLoopSoon();
}

void HQClient::connectError(std::pair<quic::QuicErrorCode, std::string> error) {
  LOG(ERROR) << "HQClient failed to connect, error=" << toString(error.first)
             << ", msg=" << error.second;
  evb_.terminateLoopSoon();
}

void HQClient::initializeQuicClient() {
  auto sock = std::make_unique<folly::AsyncUDPSocket>(&evb_);
  auto client = std::make_shared<quic::QuicClientTransport>(
      &evb_,
      std::move(sock),
      quic::FizzClientQuicHandshakeContext::Builder()
          .setFizzClientContext(createFizzClientContext(params_))
          .setCertificateVerifier(
              std::make_unique<
                  proxygen::InsecureVerifierDangerousDoNotUseInProduction>())
          .setPskCache(params_.pskCache)
          .build());
  client->setPacingTimer(pacingTimer_);
  client->setHostname(params_.host);
  client->addNewPeerAddress(params_.remoteAddress.value());
  if (params_.localAddress.has_value()) {
    client->setLocalAddress(*params_.localAddress);
  }
  client->setCongestionControllerFactory(
      std::make_shared<quic::DefaultCongestionControllerFactory>());
  client->setTransportSettings(params_.transportSettings);
  client->setSupportedVersions(params_.quicVersions);

  quicClient_ = std::move(client);
}

void HQClient::initializeQLogger() {
  if (!quicClient_) {
    return;
  }
  // Not used immediately, but if not set
  // the qlogger wont be able to report. Checking early
  if (params_.qLoggerPath.empty()) {
    return;
  }

  auto qLogger = std::make_shared<HQLoggerHelper>(
      params_.qLoggerPath, params_.prettyJson, quic::VantagePoint::Client);
  quicClient_->setQLogger(std::move(qLogger));
}

void HQClient::addNewHttpPaths(std::vector<std::string> nextPaths_) {
   httpPaths_.insert(
        httpPaths_.end(), nextPaths_.begin(), nextPaths_.end()); 
  //httpPaths_.push_back(nextPaths_[0]);
  for (int i=0; i<httpPaths_.size(); ++i) {
	  std::cout << "inside add new path " << httpPaths_[i] << ' ';
    }
  std::cout << std::endl;
  if(nextPaths_[0] == "exit"){
  	sendRequests(true);
  } else {
	std::cout << "Addnewpath: Before sending request" << std::endl; 
  	sendRequests(false);
  }

}

void HQClient::turnOffSequential(){
  disableSequential = true;
}

template <class printable>
void printOutVector(printable paths_, std::string meta){
	std::cout << "printing " << meta << std::endl;
	for (int i=0; i<paths_.size(); ++i) {
		std::cout << paths_[i] << ' ';
    	}	
  	std::cout << std::endl;
}

std::vector<std::string> split2(const std::string &str, char sep)
{
	std::vector<std::string> tokens;

	std::string i;
	std::stringstream ss(str);
    	while (ss >> i) {
        	tokens.push_back(i);
        	if (ss.peek() == sep) {
            		ss.ignore();
        	}
    	}	

    	return tokens;
}

void obtainNextPaths(HQClient& client_) {
    std::vector<std::string> nextPaths_;
    //std::vector<std::string> nextPaths_;
    std::string inp = "PATH1";
    std::cout << "Enter next path";
    int i=0;
    std::cout << "Inside obtain nextPaths address: " << &nextPaths_ << std::endl;
    while(inp != "exit") {
      std::cin >> inp;
      //std::this_thread::sleep_for(std::chrono::seconds(2));
      std::cout << i << ". Next path is " << inp << std::endl; 
      //folly::split(',', inp, nextPaths_);
      nextPaths_ = split2(inp, ',');
      //Lock mutex here
      pathMtx.lock();
      client_.addNewHttpPaths(nextPaths_);
      //client_.httpPaths_.insert(client_.httpPaths_.end(), nextPaths_.begin(), nextPaths_.end());
      //printOutVector(client_.httpPaths_, "httpPaths_");
      pathMtx.unlock();
      i++;
      nextPaths_.clear();
    }
    client_.turnOffSequential();
    std::cout << "out of input loop ";
    //unlock mutex here

    //return httpPaths;
}


void startClient(const HQParams& params) {
  HQClient client(params);
  //std::thread inp (obtainNextPaths, std::ref(client));
  client.start();
  //inp.join();
}

}} // namespace quic::team
