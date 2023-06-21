/** @file

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "tscore/ink_config.h"

#include "P_Net.h"
#include "tscore/I_Layout.h"
#include "records/I_RecHttp.h"
#include "P_SSLUtils.h"
#include "P_OCSPStapling.h"
#include "SSLStats.h"
#include "P_SSLNetProcessor.h"
#include "P_SSLNetAccept.h"
#include "P_SSLNetVConnection.h"
#include "P_SSLClientCoordinator.h"

//
// Global Data
//

SSLNetProcessor ssl_NetProcessor;
NetProcessor &sslNetProcessor = ssl_NetProcessor;

#if TS_USE_TLS_OCSP
struct OCSPContinuation : public Continuation {

  int
  mainEvent(int /* event ATS_UNUSED */, Event * /* e ATS_UNUSED */)
  {
    Note("OCSP refresh started");

    // ここがET_OCSPで実行されるスレッドのメインとなる起点のポイント
    ocsp_update();

    Note("OCSP refresh finished");
    return EVENT_CONT;
  }

  OCSPContinuation() : Continuation(new_ProxyMutex()) { SET_HANDLER(&OCSPContinuation::mainEvent); }
};
#endif /* TS_USE_TLS_OCSP */

void
SSLNetProcessor::cleanup()
{
}

int
SSLNetProcessor::start(int, size_t stacksize)
{
  // This initialization order matters ...
  SSLInitializeLibrary();
  SSLClientCoordinator::startup();
  SSLPostConfigInitialize();

  if (!SSLCertificateConfig::startup()) {
    return -1;
  }
  SSLTicketKeyConfig::startup();

  // Acquire a SSLConfigParams instance *after* we start SSL up.
  // SSLConfig::scoped_config params;

  // Initialize SSL statistics. This depends on an initial set of certificates being loaded above.
  SSLInitializeStatistics();

#if TS_USE_TLS_OCSP
  // proxy.config.ssl.ocsp.enabledが有効であれば
  if (SSLConfigParams::ssl_ocsp_enabled) {

    // OCSP専用にET_OCSPスレッドを1つ生成します
    EventType ET_OCSP  = eventProcessor.spawn_event_threads("ET_OCSP", 1, stacksize);

    // スレッドの起点となるエンドポイントはOCSPContinuationクラスです。この中でocsp_update関数が実行されます。
    Continuation *cont = new OCSPContinuation();

    // schedule the update initially to get things populated
    // 即時実行と定期実行2つ指定しています。
    //   即時実行により起動時に即座に執行情報を最初に取得します。
    //   定期実行(デフォルト60秒)により定期的にX.509に記載のOCSPレスポンダにアクセスして、最新の執行状況を取得します
    eventProcessor.schedule_imm(cont, ET_OCSP);
    eventProcessor.schedule_every(cont, HRTIME_SECONDS(SSLConfigParams::ssl_ocsp_update_period), ET_OCSP);

  }
#endif /* TS_USE_TLS_OCSP */

  // We have removed the difference between ET_SSL threads and ET_NET threads,
  // So just keep on chugging
  return 0;
}

NetAccept *
SSLNetProcessor::createNetAccept(const NetProcessor::AcceptOptions &opt)
{
  return (NetAccept *)new SSLNetAccept(opt);
}

NetVConnection *
SSLNetProcessor::allocate_vc(EThread *t)
{
  SSLNetVConnection *vc;

  if (t) {
    vc = THREAD_ALLOC_INIT(sslNetVCAllocator, t);
  } else {
    if (likely(vc = sslNetVCAllocator.alloc())) {
      vc->from_accept_thread = true;
    }
  }

  return vc;
}

SSLNetProcessor::SSLNetProcessor() {}

SSLNetProcessor::~SSLNetProcessor()
{
  cleanup();
}
