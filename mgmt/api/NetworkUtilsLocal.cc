/** @file

  A brief file description

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

/***************************************************************************
 * NetworkUtilsLocal.cc
 *
 * contains implementation of local networking utility functions, such as
 * unmarshalling requests from a remote client and marshalling replies
 *
 *
 ***************************************************************************/

/*
このファイル(NetworkUtilsLocal.cc)は、TrafficManagerから利用されています。

$ git grep -B 4 NetworkUtilsLocal.cc  | grep Makefile
mgmt/api/Makefile.am-libmgmtapilocal_la_SOURCES = \
mgmt/api/Makefile.am-	CoreAPI.cc \
mgmt/api/Makefile.am-	EventControlMain.cc \
mgmt/api/Makefile.am-	EventControlMain.h \
mgmt/api/Makefile.am:	NetworkUtilsLocal.cc \
$ git grep libmgmtapilocal.la
mgmt/api/Makefile.am:noinst_LTLIBRARIES = libmgmtapilocal.la libmgmtapi.la
mgmt/api/Makefile.am:libmgmtapilocal_la_SOURCES = \
mgmt/api/Makefile.am:libmgmtapilocal_la_LIBADD = \
src/traffic_manager/Makefile.inc:       $(top_builddir)/mgmt/api/libmgmtapilocal.la \
*/

#include "tscore/ink_platform.h"
#include "tscore/ink_sock.h"
#include "tscore/Diags.h"
#include "MgmtUtils.h"
#include "MgmtSocket.h"
#include "MgmtMarshall.h"
#include "CoreAPIShared.h"
#include "NetworkUtilsLocal.h"
#include "NetworkMessage.h"

/**********************************************************************
 * preprocess_msg
 *
 * purpose: reads in all the message; parses the message into header info
 *          (OpType + msg_len) and the request portion (used by the handle_xx fns)
 * input: sock_info - socket msg is read from
 *        msg       - the data from the network message (no OpType or msg_len)
 * output: TS_ERR_xx ( if TS_ERR_OKAY, then parameters set successfully)
 * notes: Since preprocess_msg already removes the OpType and msg_len, this part o
 *        the message is not dealt with by the other parsing functions
 **********************************************************************/
TSMgmtError
preprocess_msg(int fd, void **req, size_t *reqlen)
{

  TSMgmtError ret;
  MgmtMarshallData msg;

  *req    = nullptr;
  *reqlen = 0;

  // メッセージを受信します。この関数への遷移元によってfdのsocketが変わってきます。
  //  - mgmt/api/TSControlMain.cc のts_ctrl_main関数からの遷移の場合にはmgmtapi.sockのfdが入ります。
  //  - mgmt/api/EventControlMain.cc のevent_callback_main関数からの遷移の場合にはeventapi.sockのfdが入ります。
  ret = recv_mgmt_message(fd, msg);
  if (ret != TS_ERR_OKAY) {
    return ret;
  }

  // We should never receive an empty payload.
  // 空のペイロードを受け取るべきではないので、受け取ったらエラーとする
  if (msg.ptr == nullptr) {
    return TS_ERR_NET_READ;
  }

  // 関数へのポインタとして指定されている*reqや*reqlenに登録します
  *req    = msg.ptr;
  *reqlen = msg.len;

  Debug("ts_main", "[preprocess_msg] read message length = %zd", msg.len);
  return TS_ERR_OKAY;

}
