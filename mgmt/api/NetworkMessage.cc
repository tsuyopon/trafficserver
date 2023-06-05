/** @file

  Network message marshalling.

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

/*

下記の調査結果の通り、このNetworkMessage.ccはTraffic Serverでは利用されません。
Traffic Managerやtraffic_ctlでは組み込まれているので利用されている可能性があります

$ git grep -B 8 NetworkMessage.cc | grep Makefile.am
mgmt/api/Makefile.am-
mgmt/api/Makefile.am-libmgmtapi_la_SOURCES = \
mgmt/api/Makefile.am-   CoreAPI.h \
mgmt/api/Makefile.am-   CoreAPIShared.cc \
mgmt/api/Makefile.am-   CoreAPIShared.h \
mgmt/api/Makefile.am-   EventCallback.cc \
mgmt/api/Makefile.am-   EventCallback.h \
mgmt/api/Makefile.am-   INKMgmtAPI.cc \
mgmt/api/Makefile.am:   NetworkMessage.cc \


libmgmtapi.laは下記の2つのライブラリ生成に追加されます。
(1) 
libmgmtapilocal_la_LIBADD = \
    libmgmtapi.la \
    $(top_builddir)/src/tscore/libtscore.la


(2)
libtsmgmt_la_LIBADD = @LIBOBJS@ \
    libmgmtapi.la \
    $(top_builddir)/src/tscore/libtscore.la \
    $(top_builddir)/mgmt/utils/libutils_p.la


これら2つの利用箇所がNetworkMessage.ccの利用箇所となります。
$ git grep libtsmgmt.la
mgmt/api/Makefile.am:lib_LTLIBRARIES = libtsmgmt.la
mgmt/api/Makefile.am:libtsmgmt_la_SOURCES = \
mgmt/api/Makefile.am:libtsmgmt_la_LDFLAGS = @AM_LDFLAGS@ -no-undefined -version-info @TS_LIBTOOL_VERSION@
mgmt/api/Makefile.am:libtsmgmt_la_LIBADD = @LIBOBJS@ \
mgmt/api/Makefile.am:   libtsmgmt.la \
src/traffic_crashlog/Makefile.inc:      $(top_builddir)/mgmt/api/libtsmgmt.la \
src/traffic_ctl/Makefile.inc:   $(top_builddir)/mgmt/api/libtsmgmt.la \
src/traffic_top/Makefile.inc:   $(top_builddir)/mgmt/api/libtsmgmt.la \

$ git grep libmgmtapilocal.la
mgmt/api/Makefile.am:noinst_LTLIBRARIES = libmgmtapilocal.la libmgmtapi.la
mgmt/api/Makefile.am:libmgmtapilocal_la_SOURCES = \
mgmt/api/Makefile.am:libmgmtapilocal_la_LIBADD = \
src/traffic_manager/Makefile.inc:       $(top_builddir)/mgmt/api/libmgmtapilocal.la \


*/

#include "tscore/ink_config.h"
#include "tscore/ink_defs.h"
#include "tscore/ink_error.h"
#include "tscore/ink_assert.h"
#include "tscore/ink_memory.h"
#include "mgmtapi.h"
#include "NetworkMessage.h"

#define MAX_OPERATION_FIELDS 16

struct NetCmdOperation {
  unsigned nfields;
  const MgmtMarshallType fields[MAX_OPERATION_FIELDS];
};

// Requests always begin with a OpType, followed by additional fields.
//
// 「static const control_message_handler handlers[]」や「static const event_message_handler handlers[]」の定義と同様のコマンド定義がされている
static const struct NetCmdOperation requests[] = {
  /* RECORD_SET                 */ {3, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_STRING}},
  /* RECORD_GET                 */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* PROXY_STATE_GET            */ {1, {MGMT_MARSHALL_INT}},
  /* PROXY_STATE_SET            */ {3, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* RECONFIGURE                */ {1, {MGMT_MARSHALL_INT}},
  /* RESTART                    */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* BOUNCE                     */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* STOP                       */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* DRAIN                      */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* EVENT_RESOLVE              */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* EVENT_GET_MLT              */ {1, {MGMT_MARSHALL_INT}},
  /* EVENT_ACTIVE               */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* EVENT_REG_CALLBACK         */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* EVENT_UNREG_CALLBACK       */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* EVENT_NOTIFY               */ {3, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_STRING}}, // only msg sent from TM to
                                                                                                         // client
  /* STATS_RESET_NODE           */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* STORAGE_DEVICE_CMD_OFFLINE */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* RECORD_MATCH_GET           */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* API_PING                   */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* SERVER_BACKTRACE           */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* RECORD_DESCRIBE_CONFIG     */ {3, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_INT}},
  /* LIFECYCLE_MESSAGE          */ {3, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_DATA}},
  /* HOST_STATUS_HOST_UP        */ {4, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_STRING, MGMT_MARSHALL_INT}},
  /* HOST_STATUS_HOST_DOWN      */ {4, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_STRING, MGMT_MARSHALL_INT}},
};

// Responses always begin with a TSMgmtError code, followed by additional fields.
static const struct NetCmdOperation responses[] = {
  /* RECORD_SET                 */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* RECORD_GET                 */
  {5, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT, MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_DATA}},
  /* PROXY_STATE_GET            */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* PROXY_STATE_SET            */ {1, {MGMT_MARSHALL_INT}},
  /* RECONFIGURE                */ {1, {MGMT_MARSHALL_INT}},
  /* RESTART                    */ {1, {MGMT_MARSHALL_INT}},
  /* BOUNCE                     */ {1, {MGMT_MARSHALL_INT}},
  /* STOP                       */ {1, {MGMT_MARSHALL_INT}},
  /* DRAIN                      */ {1, {MGMT_MARSHALL_INT}},
  /* EVENT_RESOLVE              */ {1, {MGMT_MARSHALL_INT}},
  /* EVENT_GET_MLT              */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* EVENT_ACTIVE               */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT}},
  /* EVENT_REG_CALLBACK         */ {0, {}}, // no reply
  /* EVENT_UNREG_CALLBACK       */ {0, {}}, // no reply
  /* EVENT_NOTIFY               */ {0, {}}, // no reply
  /* STATS_RESET_NODE           */ {1, {MGMT_MARSHALL_INT}},
  /* STORAGE_DEVICE_CMD_OFFLINE */ {1, {MGMT_MARSHALL_INT}},
  /* RECORD_MATCH_GET           */
  {5, {MGMT_MARSHALL_INT, MGMT_MARSHALL_INT, MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_DATA}},
  /* API_PING                   */ {0, {}}, // no reply
  /* SERVER_BACKTRACE           */ {2, {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING}},
  /* RECORD_DESCRIBE_CONFIG     */
  {15,
   {MGMT_MARSHALL_INT /* status */, MGMT_MARSHALL_STRING /* name */, MGMT_MARSHALL_DATA /* value */,
    MGMT_MARSHALL_DATA /* default */, MGMT_MARSHALL_INT /* type */, MGMT_MARSHALL_INT /* class */, MGMT_MARSHALL_INT /* version */,
    MGMT_MARSHALL_INT /* rsb */, MGMT_MARSHALL_INT /* order */, MGMT_MARSHALL_INT /* access */, MGMT_MARSHALL_INT /* update */,
    MGMT_MARSHALL_INT /* updatetype */, MGMT_MARSHALL_INT /* checktype */, MGMT_MARSHALL_INT /* source */,
    MGMT_MARSHALL_STRING /* checkexpr */}},
  /* LIFECYCLE_MESSAGE          */ {1, {MGMT_MARSHALL_INT}},
  /* HOST_STATUS_UP             */ {1, {MGMT_MARSHALL_INT}},
  /* HOST_STATUS_DOWN           */ {1, {MGMT_MARSHALL_INT}},
};


// 上記で定義されている「static const struct NetCmdOperation requests[]」の1つのコマンドで定義されるマッピング情報へと変換されます。
#define GETCMD(ops, optype, cmd)                           \
  do {                                                     \
    if (static_cast<unsigned>(optype) >= countof(ops)) {   \
      return TS_ERR_PARAMS;                                \
    }                                                      \
    if (ops[static_cast<unsigned>(optype)].nfields == 0) { \
      return TS_ERR_PARAMS;                                \
    }                                                      \
    cmd = &ops[static_cast<unsigned>(optype)];             \
  } while (0);

// mgmtのためのメッセージを作成して、送信します
TSMgmtError
send_mgmt_request(const mgmt_message_sender &snd, OpType optype, ...)  // 可変長引数を受け取る
{
  va_list ap;
  ats_scoped_mem<char> msgbuf;
  MgmtMarshallInt msglen;
  const MgmtMarshallType lenfield[] = {MGMT_MARSHALL_INT};
  const NetCmdOperation *cmd;

  if (!snd.is_connected()) {
    return TS_ERR_NET_ESTABLISH; // no connection.
  }

  // requestsやoptypeの値を取得して、cmdにリクエストに必要となる情報を追加します
  GETCMD(requests, optype, cmd);

  // mgmt_message_length_vではメッセージの長さを求めます 
  // cmd->fields, cmd->nfieldsの値はGETCMDを呼び出したら設定されます。
  // ここにはメッセージに指定されるフィールド配列、フィールドの個数が入ります。可変長引数のapにはフィールドに詰める値が指定されます。
  // (送付するメッセージの長さを求めるだけなら可変長引数apは不要のようにも思えますが、MGMT_MARSHALL_STRINGやMGMT_MARSHALL_DATAだと入る長さは不定になるので長さを算出する必要があります。
  // なお、apにはフィールド数分の値を指定する必要があります
  va_start(ap, optype);
  msglen = mgmt_message_length_v(cmd->fields, cmd->nfields, ap);
  va_end(ap);

  msgbuf = static_cast<char *>(ats_malloc(msglen + 4));

  // メッセージの作成は2段階に分ける(1と2では指定されている引数が異なることに注意する)
  //
  // 1. mgmt_message_marshall
  //     メッセージサイズを表すヘッダの部分にだけ値をコピーしている。(内部的にはmgmt_message_marshall_vも呼び出しているが1と2で役割が違うことに注意する)
  // 2. mgmt_message_marshall_v
  //     メッセージの本文部分に値を設定していく


  // First marshall the total message length.
  // 1. lenfieldはこの関数の先頭に定義されていてい「{MGMT_MARSHALL_INT}」となります。そのため、countof(lenfield)は必ず1になります。そして、可変長引数の &msglenにはメッセージ全体のサイズが入ります。
  mgmt_message_marshall((char *)msgbuf, msglen, lenfield, countof(lenfield), &msglen);

  // Now marshall the message itself.
  // 2. 1ではMGMT_MARSHALL_INTサイズ分のメッセージ長を保存していているため、4byte増やした位置からパケットへの登録を行います。
  // cmd->fields, cmd->nfieldsの値はGETCMDを呼び出したら設定されているものです。
  // 下記関数に指定される引数にはフィールド配列(cmd->fields)、フィールドの個数(cmd->nfields)が入ります。可変長引数のapにはフィールドに詰める値がフィールド配列(cmd->fields)に指定した値の順番でフィールドの個数(cmd->nfields)分指定が必要です。
  va_start(ap, optype);
  if (mgmt_message_marshall_v((char *)msgbuf + 4, msglen, cmd->fields, cmd->nfields, ap) == -1) {
    va_end(ap);
    return TS_ERR_PARAMS;
  }

  va_end(ap);

  // mgmtapi_sender::send を呼び出す
  return snd.send(msgbuf, msglen + 4);  // 「+ 4」は先頭にメッセージのサイズとしてMGMT_MARSHALL_INT分のパケット長を追加しているのでその分

}

// 下記の様に呼ばれる
//  (例) ret = send_mgmt_request(client_entry->fd, OpType::EVENT_NOTIFY, &optype, &name, &desc);
TSMgmtError
send_mgmt_request(int fd, OpType optype, ...)
{

  va_list ap;
  MgmtMarshallInt msglen;
  MgmtMarshallData req            = {nullptr, 0};
  const MgmtMarshallType fields[] = {MGMT_MARSHALL_DATA};
  const NetCmdOperation *cmd;

  // 下記でoptype=「OpType::EVENT_NOTIFY」としてのリクエストは下記でcmdに登録しています
  // 例えば、cmd = &request[static_cast<unsigned>(OpType::EVENT_NOTIFY)];  として変換されます。
  GETCMD(requests, optype, cmd);

  // Figure out the payload length.
  // cmdに応じてリクエストする際のデータ構造が決まっていてその長さをmgmt_message_length_vで取得しています。その値はreq.lenに設定してから、mgmt_message_marshall_vを呼び出すために使われています。
  va_start(ap, optype);
  msglen = mgmt_message_length_v(cmd->fields, cmd->nfields, ap);
  va_end(ap);

  ink_assert(msglen >= 0);

  req.ptr = static_cast<char *>(ats_malloc(msglen));
  req.len = msglen;

  // Marshall the message itself.
  // 下記でレスポンスが帰ってくる
  va_start(ap, optype);
  if (mgmt_message_marshall_v(req.ptr, req.len, cmd->fields, cmd->nfields, ap) == -1) {
    ats_free(req.ptr);
    va_end(ap);
    return TS_ERR_PARAMS;
  }

  va_end(ap);

  MgmtMarshallInt op;
  MgmtMarshallString name;
  int down_time;
  static const MgmtMarshallType fieldso[] = {MGMT_MARSHALL_INT, MGMT_MARSHALL_STRING, MGMT_MARSHALL_INT};

  // 上記でfieldsoには固定フィールドが指定されています。countof(fieldso)の値は3になります。
  if (mgmt_message_parse(static_cast<void *>(req.ptr), msglen, fieldso, countof(fieldso), &op, &name, &down_time) == -1) {
    printf("Plugin message - RPC parsing error - message discarded.\n");
  }

  // Send the response as the payload of a data object.
  // メッセージの書き込みを行います
  if (mgmt_message_write(fd, fields, countof(fields), &req) == -1) {
    ats_free(req.ptr);
    return TS_ERR_NET_WRITE;
  }

  ats_free(req.ptr);
  return TS_ERR_OKAY;
}

TSMgmtError
send_mgmt_error(int fd, OpType optype, TSMgmtError error)
{
  MgmtMarshallInt ecode     = error;
  MgmtMarshallInt intval    = 0;
  MgmtMarshallData dataval  = {nullptr, 0};
  MgmtMarshallString strval = nullptr;

  // Switch on operations, grouped by response format.
  switch (optype) {
  case OpType::BOUNCE:
  case OpType::STOP:
  case OpType::DRAIN:
  case OpType::EVENT_RESOLVE:
  case OpType::LIFECYCLE_MESSAGE:
  case OpType::PROXY_STATE_SET:
  case OpType::RECONFIGURE:
  case OpType::RESTART:
  case OpType::STATS_RESET_NODE:
  case OpType::HOST_STATUS_UP:
  case OpType::HOST_STATUS_DOWN:
  case OpType::STORAGE_DEVICE_CMD_OFFLINE:
    ink_release_assert(responses[static_cast<unsigned>(optype)].nfields == 1);
    return send_mgmt_response(fd, optype, &ecode);

  case OpType::RECORD_SET:
  case OpType::PROXY_STATE_GET:
  case OpType::EVENT_ACTIVE:
    ink_release_assert(responses[static_cast<unsigned>(optype)].nfields == 2);
    return send_mgmt_response(fd, optype, &ecode, &intval);

  case OpType::EVENT_GET_MLT:
  case OpType::SERVER_BACKTRACE:
    ink_release_assert(responses[static_cast<unsigned>(optype)].nfields == 2);
    return send_mgmt_response(fd, optype, &ecode, &strval);

  case OpType::RECORD_GET:
  case OpType::RECORD_MATCH_GET:
    ink_release_assert(responses[static_cast<unsigned>(optype)].nfields == 5);
    return send_mgmt_response(fd, optype, &ecode, &intval, &intval, &strval, &dataval);

  case OpType::RECORD_DESCRIBE_CONFIG:
    ink_release_assert(responses[static_cast<unsigned>(optype)].nfields == 15);
    return send_mgmt_response(fd, optype, &ecode, &strval /* name */, &dataval /* value */, &dataval /* default */,
                              &intval /* type */, &intval /* class */, &intval /* version */, &intval /* rsb */,
                              &intval /* order */, &intval /* access */, &intval /* update */, &intval /* updatetype */,
                              &intval /* checktype */, &intval /* source */, &strval /* checkexpr */);

  case OpType::EVENT_REG_CALLBACK:
  case OpType::EVENT_UNREG_CALLBACK:
  case OpType::EVENT_NOTIFY:
  case OpType::API_PING:
    /* no response for these */
    ink_release_assert(responses[static_cast<unsigned>(optype)].nfields == 0);
    return TS_ERR_OKAY;

  case OpType::UNDEFINED_OP:
    return TS_ERR_OKAY;
  }

  // We should never get here unless OpTypes are added without
  // updating the switch statement above. Don't do that; this
  // code must be able to handle every OpType.

  ink_fatal("missing generic error support for type %d management message", static_cast<int>(optype));
  return TS_ERR_FAIL;
}

// Send a management message response. We don't need to worry about retransmitting the message if we get
// disconnected, so this is much simpler. We can directly marshall the response as a data object.
TSMgmtError
send_mgmt_response(int fd, OpType optype, ...)
{

  va_list ap;
  MgmtMarshallInt msglen;
  MgmtMarshallData reply          = {nullptr, 0};
  const MgmtMarshallType fields[] = {MGMT_MARSHALL_DATA};
  const NetCmdOperation *cmd;

  // レスポンスに必要なメッセージの構造も決まっているので取得します
  GETCMD(responses, optype, cmd);

  // メッセージのためのサイズを求める
  va_start(ap, optype);
  msglen = mgmt_message_length_v(cmd->fields, cmd->nfields, ap);
  va_end(ap);

  ink_assert(msglen >= 0);

  reply.ptr = static_cast<char *>(ats_malloc(msglen));
  reply.len = msglen;

  // Marshall the message itself.
  // メッセージを生成する
  va_start(ap, optype);
  if (mgmt_message_marshall_v(reply.ptr, reply.len, cmd->fields, cmd->nfields, ap) == -1) {
    ats_free(reply.ptr);
    va_end(ap);
    return TS_ERR_PARAMS;
  }

  va_end(ap);

  // Send the response as the payload of a data object.
  // メッセージを送信する
  if (mgmt_message_write(fd, fields, countof(fields), &reply) == -1) {
    ats_free(reply.ptr);
    return TS_ERR_NET_WRITE;
  }

  ats_free(reply.ptr);
  return TS_ERR_OKAY;
}

template <unsigned N>
static TSMgmtError
recv_x(const struct NetCmdOperation (&ops)[N], void *buf, size_t buflen, OpType optype, va_list ap)
{
  ssize_t msglen;
  const NetCmdOperation *cmd;

  GETCMD(ops, optype, cmd);

  msglen = mgmt_message_parse_v(buf, buflen, cmd->fields, cmd->nfields, ap);
  return (msglen == -1) ? TS_ERR_PARAMS : TS_ERR_OKAY;
}

TSMgmtError
recv_mgmt_request(void *buf, size_t buflen, OpType optype, ...)
{
  TSMgmtError err;
  va_list ap;

  va_start(ap, optype);
  err = recv_x(requests, buf, buflen, optype, ap);
  va_end(ap);

  return err;
}

TSMgmtError
recv_mgmt_response(void *buf, size_t buflen, OpType optype, ...)
{
  TSMgmtError err;
  va_list ap;

  va_start(ap, optype);
  err = recv_x(responses, buf, buflen, optype, ap);
  va_end(ap);

  return err;
}

TSMgmtError
recv_mgmt_message(int fd, MgmtMarshallData &msg)
{
  const MgmtMarshallType fields[] = {MGMT_MARSHALL_DATA};

  if (mgmt_message_read(fd, fields, countof(fields), &msg) == -1) {
    return TS_ERR_NET_READ;
  }

  return TS_ERR_OKAY;
}

OpType
extract_mgmt_request_optype(void *msg, size_t msglen)
{
  const MgmtMarshallType fields[] = {MGMT_MARSHALL_INT};
  MgmtMarshallInt optype;

  if (mgmt_message_parse(msg, msglen, fields, countof(fields), &optype) == -1) {
    return OpType::UNDEFINED_OP;
  }

  return static_cast<OpType>(optype);
}
