/** @file

  SSLNextProtocolSet

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
#include "ts/apidefs.h"
#include "tscore/ink_platform.h"
#include "P_SSLNextProtocolSet.h"
#include "tscpp/util/TextView.h"

// For currently defined protocol strings, see
// http://technotes.googlecode.com/git/nextprotoneg.html. The OpenSSL
// documentation tells us to return a string in "wire format". The
// draft NPN RFC helpfully refuses to document the wire format. The
// above link says we need to send length-prefixed strings, but does
// not say how many bytes the length is. For the record, it's 1.

// NPNのコールバックに戻す文字列は (プロトコル1の文字数 + プロトコル名1 + プロトコル2の文字数 + プロトコル名2 + ... )といった形式にする必要があります。
// ここでは「プロトコル1の文字数 + プロトコル名1 + プロトコル2の文字数 + プロトコル名2 + ... 」の形式を作り出す関数です。
unsigned char *
append_protocol(const char *proto, unsigned char *buf)
{
  size_t sz = strlen(proto);

  // ここはまずは*bufにszのプロトコル分の文字列を格納しています。その後、bufのポインタを1進めています。
  //
  // 注意: *buf++とbuf++の違いを説明しておきます。
  //      *buf++ は、ポインタ buf が指す場所の値を取得した後に、ポインタ buf を次の位置に進める操作を行います。具体的には、次の手順で処理が行われます。
  //       buf++ は、ポインタ buf を次の位置に進める操作を行うだけで、取得する値はありません。この操作はポインタを次の要素（または次のメモリ位置）に移動するためだけのものです。
  *buf++    = static_cast<unsigned char>(sz);

  // 手前でbufのポインタを1進めているので、szのプロトコル分の文字数の後にプロトコルの文字列を格納します。
  memcpy(buf, proto, sz);

  // ポインタ位置を末尾に上のmemcpyでコピーしたsz分の文字列を進めます
  return buf + sz;
}

// HTTPSリクエストをacceptした後に呼ばれる
// TLSのNPN(Next Protocol Negotiation)だけでなく、ALPNのコールバックでも呼ばれる
bool
SSLNextProtocolSet::create_npn_advertisement(const SessionProtocolSet &enabled, unsigned char **npn, size_t *len) const
{

  const SSLNextProtocolSet::NextProtocolEndpoint *ep;
  unsigned char *advertised;

  ats_free(*npn);
  *npn = nullptr;
  *len = 0;

  // この後*npnには「文字列長1 + プロトコル1名 + 文字列長2 + プロトコル名2 + ...」といった規則でサポートするプロトコルリストが格納されますが(これはOpenSSL APIに指定される)、この時の文字列を取得します。
  for (ep = endpoints.head; ep != nullptr; ep = endpoints.next(ep)) {
    ink_release_assert((strlen(ep->protocol) > 0));
    // ここでep->protocol(プロトコル名)に「+1」しているのはプロトコル名の前に必ず1byteの文字列長が必要となるためです
    *len += (strlen(ep->protocol) + 1);
  }

  // この行では、advertised と *npn が同じメモリ領域を指すように設定されています。
  // つまり、ats_malloc(*len) によって確保されたメモリブロックの先頭アドレスが advertised および *npn に代入されています。
  *npn = advertised = static_cast<unsigned char *>(ats_malloc(*len));
  if (!(*npn)) {
    goto fail;
  }

  // 全てのプロトコル情報によりイテレーション操作を行います
  for (ep = endpoints.head; ep != nullptr; ep = endpoints.next(ep)) {

    // 有効なプロトコルに設定されている場合には、NPNコールバック用との文字列を生成します(詳細はappend_protocolを参考のこと)
    if (enabled.contains(globalSessionProtocolNameRegistry.toIndex(ts::TextView{ep->protocol, strlen(ep->protocol)}))) {

      // リクエストを受信すると下記のようにALPNに含まれる値を各行それぞれで表示します
      //   DEBUG: <SSLNextProtocolSet.cc:68 (create_npn_advertisement)> (ssl) advertising protocol h2, 0x55fd2426cf40
      //   DEBUG: <SSLNextProtocolSet.cc:68 (create_npn_advertisement)> (ssl) advertising protocol http/1.1, 0x55fd2426cdb0
      //   DEBUG: <SSLNextProtocolSet.cc:68 (create_npn_advertisement)> (ssl) advertising protocol http/1.0, 0x55fd2426cdb0
      Debug("ssl", "advertising protocol %s, %p", ep->protocol, ep->endpoint);

      // append_protocolでadvertisedポインタの位置が変わってきます。
      // 要するに、advertised と *npn は同じメモリブロックの異なる位置を指すポインタとして扱われています。
      advertised = append_protocol(ep->protocol, advertised);
    }
  }

  return true;

fail:
  ats_free(*npn);
  *npn = nullptr;
  *len = 0;
  return false;
}

bool
SSLNextProtocolSet::registerEndpoint(const char *proto, Continuation *ep)
{

  size_t len = strlen(proto);

  // Both ALPN and NPN only allow 255 bytes of protocol name.
  if (len > 255) {
    return false;
  }

  if (!findEndpoint(reinterpret_cast<const unsigned char *>(proto), len)) {
    this->endpoints.push(new NextProtocolEndpoint(proto, ep));
    return true;
  }

  return false;

}

Continuation *
SSLNextProtocolSet::findEndpoint(const unsigned char *proto, unsigned len) const
{
  for (const NextProtocolEndpoint *ep = this->endpoints.head; ep != nullptr; ep = this->endpoints.next(ep)) {
    size_t sz = strlen(ep->protocol);
    if (sz == len && memcmp(ep->protocol, proto, len) == 0) {
      return ep->endpoint;
    }
  }
  return nullptr;
}

SSLNextProtocolSet::SSLNextProtocolSet() {}

SSLNextProtocolSet::~SSLNextProtocolSet()
{
  for (NextProtocolEndpoint *ep; (ep = this->endpoints.pop());) {
    delete ep;
  }
}

SSLNextProtocolSet::NextProtocolEndpoint::NextProtocolEndpoint(const char *_proto, Continuation *_ep)
  : protocol(_proto), endpoint(_ep)
{
}

SSLNextProtocolSet::NextProtocolEndpoint::~NextProtocolEndpoint() {}
