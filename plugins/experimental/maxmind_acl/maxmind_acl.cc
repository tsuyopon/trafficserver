/*
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

// 仕様書は下記を参考のこと
//   cf. https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html

#include "mmdb.h"

///////////////////////////////////////////////////////////////////////////////
// Initialize the plugin as a remap plugin.
//

// 起動時に最初に1度だけ処理する関数
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (api_info->size < sizeof(TSRemapInterface)) {
    strncpy(errbuf, "[tsremap_init] - Incorrect size of TSRemapInterface structure", errbuf_size - 1);
    return TS_ERROR;
  }

  if (api_info->tsremap_version < TSREMAP_VERSION) {
    snprintf(errbuf, errbuf_size, "[tsremap_init] - Incorrect API version %ld.%ld", api_info->tsremap_version >> 16,
             (api_info->tsremap_version & 0xffff));
    return TS_ERROR;
  }

  TSDebug(PLUGIN_NAME, "remap plugin is successfully initialized");
  return TS_SUCCESS;
}

// 起動時に最初に1度だけ処理する関数(TSRemapInitの後に実行される)
TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char * /* errbuf */, int /* errbuf_size */)
{
  if (argc < 3) {
    TSError("[%s] Unable to create remap instance, missing configuration file", PLUGIN_NAME);
    return TS_ERROR;
  }

  // Aclクラスはgeoip_aclプラグインにも同一の名前があるので読み間違えないように注意
  Acl *a = new Acl();

  // Aclクラスをなんでも可能な入れ物である"void *"に対してihにセットしておく
  *ih    = static_cast<void *>(a);

  // 「map http://example.com/music http://music.example.com @plugin=maxmind_acl.so @pparam=maxmind.yaml」のように指定される
  // つまり、2つの引数が必要となる
  if (!a->init(argv[2])) {
    TSError("[%s] Failed to initialize maxmind with %s", PLUGIN_NAME, argv[2]);
    return TS_ERROR;
  }

  TSDebug(PLUGIN_NAME, "created remap instance with configuration %s", argv[2]);
  return TS_SUCCESS;
}

// traficserver終了時などに呼ばれる関数
void
TSRemapDeleteInstance(void *ih)
{

  // ihはTSRemapNewInstanceで設定されている
  if (nullptr != ih) {

    // Aclのポインタを取得して、deleteしてリソースを解放する
    Acl *const a = static_cast<Acl *>(ih);
    delete a;

  }
}

///////////////////////////////////////////////////////////////////////////////
// Main entry point when used as a remap plugin.
//
TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn rh, TSRemapRequestInfo *rri)
{

  if (nullptr == ih) {
    TSDebug(PLUGIN_NAME, "No ACLs configured");
  } else {

    // Aclクラスはmaxmind_aclのAclクラスとgeoip_aclのAclクラスと２つあるので参照先を間違えないように注意
    Acl *a = static_cast<Acl *>(ih);

    // Acl::evalを呼び出す。下記eval関数が主要処理となる
    if (!a->eval(rri, rh)) {

      // denyの場合の処理
      TSDebug(PLUGIN_NAME, "denying request");

      // denyの場合にはステータスコードが403 Forbiddenに固定される
      TSHttpTxnStatusSet(rh, TS_HTTP_STATUS_FORBIDDEN);

      // denyの場合にはmaxmind.yamlの $.maxmind.htmlにdenyの際に表示できるhtmlを読み込む
      a->send_html(rh);
    }
  }
  return TSREMAP_NO_REMAP;
}
