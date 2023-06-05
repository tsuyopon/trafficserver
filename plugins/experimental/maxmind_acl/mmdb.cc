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

#include "mmdb.h"

// MaxMind DB関連についてはあまり資料がないが、下記が正規資料と思われる
//
//   github: https://github.com/maxmind/libmaxminddb
//   API: https://maxmind.github.io/libmaxminddb/
//   MaxMind DB File Format Specification: http://maxmind.github.io/MaxMind-DB/

///////////////////////////////////////////////////////////////////////////////
// Load the config file from param
// check for basics
// Clear out any existing data since this may be a reload
bool
Acl::init(char const *filename)
{
  struct stat s;
  bool status = false;

  YAML::Node maxmind;

  configloc.clear();

  // ファイル名の先頭文字列が「/」であるかどうかによって絶対パスか相対パスを判断する
  if (filename[0] != '/') {
    // relative file
    configloc = TSConfigDirGet();
    configloc += "/";
    configloc.append(filename);
  } else {
    configloc.assign(filename);
  }

  if (stat(configloc.c_str(), &s) < 0) {
    TSDebug(PLUGIN_NAME, "Could not stat %s", configloc.c_str());
    return status;
  }

  try {

    // remap.configに@pparamで指定するmaxmind.yamlの読み込みを行います。
    // cf. https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html
    _config = YAML::LoadFile(configloc.c_str());

    // 設定ファイルがyamlとしてパースできない(null)だったら
    if (_config.IsNull()) {
      TSDebug(PLUGIN_NAME, "Config file not found or unreadable");
      return status;
    }

    // yamlの構造として $.maxmind が第１階層となる。これがないと合致していないとしている。
    if (!_config["maxmind"]) {
      TSDebug(PLUGIN_NAME, "Config file not in maxmind namespace");
      return status;
    }

    // Get our root maxmind node
    // $.maxmind 配下のノードを取得する
    maxmind = _config["maxmind"];

// テスト用途
#if 0
      // Test junk
      for (YAML::const_iterator it = maxmind.begin(); it != maxmind.end(); ++it) {
        const std::string &name    = it->first.as<std::string>();
        YAML::NodeType::value type = it->second.Type();
        TSDebug(PLUGIN_NAME, "name: %s, value: %d", name.c_str(), type);
      }
#endif
  } catch (const YAML::Exception &e) {
    TSError("[%s] YAML::Exception %s when parsing YAML config file %s for maxmind", PLUGIN_NAME, e.what(), configloc.c_str());
    return status;
  }

  // Associate our config file with remap.config to be able to initiate reloads
  TSMgmtString result;
  const char *var_name = "proxy.config.url_remap.filename";
  TSMgmtStringGet(var_name, &result);
  TSMgmtConfigFileAdd(result, configloc.c_str());

  // Find our database name and convert to full path as needed
  // $.databaseで指定されたmaxminddbのデータベースを読み込みます
  // see: https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html#configuration
  status = loaddb(maxmind["database"]);

  if (!status) {
    TSDebug(PLUGIN_NAME, "Failed to load MaxMind Database");
    return status;
  }

  // Clear out existing data, these may no longer exist in a new config and so we
  // dont want old ones left behind
  allow_country.clear();
  allow_ip_map.clear();
  deny_ip_map.clear();
  allow_regex.clear();
  deny_regex.clear();
  _html.clear();
  default_allow = false;

  // 指定されたmaxmind.yamlから $.maxmind.allow を取得する
  if (loadallow(maxmind["allow"])) {
    TSDebug(PLUGIN_NAME, "Loaded Allow ruleset");
    status = true;
  } else {
    // We have no proper allow ruleset
    // setting to allow by default to only apply deny rules
    default_allow = true;
  }

  // 指定されたmaxmind.yamlから $.maxmind.denyを取得する
  if (loaddeny(maxmind["deny"])) {
    TSDebug(PLUGIN_NAME, "Loaded Deny ruleset");
    status = true;
  }

  // 指定されたmaxmind.yamlから $.maxmind.htmlを取得して、それを引数としてloadhtml()を呼び出す
  loadhtml(maxmind["html"]);

  if (!status) {
    TSDebug(PLUGIN_NAME, "Failed to load any rulesets, none specified");
    status = false;
  }

  return status;
}

///////////////////////////////////////////////////////////////////////////////
// Parse the deny list country codes and IPs
bool
Acl::loaddeny(const YAML::Node &denyNode)
{

  if (!denyNode) {
    TSDebug(PLUGIN_NAME, "No Deny rules set");
    return false;
  }

  if (denyNode.IsNull()) {
    TSDebug(PLUGIN_NAME, "Deny rules are NULL");
    return false;
  }

#if 0
  // Test junk
  for (YAML::const_iterator it = denyNode.begin(); it != denyNode.end(); ++it) {
    const std::string &name    = it->first.as<std::string>();
    YAML::NodeType::value type = it->second.Type();
    TSDebug(PLUGIN_NAME, "name: %s, value: %d", name.c_str(), type);
  }
#endif

  // Load Allowable Country codes
  try {

    // $.deny.country があるかどうか
    //  cf. https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html#configuration
    if (denyNode["country"]) {
      YAML::Node country = denyNode["country"];

      // countryが空でない
      if (!country.IsNull()) {
        // countryがYAML構文となっている
        if (country.IsSequence()) {

          // $.deny.countryはリスト形式で指定されることがあるのでforでイテレーションする
          for (auto &&i : country) {

            // $.deny.country で指定された国情報をallow_countryに登録する
            allow_country.insert_or_assign(i.as<std::string>(), false);
          }
        } else {
          TSDebug(PLUGIN_NAME, "Invalid country code allow list yaml");
        }
      }
    }
  } catch (const YAML::Exception &e) {
    TSDebug(PLUGIN_NAME, "YAML::Exception %s when parsing YAML config file country code deny list for maxmind", e.what());
    return false;
  }

  // Load Denyable IPs
  try {

    // $.deny.ipが定義されていた場合の処理
    // cf. https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html#configuration
    if (denyNode["ip"]) {
      YAML::Node ip = denyNode["ip"];

      // ipが空でない
      if (!ip.IsNull()) {
        // ipがYaml構文として問題ない
        if (ip.IsSequence()) {
          // Do IP Deny processing
          for (auto &&i : ip) {
            IpAddr min, max;
            // IPアドレスに合致するかをチェックする
            ats_ip_range_parse(std::string_view{i.as<std::string>()}, min, max);

            // deny_ip_mapにIPアドレス範囲を登録しておきます。
            deny_ip_map.fill(min, max, nullptr);
            TSDebug(PLUGIN_NAME, "loading ip: valid: %d, fam %d ", min.isValid(), min.family());
          }
        } else {
          TSDebug(PLUGIN_NAME, "Invalid IP deny list yaml");
        }
      }
    }
  } catch (const YAML::Exception &e) {
    TSDebug(PLUGIN_NAME, "YAML::Exception %s when parsing YAML config file ip deny list for maxmind", e.what());
    return false;
  }

  // $.deny.regexが指定された場合
  if (denyNode["regex"]) {
    YAML::Node regex = denyNode["regex"];
    parseregex(regex, false);
  }

#if 0
  std::unordered_map<std::string, bool>::iterator cursor;
  TSDebug(PLUGIN_NAME, "Deny Country List:");
  for (cursor = allow_country.begin(); cursor != allow_country.end(); cursor++) {
    TSDebug(PLUGIN_NAME, "%s:%d", cursor->first.c_str(), cursor->second);
  }
#endif

  return true;
}

// Parse the allow list country codes and IPs
bool
Acl::loadallow(const YAML::Node &allowNode)
{

  // 
  if (!allowNode) {
    TSDebug(PLUGIN_NAME, "No Allow rules set");
    return false;
  }

  if (allowNode.IsNull()) {
    TSDebug(PLUGIN_NAME, "Allow rules are NULL");
    return false;
  }

#if 0
  // Test junk
  for (YAML::const_iterator it = allowNode.begin(); it != allowNode.end(); ++it) {
    const std::string &name    = it->first.as<std::string>();
    YAML::NodeType::value type = it->second.Type();
    TSDebug(PLUGIN_NAME, "name: %s, value: %d", name.c_str(), type);
  }
#endif

  // Load Allowable Country codes
  try {

    // $.allow.countryがあれば
    //  cf. https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html#configuration
    if (allowNode["country"]) {
      YAML::Node country = allowNode["country"];
      
      // 取得したcountryが空でない
      if (!country.IsNull()) {

        // 取得したyaml構文として問題ない
        if (country.IsSequence()) {

          // countryはリスト形式で設定可能なので取得する
          for (auto &&i : country) {

            // allow_countryに登録しておきます
            allow_country.insert_or_assign(i.as<std::string>(), true);
          }

        } else {
          TSDebug(PLUGIN_NAME, "Invalid country code allow list yaml");
        }
      }
    }
  } catch (const YAML::Exception &e) {
    TSDebug(PLUGIN_NAME, "YAML::Exception %s when parsing YAML config file country code allow list for maxmind", e.what());
    return false;
  }

  // Load Allowable IPs
  try {

    // $.allow.ipが定義されていた場合の処理。下記のようにリストになることがあります
    // cf. https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html#configuration
    if (allowNode["ip"]) {
      YAML::Node ip = allowNode["ip"];

      // $.allow.ipの値がnullでなくYamlの記法に従っているか
      if (!ip.IsNull()) {
        // see: https://github.com/jbeder/yaml-cpp/blob/master/docs/Tutorial.md#basic-parsing-and-node-editing
        if (ip.IsSequence()) {

    
          // Do IP Allow processing
          // IPアドレスに対する処理です。IPアドレスは下記設定が示すようにリストになります。forなのはリストを処理しています。
          // cf. https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html#configuration
          for (auto &&i : ip) {
            IpAddr min, max;
            // IPアドレスに合致するかをチェックする
            ats_ip_range_parse(std::string_view{i.as<std::string>()}, min, max);

            // allow_ip_mapに登録します
            allow_ip_map.fill(min, max, nullptr);
            TSDebug(PLUGIN_NAME, "loading ip: valid: %d, fam %d ", min.isValid(), min.family());
          }
        } else {
          TSDebug(PLUGIN_NAME, "Invalid IP allow list yaml");
        }
      }
    }
  } catch (const YAML::Exception &e) {
    TSDebug(PLUGIN_NAME, "YAML::Exception %s when parsing YAML config file ip allow list for maxmind", e.what());
    return false;
  }

  // $.allow.regexが指定された場合
  if (allowNode["regex"]) {
    YAML::Node regex = allowNode["regex"];
    parseregex(regex, true);
  }

#if 0
  std::unordered_map<std::string, bool>::iterator cursor;
  TSDebug(PLUGIN_NAME, "Allow Country List:");
  for (cursor = allow_country.begin(); cursor != allow_country.end(); cursor++) {
    TSDebug(PLUGIN_NAME, "%s:%d", cursor->first.c_str(), cursor->second);
  }
#endif

  return true;
}

void
Acl::parseregex(const YAML::Node &regex, bool allow)
{
  try {
    if (!regex.IsNull()) {
      if (regex.IsSequence()) {
        // Parse each country-regex pair
        for (const auto &i : regex) {
          plugin_regex temp;
          auto temprule = i.as<std::vector<std::string>>();
          temp._regex_s = temprule.back();
          const char *error;
          int erroffset;
          temp._rex = pcre_compile(temp._regex_s.c_str(), 0, &error, &erroffset, nullptr);

          // Compile the regex for this set of countries
          if (nullptr != temp._rex) {
            temp._extra = pcre_study(temp._rex, 0, &error);
            if ((nullptr == temp._extra) && error && (*error != 0)) {
              TSError("[%s] Failed to study regular expression in %s:%s", PLUGIN_NAME, temp._regex_s.c_str(), error);
              return;
            }
          } else {
            TSError("[%s] Failed to compile regular expression in %s: %s", PLUGIN_NAME, temp._regex_s.c_str(), error);
            return;
          }

          for (std::size_t y = 0; y < temprule.size() - 1; y++) {
            TSDebug(PLUGIN_NAME, "Adding regex: %s, for country: %s", temp._regex_s.c_str(), i[y].as<std::string>().c_str());
            if (allow) {
              allow_regex[i[y].as<std::string>()].push_back(temp);
            } else {
              deny_regex[i[y].as<std::string>()].push_back(temp);
            }
          }
        }
      }
    }
  } catch (const YAML::Exception &e) {
    TSDebug(PLUGIN_NAME, "YAML::Exception %s when parsing YAML config file regex allow list for maxmind", e.what());
    return;
  }
}

// maxmind.yaml中の $.maxmind.html を処理する関数
// cf. https://docs.trafficserver.apache.org/admin-guide/plugins/maxmind_acl.en.html#configuration
void
Acl::loadhtml(const YAML::Node &htmlNode)
{
  std::string htmlname, htmlloc;
  std::ifstream f;

  // html フィールドがセットされていない場合にはnullptrとなる。
  if (!htmlNode) {
    TSDebug(PLUGIN_NAME, "No html field set");
    return;
  }

  // html フィールドに何もセットされていない場合
  if (htmlNode.IsNull()) {
    TSDebug(PLUGIN_NAME, "Html field not set");
    return;
  }

  // htmlNodeを文字列でファイル名を取得する
  htmlname = htmlNode.as<std::string>();

  // 先頭が「/」だと絶対パスとなるので、下記では絶対パスか相対パスかを判定している。htmlで指定されたファイルパスを取得する
  if (htmlname[0] != '/') {
    htmlloc = TSConfigDirGet();
    htmlloc += "/";
    htmlloc.append(htmlname);
  } else {
    htmlloc.assign(htmlname);
  }

  // htmlファイルをopenして、読み込みを行います
  f.open(htmlloc, std::ios::in);
  if (f.is_open()) {
    // _htmlについてはmmdb.hで定義されるsend_html()が呼ばれた際にエラーレスポンスとしてセットされます。
    _html.append(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    f.close();
    TSDebug(PLUGIN_NAME, "Loaded HTML from %s", htmlloc.c_str());
  } else {
    TSError("[%s] Unable to open HTML file %s", PLUGIN_NAME, htmlloc.c_str());
  }
}

///////////////////////////////////////////////////////////////////////////////
// Load the maxmind database from the config parameter
bool
Acl::loaddb(const YAML::Node &dbNode)
{
  std::string dbloc, dbname;

  if (!dbNode) {
    TSDebug(PLUGIN_NAME, "No Database field set");
    return false;
  }

  if (dbNode.IsNull()) {
    TSDebug(PLUGIN_NAME, "Database file not set");
    return false;
  }

  // 指定されたdbが絶対パスか相対パスかを判定してdblocを生成する
  dbname = dbNode.as<std::string>();
  if (dbname[0] != '/') {
    dbloc = TSConfigDirGet();
    dbloc += "/";
    dbloc.append(dbname);
  } else {
    dbloc.assign(dbname);
  }

  // Make sure we close any previously opened DBs in case this is a reload
  if (db_loaded) {
    MMDB_close(&_mmdb);
  }

  // MaxMind DB File Format Specification: http://maxmind.github.io/MaxMind-DB/
  // see: https://maxmind.github.io/libmaxminddb/
  int status = MMDB_open(dbloc.c_str(), MMDB_MODE_MMAP, &_mmdb);
  if (MMDB_SUCCESS != status) {
    TSDebug(PLUGIN_NAME, "Can't open DB %s - %s", dbloc.c_str(), MMDB_strerror(status));
    return false;
  }

  db_loaded = true;
  TSDebug(PLUGIN_NAME, "Initialized MMDB with %s", dbloc.c_str());
  return true;
}

// maxmind_aclのDoRemapからリクエスト毎に呼び出される
bool
Acl::eval(TSRemapRequestInfo *rri, TSHttpTxn txnp)
{

  bool ret = default_allow;
  int mmdb_error;

  // リクエストからsockaddr構造体を取得する
  auto sockaddr = TSHttpTxnClientAddrGet(txnp);

  // sockaddrが取得できなければfalseを戻す
  if (sockaddr == nullptr) {
    TSDebug(PLUGIN_NAME, "Err during TsHttpClientAddrGet, nullptr returned");
    ret = false;
    return ret;
  }

  // sockaddr構造体を引き渡してIPアドレスが存在するかをチェックする
  MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&_mmdb, sockaddr, &mmdb_error);

  // IPアドレスからエントリが見当たらなければfalseを戻す
  if (MMDB_SUCCESS != mmdb_error) {
    TSDebug(PLUGIN_NAME, "Error during sockaddr lookup: %s", MMDB_strerror(mmdb_error));
    ret = false;
    return ret;
  }

  MMDB_entry_data_list_s *entry_data_list = nullptr;

  // IPアドレスのエントリが存在したら
  if (result.found_entry) {

    // IPアドレスに紐づくエントリリストをentry_data_listに取得する
    int status = MMDB_get_entry_data_list(&result.entry, &entry_data_list);
    if (MMDB_SUCCESS != status) {
      TSDebug(PLUGIN_NAME, "Error looking up entry data: %s", MMDB_strerror(status));
      ret = false;
      return ret;
    }

    // IPアドレスに紐づくエントリリストが取得できたら
    if (nullptr != entry_data_list) {
      // This is useful to be able to dump out a full record of a
      // mmdb entry for debug. Enabling can help if you want to figure
      // out how to add new fields
#if 0
      // Block of test stuff to dump output, remove later
      char buffer[4096];
      FILE *temp = fmemopen(&buffer[0], 4096, "wb+");
      int status = MMDB_dump_entry_data_list(temp, entry_data_list, 0);
      fflush(temp);
      TSDebug(PLUGIN_NAME, "Entry: %s, status: %s, type: %d", buffer, MMDB_strerror(status), entry_data_list->entry_data.type);
#endif

      MMDB_entry_data_s entry_data;
      int path_len     = 0;
      const char *path = nullptr;

      // allow_regexまたはdeny_regexが設定されていたらURLのPath情報を取得する
      if (!allow_regex.empty() || !deny_regex.empty()) {
        path = TSUrlPathGet(rri->requestBufp, rri->requestUrl, &path_len);
      }

      // Test for country code
      // mmdbから判定するためにはallow_country, allow_regex, deny_regexのいずれかが設定されていなければらない。
      if (!allow_country.empty() || !allow_regex.empty() || !deny_regex.empty()) {

        // 「mmdblookup --file /usr/share/GeoIP/GeoLite2-City.mmdb --ip 49.225.14.11」のサンプル
        //  データ構造については下記を参考のこと
        //   cf. https://echorand.me/posts/nginx-geoip2-mmdblookup/
        //  「$.city.country.iso_code」によって2文字のカントリーコードを取得することができる。 (cityは指定しなくてもよいらしい)
        //
        // 以下でentry_dataには「JP」などのISO 3166-1の規格の国コードが返ってきます。
        status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

        // iso_codeが取得できたかどうかを判定する
        if (MMDB_SUCCESS != status) {
          TSDebug(PLUGIN_NAME, "err on get country code value: %s", MMDB_strerror(status));
          return false;
        }

        // iso_codeが取得できたから、そのiso_codeで判定処理を行う
        if (entry_data.has_data) {
          ret = eval_country(&entry_data, path, path_len);
        }

      } else {
        // Country map is empty as well as regexes, use our default rejection
        // default_allowはデフォルトでfalseとなっています(名前からtrueと勘違いしないように)
        ret = default_allow;
      }
    }
  } else {
    // IPアドレスに紐づくエントリリストが取得できない場合
    TSDebug(PLUGIN_NAME, "No Country Code entry for this IP was found");
    ret = false;
  }

  // Test for allowable IPs based on our lists
  // クライアントリクエストのsockaddrをeval_ipに引き渡して、「@plugin=maxmind_acl.so @pparam=maxmind.yaml」で引き渡されたmaxmind.yaml中の$.allow.ip, $.deny.iopと照合を行ない、ALLOWかDENYかを判定する
  //
  // 注意点として$.allow.ipも$.deny.ipも指定されていない場合には、eval_ipの戻り値はUNKNOWN_IPとなります。この場合、これより前のロジックである国名コードのフィルタリング判定結果を応答することになります。
  switch (eval_ip(TSHttpTxnClientAddrGet(txnp))) {
  case ALLOW_IP:
    TSDebug(PLUGIN_NAME, "Saw explicit allow of this IP");
    ret = true;
    break;
  case DENY_IP:
    TSDebug(PLUGIN_NAME, "Saw explicit deny of this IP");
    ret = false;
    break;
  case UNKNOWN_IP:
    TSDebug(PLUGIN_NAME, "Unknown IP, following default from ruleset: %d", ret);
    break;
  default:
    TSDebug(PLUGIN_NAME, "Unknown client addr ip state, should not get here");
    ret = false;
    break;
  }

  if (nullptr != entry_data_list) {
    MMDB_free_entry_data_list(entry_data_list);
  }

  return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Returns true if entry data contains an
// allowable country code from our map.
// False otherwise
//
// entry_dataにはIPアドレス(sockaddr)からmmdbを探索した際に取得した国名コードの情報(構造体)が設定されます。
// そのPathに対して、許可された国であればtrue、拒否された国であればfalseを返す。pathやpath_lenへの指定は任意となっている。
bool
Acl::eval_country(MMDB_entry_data_s *entry_data, const char *path, int path_len)
{

  bool ret     = false;
  bool allow   = default_allow;
  char *output = nullptr;

  // We need to null terminate the iso_code ourselves, they are unterminated in the DBs

  // outputには「JP」のように国名コードが入るためのメモリ確保が行わます。
  output = static_cast<char *>(malloc((sizeof(char) * (entry_data->data_size + 1))));
  strncpy(output, entry_data->utf8_string, entry_data->data_size);
  output[entry_data->data_size] = '\0';

  TSDebug(PLUGIN_NAME, "This IP Country Code: %s", output);

  // allow_countryへの登録はAcl::loaddenyやAcl::loadallow関数中のallow_country.insert_or_assignで設定されています。
  auto exists = allow_country.count(output);

  // If the country exists in our map then set its allow value here
  // Otherwise we will use our default value
  if (exists) {
    // outputにはIPアドレスからの国名コード(JP等)が入るので、allow_country["JP"]に相当するような値がallowに入ります。
    allow = allow_country[output];
  }

  // allowが存在すれば国名コードが見つかったとして許可リストに存在します
  if (allow) {
    TSDebug(PLUGIN_NAME, "Found country code of IP in allow list or allow by default");
    ret = true;
  }

  // pathやpath_lenが指定された場合(allow_regexやdeny_regexが空でない場合にのみこの遷移に入ります)
  if (nullptr != path && 0 != path_len) {

    // allow_regexに関する処理
    if (!allow_regex[output].empty()) {
      for (auto &i : allow_regex[output]) {

        // pcre_exec
        //    see: https://www.pcre.org/original/doc/html/pcre_exec.html
        if (PCRE_ERROR_NOMATCH != pcre_exec(i._rex, i._extra, path, path_len, 0, PCRE_NOTEMPTY, nullptr, 0)) {

          // 許可の正規表現リストにマッチした場合にはtrueを返す
          TSDebug(PLUGIN_NAME, "Got a regex allow hit on regex: %s, country: %s", i._regex_s.c_str(), output);
          ret = true;
        }

      }
    }

    // deny_regexに関する処理
    if (!deny_regex[output].empty()) {
      for (auto &i : deny_regex[output]) {

        // pcre_exec
        //    see: https://www.pcre.org/original/doc/html/pcre_exec.html
        if (PCRE_ERROR_NOMATCH != pcre_exec(i._rex, i._extra, path, path_len, 0, PCRE_NOTEMPTY, nullptr, 0)) {

          // 拒否の正規表現リストにマッチした場合にはfalseを返す
          TSDebug(PLUGIN_NAME, "Got a regex deny hit on regex: %s, country: %s", i._regex_s.c_str(), output);
          ret = false;
        }

      }
    }
  }

  free(output);
  return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Returns enum based on current client:
// ALLOW_IP if IP is in the allow list
// DENY_IP if IP is in the deny list
// UNKNOWN_IP if it does not exist in either, this is then used to determine
//  action based on the default allow action

// 引数はクライアントのsockaddrが格納されます
ipstate
Acl::eval_ip(const sockaddr *sock) const
{


// デバッグ用途などで使われる。下記の0を1に変更するだけでデバッグとして出力されるようになる
#if 0
  for (auto &spot : allow_ip_map) {
    char text[INET6_ADDRSTRLEN];
    TSDebug(PLUGIN_NAME, "IP: %s", ats_ip_ntop(spot.min(), text, sizeof text));
    if (0 != ats_ip_addr_cmp(spot.min(), spot.max())) {
      TSDebug(PLUGIN_NAME, "stuff: %s", ats_ip_ntop(spot.max(), text, sizeof text));
    }
  }
#endif

  // 許可リストに含まれている場合
  // Acl::loadallowのallow_ip_map.fillでallow_ip_mapは設定されます
  if (allow_ip_map.contains(sock, nullptr)) {
    // Allow map has this ip, we know we want to allow it
    return ALLOW_IP;
  }

  // 拒否リストに含まれている場合
  // Acl::loaddenyのdeny_ip_map.fillでdeny_ip_mapは設定されます
  if (deny_ip_map.contains(sock, nullptr)) {
    // Deny map has this ip, explicitly deny
    return DENY_IP;
  }

  return UNKNOWN_IP;
}
