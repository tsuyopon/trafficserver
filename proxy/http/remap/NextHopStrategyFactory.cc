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

#include <yaml-cpp/yaml.h>

#include <fstream>
#include <cstring>

#include "NextHopStrategyFactory.h"
#include "NextHopConsistentHash.h"
#include "NextHopRoundRobin.h"
#include <YamlCfg.h>

NextHopStrategyFactory::NextHopStrategyFactory(const char *file) : fn(file)
{
  YAML::Node config;
  YAML::Node strategies;
  std::stringstream doc;
  std::unordered_set<std::string> include_once;

  // strategy policies.
  constexpr std::string_view consistent_hash = "consistent_hash";
  constexpr std::string_view first_live      = "first_live";
  constexpr std::string_view rr_strict       = "rr_strict";
  constexpr std::string_view rr_ip           = "rr_ip";
  constexpr std::string_view latched         = "latched";

  bool error_loading   = false;
  strategies_loaded    = true;
  const char *basename = std::string_view(fn).substr(fn.find_last_of('/') + 1).data();

  NH_Note("%s loading ...", basename);

  struct stat sbuf;
  if (stat(fn.c_str(), &sbuf) == -1 && errno == ENOENT) {
    // missing config file is an acceptable runtime state
    strategies_loaded = false;
    NH_Note("%s doesn't exist", fn.c_str());
    goto done;
  }

  // load the strategies yaml config file.
  try {
    loadConfigFile(fn.c_str(), doc, include_once);

    config = YAML::Load(doc);
    if (config.IsNull()) {
      NH_Note("No NextHop strategy configs were loaded.");
      strategies_loaded = false;
    } else {
      strategies = config["strategies"];
      if (strategies.Type() != YAML::NodeType::Sequence) {
        NH_Error("malformed %s file, expected a 'strategies' sequence", basename);
        strategies_loaded = false;
        error_loading     = true;
      }
    }

    // loop through the strategies document.
    for (auto &&strategie : strategies) {
      ts::Yaml::Map strategy{strategie};
      auto name   = strategy["strategy"].as<std::string>();
      auto policy = strategy["policy"];
      if (!policy) {
        NH_Error("No policy is defined for the strategy named '%s', this strategy will be ignored.", name.c_str());
        continue;
      }
      const auto &policy_value = policy.Scalar();
      NHPolicyType policy_type = NH_UNDEFINED;

      // consistent_hash, first_live, rr_strict, rr_ip, latchedなどの定義は下記ドキュメントを参照のこと
      // cf. https://docs.trafficserver.apache.org/en/9.1.x/admin-guide/files/strategies.yaml.en.html#strategies-definitions
      if (policy_value == consistent_hash) {
        policy_type = NH_CONSISTENT_HASH;
      } else if (policy_value == first_live) {
        policy_type = NH_FIRST_LIVE;
      } else if (policy_value == rr_strict) {
        policy_type = NH_RR_STRICT;
      } else if (policy_value == rr_ip) {
        policy_type = NH_RR_IP;
      } else if (policy_value == latched) {
        policy_type = NH_RR_LATCHED;
      }
      if (policy_type == NH_UNDEFINED) {
        NH_Error("Invalid policy '%s' for the strategy named '%s', this strategy will be ignored.", policy_value.c_str(),
                 name.c_str());
      } else {
        createStrategy(name, policy_type, strategy);
        strategy.done();
      }
    }
  } catch (std::exception &ex) {
    NH_Error("%s", ex.what());
    strategies_loaded = false;
    error_loading     = true;
  }

done:
  if (!error_loading) {
    NH_Note("%s finished loading", basename);
  } else {
    Error("%s failed to load", basename);
  }
}

NextHopStrategyFactory::~NextHopStrategyFactory()
{
  NH_Debug(NH_DEBUG_TAG, "destroying NextHopStrategyFactory");
}

void
NextHopStrategyFactory::createStrategy(const std::string &name, const NHPolicyType policy_type, ts::Yaml::Map &node)
{
  std::shared_ptr<NextHopSelectionStrategy> strat;
  std::shared_ptr<NextHopRoundRobin> strat_rr;
  std::shared_ptr<NextHopConsistentHash> strat_chash;

  strat = strategyInstance(name.c_str());
  if (strat != nullptr) {
    NH_Note("A strategy named '%s' has already been loaded and another will not be created.", name.data());
    node.bad();
    return;
  }

  try {

    // consistent_hash, first_live, rr_strict, rr_ip, latchedなどの定義は下記ドキュメントを参照のこと
    // cf. https://docs.trafficserver.apache.org/en/9.1.x/admin-guide/files/strategies.yaml.en.html#strategies-definitions
    switch (policy_type) {
    case NH_FIRST_LIVE:
    case NH_RR_STRICT:
    case NH_RR_IP:
    case NH_RR_LATCHED:
      strat_rr = std::make_shared<NextHopRoundRobin>(name, policy_type, node);
      _strategies.emplace(std::make_pair(std::string(name), strat_rr));
      break;
    case NH_CONSISTENT_HASH:
      strat_chash = std::make_shared<NextHopConsistentHash>(name, policy_type, node);
      _strategies.emplace(std::make_pair(std::string(name), strat_chash));
      break;
    default: // handles P_UNDEFINED, no strategy is added
      break;
    };
  } catch (std::exception &ex) {
    strat.reset();
  }
}

std::shared_ptr<NextHopSelectionStrategy>
NextHopStrategyFactory::strategyInstance(const char *name)
{
  std::shared_ptr<NextHopSelectionStrategy> ps_strategy;

  if (!strategies_loaded) {
    // strategies.yamlが存在しなかったり、yamlとして値を取得できなかったり、フォーマットが改ざんされている場合にはこの遷移に入ります
    NH_Error("no strategy configurations were defined, see definitions in '%s' file", fn.c_str());
    return nullptr;
  } else {
    auto it = _strategies.find(name);
    if (it == _strategies.end()) {
      // NH_Error("no strategy found for name: %s", name);
      return nullptr;
    } else {
      ps_strategy           = it->second;
      ps_strategy->distance = std::distance(_strategies.begin(), it);
    }
  }

  return ps_strategy;
}

/*
 * loads the contents of a file into a std::stringstream document.  If the file has a '#include file'
 * directive, that 'file' is read into the document beginning at the point where the
 * '#include' was found. This allows the 'strategy' and 'hosts' yaml files to be separate.  The
 * 'strategy' yaml file would then normally have the '#include hosts.yml' in it's beginning.
 */
// strategies.yamlを読み込む
// なお、この関数でstrategies.yamlの中から「#include <filename>」と指定された場合にも読み込まれる再帰利用されることがあります。filenameはディレクトリを指定することもできるようです
//
// 下記の関数のfileName変数はファイル名だけでなく、ディレクトリの場合の処理もあるので変数名から勘違いしないように注意すること
void
NextHopStrategyFactory::loadConfigFile(const std::string &fileName, std::stringstream &doc,
                                       std::unordered_set<std::string> &include_once)
{

  const char *sep = " \t";
  char *tok, *last;
  struct stat buf;
  std::string line;

  // statシステムコールで指定されたfilenNameの情報が取得できない場合
  if (stat(fileName.c_str(), &buf) == -1) {
    std::string err_msg = strerror(errno);
    throw std::invalid_argument("Unable to stat '" + fileName + "': " + err_msg);
  }

  /*
   * (重要) fileNameはファイル名だけでなく、ディレクトリの場合の処理もあるので変数名から勘違いしないように注意すること
   */

  // if fileName is a directory, concatenate all '.yaml' files alphanumerically
  // into a single document stream.  No #include is supported.
  // 指定されたfileNameがディレクトリの場合にはアルファベット順で１つのファイルとして読み込む。なお、#include記法はこの場合にはサポートされない
  if (S_ISDIR(buf.st_mode)) {

    DIR *dir               = nullptr;
    struct dirent *dir_ent = nullptr;
    std::vector<std::string_view> files;

    NH_Note("loading strategy YAML files from the directory %s", fileName.c_str());

    // fileNameはディレクトリなので、ディレクトリをopenします。
    if ((dir = opendir(fileName.c_str())) == nullptr) {
      // fileNameで指定されたディレクトリのopendirに失敗した場合
      std::string err_msg = strerror(errno);
      throw std::invalid_argument("Unable to open the directory '" + fileName + "': " + err_msg);
    } else {

      // fileNameで指定されたディレクトリのopendirに成功した場合

      // ディレクトリ中のファイルを1つ１つ抽出してfilesにpush_backする
      while ((dir_ent = readdir(dir)) != nullptr) {
        // filename should be greater that 6 characters to have a '.yaml' suffix.
        // 拡張子「.yaml」だけで5文字なので、6文字未満(=5文字)にマッチしなかったらcontinueする
        if (strlen(dir_ent->d_name) < 6) {
          continue;
        }

        // 末尾が「.yaml」で終わっているファイル名を見つけて、filesにpush_backする
        std::string_view sv = dir_ent->d_name;
        if (sv.find(".yaml", sv.size() - 5) == sv.size() - 5) {
          files.push_back(sv);
        }
      }

      // sort the files alphanumerically
      // filesにpush_backしたファイルを、アルファベット順に並べます。
      std::sort(files.begin(), files.end(),
                [](const std::string_view lhs, const std::string_view rhs) { return lhs.compare(rhs) < 0; });

      // filesに対するイテレーション操作を行う
      for (auto &i : files) {

        // 変数名は紛らわしいがfileNameはディレクトリを表す
        std::ifstream file(fileName + "/" + i.data());

        // ファイルをopenする
        if (file.is_open()) {
          // ファイルを行毎に取得する
          while (std::getline(file, line)) {
            // 関数に指定されたfileNameがディレクトリの場合には「#include」記法をサポートしないので、そのままコメント扱いとしてcontinueする
            if (line[0] == '#') {
              // continue;
            }
            // 読み込んだファイル情報を行毎に結合する
            doc << line << "\n";
          }
          file.close();
        } else {
          throw std::invalid_argument("Unable to open and read '" + fileName + "/" + i.data() + "'");
        }
      }
    }

    closedir(dir);

  } else {

    // ファイルがopenできた場合の処理
    std::ifstream file(fileName);
    if (file.is_open()) {

      // ファイルを行毎に処理する
      while (std::getline(file, line)) {

        // 行が「#」で始まる場合の処理
        if (line[0] == '#') {
          tok = strtok_r(const_cast<char *>(line.c_str()), sep, &last);

          // strategies.yamlには「#include <filename>」として別のファイルを参照する仕組みになっています
          // see: https://docs.trafficserver.apache.org/admin-guide/files/strategies.yaml.en.html

          // 「#include」が存在する場合
          if (tok != nullptr && strcmp(tok, "#include") == 0) {
            std::string f = strtok_r(nullptr, sep, &last);
            if (include_once.find(f) == include_once.end()) {
              include_once.insert(f);
              // try to load included file.
              try {
                // strategies.yamlに記載された「#include <filename>」のfilenameを読み込む
                loadConfigFile(f, doc, include_once);
              } catch (std::exception &ex) {
                throw std::invalid_argument("Unable to open included file '" + f + "' from '" + fileName + "'");
              }
            }
          }
        } else {
          // 読み込んだファイル情報を行毎に結合する
          doc << line << "\n";
        }
      }
      file.close();
    } else {
      throw std::invalid_argument("Unable to open and read '" + fileName + "'");
    }
  }
}
