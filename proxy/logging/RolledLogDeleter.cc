/** @file

  This file implements the rolled log deletion.

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

#include <climits>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "RolledLogDeleter.h"
#include "LogUtils.h"
#include "tscore/ts_file.h"
#include "tscpp/util/TextView.h"

namespace fs = ts::file;

LogDeletingInfo::LogDeletingInfo(const char *_logname, int _min_count)
  : logname(_logname),
    /**
     * A min_count of zero indicates a request to try to keep all rotated logs
     * around. By setting min_count to INT_MAX in these cases, we make the rolled
     * log deletion priority small.
     *
     * @note This cannot have a zero value because it is used as the denominator
     * in a division operation when calculating the log deletion preference.
     */
    min_count((_min_count > 0) ? _min_count : INT_MAX)
{
}

LogDeletingInfo::LogDeletingInfo(std::string_view _logname, int _min_count)
  : logname(_logname),
    /**
     * A min_count of zero indicates a request to try to keep all rotated logs
     * around. By setting min_count to INT_MAX in these cases, we make the rolled
     * log deletion priority small.
     *
     * @note This cannot have a zero value because it is used as the denominator
     * in a division operation when calculating the log deletion preference.
     */
    min_count((_min_count > 0) ? _min_count : INT_MAX)
{
}

void
RolledLogDeleter::register_log_type_for_deletion(std::string_view log_type, int rolling_min_count)
{
  if (deleting_info.find(log_type) != deleting_info.end()) {
    // Already registered.
    return;
  }

  // LogDeletingInfoのstd::uniqueポインタを生成する
  auto deletingInfo     = std::make_unique<LogDeletingInfo>(log_type, rolling_min_count);

  // std::uniqueのget()によりポインタ情報を取得する
  auto *deletingInfoPtr = deletingInfo.get();

  // std::moveによりdeletingInfoの所有権が移動しているので、std::uniqueポインタのdeletingInfoはこの関数スコープを抜けても自動的にメモリ解放されない仕組みになっている
  // deletingInfoは所有権を渡すので、deletingInfoはnullポインタとなります
  deletingInfoList.push_back(std::move(deletingInfo));

  // deleting_infoにはLogDeletingInfoのunique_ptrを格納する。
  deleting_info.insert(deletingInfoPtr);

  candidates_require_sorting = true;
}

bool
RolledLogDeleter::consider_for_candidacy(std::string_view log_path, int64_t file_size, time_t modification_time)
{
  const fs::path rolled_log_file = fs::filename(log_path);

  // findの引数にはローリングされたファイル名から元のファイル名へと変換された文字列になる
  auto iter                      = deleting_info.find(LogUtils::get_unrolled_filename(rolled_log_file.view()));

  // 対象となるファイルがdeleting_infoに存在しない場合にはfalseを応答する
  if (iter == deleting_info.end()) {
    return false;
  }
  auto &candidates = iter->candidates;

  // std::make_uniqueを使用すると、メモリリークを防ぐための安全な方法でstd::unique_ptrを生成することができます
  // std::make_uniqueは動的メモリ割り当てとその解放を一度に行うため、メモリ管理を簡略化します
  // 通常、new演算子を利用してstd::uniqueを生成する場合にメモリ解放忘れの可能性がありますが、これを防ぐことができます。
  candidates.push_back(std::make_unique<LogDeleteCandidate>(log_path, file_size, modification_time));
  ++num_candidates;
  candidates_require_sorting = true;
  return true;
}

// ソートを行う
void
RolledLogDeleter::sort_candidates()
{

  deleting_info.apply([](LogDeletingInfo &info) {
    std::sort(info.candidates.begin(), info.candidates.end(),
              [](std::unique_ptr<LogDeleteCandidate> const &a, std::unique_ptr<LogDeleteCandidate> const &b) {
                // mtimeの降順にソートされます
                return a->mtime > b->mtime;
              });
  });

  // 呼び出し元(RolledLogDeleter::take_next_candidate_to_delete())にて、candidates_require_sortingがtrueでこの関数に入って処理が実行されているので、falseに戻しておく
  candidates_require_sorting = false;
}

std::unique_ptr<LogDeleteCandidate>
RolledLogDeleter::take_next_candidate_to_delete()
{

  if (!has_candidates()) {
    return nullptr;
  }

  if (candidates_require_sorting) {
    sort_candidates();
  }

  // Select the highest priority type (diags.log, traffic.out, etc.) from which
  // to select a candidate.
  auto target_type =
    std::max_element(deleting_info.begin(), deleting_info.end(), [](LogDeletingInfo const &A, LogDeletingInfo const &B) {
      return static_cast<double>(A.candidates.size()) / A.min_count < static_cast<double>(B.candidates.size()) / B.min_count;
    });

  auto &candidates = target_type->candidates;
  if (candidates.empty()) {
    return nullptr;
  }

  // Return the highest priority candidate among the candidates of that type.
  // std::moveで末尾の要素の所有権を移動した後に、末尾をpop_backする
  auto victim = std::move(candidates.back());
  candidates.pop_back();
  --num_candidates;

  return victim;
}

bool
RolledLogDeleter::has_candidates() const
{
  // get_candidate_count()が0でなかったら削除ログ候補があるものとしてtrueを返す
  return get_candidate_count() != 0;
}

size_t
RolledLogDeleter::get_candidate_count() const
{
  return num_candidates;
}

void
RolledLogDeleter::clear_candidates()
{
  deleting_info.apply([](LogDeletingInfo &info) { info.clear(); });
  num_candidates = 0;
}
