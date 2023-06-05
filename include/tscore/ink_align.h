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

//-*-c++-*-
#pragma once

#include "tscore/ink_time.h"

union Alias32 {
  uint8_t byte[4];
  int32_t i32;
  uint32_t u32;
};

union Alias64 {
  uint8_t byte[8];
  int32_t i32[2];
  uint32_t u32[2];
  int64_t i64;
  uint64_t u64;
  ink_time_t i_time;
};

/**
 * Alignment macros
 */

#define INK_MIN_ALIGN 8

/* INK_ALIGN() is only to be used to align on a power of 2 boundary */
// 与えられたサイズを指定されたバウンダリ（境界）に合わせるための演算を行います。具体的には、サイズをバウンダリで割り、切り上げた後に再びバウンダリで乗算します。

// (例1) INK_ALIGNを求める際に(ptrdiff_t)pointerの値は0x1007, alignmentの値は8として計算すると
// 0x1007 + 7 = 0x100E
// ~(7) = 0xFFFFFFF8
// 0x100E & 0xFFFFFFF8 = 0x1008

// (例2) INK_ALIGNを求める際に(ptrdiff_t)pointerの値は0x1008, alignmentの値は8として計算すると
// 0x1008 + 7 = 0x100F
// ~(7) = 0xFFFFFFF8
// 0x100F & 0xFFFFFFF8 = 0x1008

// (例3) INK_ALIGNを求める際に(ptrdiff_t)pointerの値は0x1009, alignmentの値は8として計算すると
// 0x1009 + 7 = 0x1010
// ~(7) = 0xFFFFFFF8
// 0x1010 & 0xFFFFFFF8 = 0x1010

// (例4) INK_ALIGNを求める際に(ptrdiff_t)pointerの値は0x1018, alignmentの値は8として計算すると
// 0x1011 + 7 = 0x1018
// ~(7) = 0xFFFFFFF8
// 0x1018 & 0xFFFFFFF8 = 0x1018

// つまり例1〜例4をみると 0x1008(=4104), 0x1010(=4112), 0x1018(=4120) と10進数にすると8byteおきの値になっていることがわかります。

#define INK_ALIGN(size, boundary) (((size) + ((boundary)-1)) & ~((boundary)-1))

/** Default alignment */
#define INK_ALIGN_DEFAULT(size) INK_ALIGN(size, INK_MIN_ALIGN)

//
// Move a pointer forward until it meets the alignment width.
//
// align_pointer_forward関数を使用してアライメントを合わせます。
static inline void *
align_pointer_forward(const void *pointer_, size_t alignment)
{
  char *pointer = (char *)pointer_;
  //
  // Round up alignment..
  //
  pointer = (char *)INK_ALIGN((ptrdiff_t)pointer, alignment);

  return (void *)pointer;
}

//
// Move a pointer forward until it meets the alignment width specified,
// and zero out the contents of the space you're skipping over.
//
static inline void *
align_pointer_forward_and_zero(const void *pointer_, size_t alignment)
{
  char *pointer = (char *)pointer_;
  char *aligned = (char *)INK_ALIGN((ptrdiff_t)pointer, alignment);
  //
  // Fill the skippings..
  //
  while (pointer < aligned) {
    *pointer = 0;
    pointer++;
  }

  return (void *)aligned;
}

//
// We include two signatures for the same function to avoid error
// messages concerning coercion between void* and unsigned long.
// We could handle this using casts, but that's more prone to
// errors during porting.
//
