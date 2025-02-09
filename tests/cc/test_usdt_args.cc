/*
 * Copyright (c) 2016 GitHub, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <iostream>
#include <string>

#include "catch.hpp"
#include "usdt.h"

using std::experimental::optional;
using std::experimental::nullopt;

static void verify_register(USDT::ArgumentParser &parser, int arg_size,
                            long long constant) {
  USDT::Argument arg;
  REQUIRE(parser.parse(&arg));
  REQUIRE(arg.arg_size() == arg_size);

  REQUIRE(arg.constant());
  REQUIRE(arg.constant() == constant);
}

static void verify_register(USDT::ArgumentParser &parser, int arg_size,
                            const std::string &regname,
                            optional<int> deref_offset = nullopt,
                            optional<std::string> deref_ident = nullopt,
                            optional<std::string> index_regname = nullopt,
                            optional<int> scale = nullopt) {
  USDT::Argument arg;
  REQUIRE(parser.parse(&arg));
  REQUIRE(arg.arg_size() == arg_size);

  REQUIRE(arg.base_register_name());
  REQUIRE(arg.base_register_name() == regname);

  REQUIRE(arg.deref_offset() == deref_offset);
  REQUIRE(arg.deref_ident() == deref_ident);

  REQUIRE(arg.index_register_name() == index_regname);
  REQUIRE(arg.scale() == scale);
}

/* supported arches only */
#if defined(__aarch64__) || defined(__loongarch64) || \
    defined(__powerpc64__) || defined(__s390x__) || \
    defined(__x86_64__) || defined(__riscv)

TEST_CASE("test usdt argument parsing", "[usdt]") {
  SECTION("parse failure") {
#if defined(__aarch64__)
    USDT::ArgumentParser_aarch64 parser("4@[x32,200]");
#elif defined(__loongarch64)
    USDT::ArgumentParser_loongarch64 parser("4@[$r32,200]");
#elif defined(__powerpc64__)
    USDT::ArgumentParser_powerpc64 parser("4@-12(42)");
#elif defined(__s390x__)
    USDT::ArgumentParser_s390x parser("4@-12(%r42)");
#elif defined(__riscv)
    USDT::ArgumentParser_riscv64 parser("4@20(s35)");
#elif defined(__x86_64__)
    USDT::ArgumentParser_x64 parser("4@i%ra+1r");
#endif
    USDT::Argument arg;
    REQUIRE(!parser.parse(&arg));
    int i;
    for (i = 0; i < 10 && !parser.done(); ++i) {
      parser.parse(&arg);
    }
    // Make sure we reach termination
    REQUIRE(i < 10);
  }
  SECTION("argument examples from the Python implementation") {
#if defined(__aarch64__)
    USDT::ArgumentParser_aarch64 parser(
        "-1@x0 4@5 8@[x12] -4@[x30,-40] -4@[x31,-40] 8@[sp, 120]");
    verify_register(parser, -1, "regs[0]");
    verify_register(parser, 4, 5);
    verify_register(parser, 8, "regs[12]", 0);
    verify_register(parser, -4, "regs[30]", -40);
    verify_register(parser, -4, "sp", -40);
    verify_register(parser, 8, "sp", 120);
#elif defined(__loongarch64)
    USDT::ArgumentParser_loongarch64 parser(
	"-1@$r0 4@5 8@[$r12] -4@[$r30,-40] -4@[$r3,-40] 8@[sp, 120]");
    verify_register(parser, -1, "regs[0]");
    verify_register(parser, 4, 5);
    verify_register(parser, 8, "regs[12]", 0);
    verify_register(parser, -4, "regs[30]", -40);
    verify_register(parser, -4, "sp", -40);
    verify_register(parser, 8, "sp", 120);
#elif defined(__powerpc64__)
    USDT::ArgumentParser_powerpc64 parser(
        "-4@0 8@%r0 8@i0 4@0(%r0) -2@0(0) "
        "1@0 -2@%r3 -8@i9 -1@0(%r4) -4@16(6) "
        "2@7 4@%r11 4@i-67 8@-16(%r17) 1@-52(11) "
        "-8@13 -8@%r25 2@i-11 -2@14(%r26) -8@-32(24) "
        "4@29 2@%r17 -8@i-693 -1@-23(%r31) 4@28(30) "
        "-2@31 -4@%r30 2@i1097 4@108(%r30) -2@-4(31)");

    verify_register(parser, -4, "gpr[0]");
    verify_register(parser, 8, "gpr[0]");
    verify_register(parser, 8, 0);
    verify_register(parser, 4, "gpr[0]", 0);
    verify_register(parser, -2, "gpr[0]", 0);

    verify_register(parser, 1, "gpr[0]");
    verify_register(parser, -2, "gpr[3]");
    verify_register(parser, -8, 9);
    verify_register(parser, -1, "gpr[4]", 0);
    verify_register(parser, -4, "gpr[6]", 16);

    verify_register(parser, 2, "gpr[7]");
    verify_register(parser, 4, "gpr[11]");
    verify_register(parser, 4, -67);
    verify_register(parser, 8, "gpr[17]", -16);
    verify_register(parser, 1, "gpr[11]", -52);

    verify_register(parser, -8, "gpr[13]");
    verify_register(parser, -8, "gpr[25]");
    verify_register(parser, 2, -11);
    verify_register(parser, -2, "gpr[26]", 14);
    verify_register(parser, -8, "gpr[24]", -32);

    verify_register(parser, 4, "gpr[29]");
    verify_register(parser, 2, "gpr[17]");
    verify_register(parser, -8, -693);
    verify_register(parser, -1, "gpr[31]", -23);
    verify_register(parser, 4, "gpr[30]", 28);

    verify_register(parser, -2, "gpr[31]");
    verify_register(parser, -4, "gpr[30]");
    verify_register(parser, 2, 1097);
    verify_register(parser, 4, "gpr[30]", 108);
    verify_register(parser, -2, "gpr[31]", -4);
#elif defined(__s390x__)
    USDT::ArgumentParser_s390x parser(
        "-4@%r0 8@%r0 8@0 4@0(%r0) -2@0(%r0) "
        "1@%r0 -2@%r3 -8@9 -1@0(%r4) -4@16(%r6) "
        "2@%r7 4@%r11 4@-67 8@-16(%r15) 1@-52(%r11) "
        "-8@%r4 -8@%r14 2@-11 -2@14(%r13) -8@-32(%r12) "
        "4@%r5 2@%r11 -8@-693 -1@-23(%r10) 4@28(%r9) "
        "-2@%r3 -4@%r8 2@1097 4@108(%r7) -2@-4(%r6)");

    verify_register(parser, -4, "gprs[0]");
    verify_register(parser, 8, "gprs[0]");
    verify_register(parser, 8, 0);
    verify_register(parser, 4, "gprs[0]", 0);
    verify_register(parser, -2, "gprs[0]", 0);

    verify_register(parser, 1, "gprs[0]");
    verify_register(parser, -2, "gprs[3]");
    verify_register(parser, -8, 9);
    verify_register(parser, -1, "gprs[4]", 0);
    verify_register(parser, -4, "gprs[6]", 16);

    verify_register(parser, 2, "gprs[7]");
    verify_register(parser, 4, "gprs[11]");
    verify_register(parser, 4, -67);
    verify_register(parser, 8, "gprs[15]", -16);
    verify_register(parser, 1, "gprs[11]", -52);

    verify_register(parser, -8, "gprs[4]");
    verify_register(parser, -8, "gprs[14]");
    verify_register(parser, 2, -11);
    verify_register(parser, -2, "gprs[13]", 14);
    verify_register(parser, -8, "gprs[12]", -32);

    verify_register(parser, 4, "gprs[5]");
    verify_register(parser, 2, "gprs[11]");
    verify_register(parser, -8, -693);
    verify_register(parser, -1, "gprs[10]", -23);
    verify_register(parser, 4, "gprs[9]", 28);

    verify_register(parser, -2, "gprs[3]");
    verify_register(parser, -4, "gprs[8]");
    verify_register(parser, 2, 1097);
    verify_register(parser, 4, "gprs[7]", 108);
    verify_register(parser, -2, "gprs[6]", -4);
#elif defined(__riscv)
    USDT::ArgumentParser_riscv64 parser(
	"-4@s5 -4@a0 4@20(s1) -4@-1 8@-72(s0) 8@0");
    verify_register(parser, -4, "s5");
    verify_register(parser, -4, "a0");
    verify_register(parser, 4, "s1", 20);
    verify_register(parser, -4, -1);
    verify_register(parser, 8, "s0", -72);
    verify_register(parser, 8, 0);
#elif defined(__x86_64__)
    USDT::ArgumentParser_x64 parser(
        "-4@$0 8@$1234 %rdi %rax %rsi "
        "8@$9223372036854775806 8@$18446744073709551614 "
        "-8@$-1 "
        "-8@%rbx 4@%r12 8@-8(%rbp) 4@(%rax) "
        "-4@global_max_action(%rip) "
        "8@24+mp_(%rip) "
        "-4@CheckpointStats+40(%rip) "
        "4@glob-2(%rip) "
        "8@(%rax,%rdx,8) "
        "4@(%rbx,%rcx)");

    verify_register(parser, -4, 0);
    verify_register(parser, 8, 1234);

    verify_register(parser, 8, "di");
    verify_register(parser, 8, "ax");
    verify_register(parser, 8, "si");
    verify_register(parser, 8, 9223372036854775806ll);
    verify_register(parser, 8, (long long)18446744073709551614ull);
    verify_register(parser, -8, -1);
    verify_register(parser, -8, "bx");
    verify_register(parser, 4, "r12");

    verify_register(parser, 8, "bp", -8);
    verify_register(parser, 4, "ax", 0);

    verify_register(parser, -4, "ip", 0, std::string("global_max_action"));
    verify_register(parser, 8, "ip", 24, std::string("mp_"));
    verify_register(parser, -4, "ip", 40, std::string("CheckpointStats"));
    verify_register(parser, 4, "ip", -2, std::string("glob"));

    verify_register(parser, 8, "ax", 0, nullopt, std::string("dx"), 8);
    verify_register(parser, 4, "bx", 0, nullopt, std::string("cx"));
#endif

    REQUIRE(parser.done());
  }
}

#endif /* supported arches only */
