// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

/**
 * Cookie types that's stored in the HILTI context to provide access to the
 * current analyzer.
 */

#pragma once

#include <optional>
#include <variant>

#include <zeek-spicy/zeek-compat.h>

namespace spicy::zeek::rt {

namespace cookie {

/** State on the current protocol analyzer. */
struct ProtocolAnalyzer {
    ::zeek::analyzer::Analyzer* analyzer = nullptr; /**< current analyzer */
    bool is_orig = false;                           /**< direction of the connection */
    uint64_t num_packets = 0;                       /**< number of packets seen so far */
    uint64_t analyzer_id = 0;                       /**< unique analyzer ID */
    uint64_t file_id = 0;                           /**< counter for file IDs */
};

/** State on the current file analyzer. */
struct FileAnalyzer {
    ::zeek::file_analysis::Analyzer* analyzer = nullptr; /**< current analyzer */
};

/** State on the current file analyzer. */
struct PacketAnalyzer {
    ::zeek::packet_analysis::Analyzer* analyzer = nullptr; /**< current analyzer */
    std::optional<uint32_t> next_analyzer;
};

} // namespace cookie

/** Type of state stored in HILTI's execution context during Spicy processing. */
using Cookie = std::variant<cookie::ProtocolAnalyzer, cookie::FileAnalyzer, cookie::PacketAnalyzer>;

} // namespace spicy::zeek::rt
