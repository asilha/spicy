// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <getopt.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <unordered_map>

#include <hilti/rt/fmt.h>
#include <hilti/rt/init.h>

#include <spicy/rt/driver.h>

using hilti::rt::Nothing;
using hilti::rt::Result;
using namespace hilti::rt::result;
using hilti::rt::fmt;

using namespace spicy::rt;

inline static auto pretty_print_number(uint64_t n) {
    if ( n > 1024 * 1024 * 1024 )
        return fmt("%" PRIu64 "G", n / 1024 / 1024 / 1024);
    if ( n > 1024 * 1024 )
        return fmt("%" PRIu64 "M", n / 1024 / 1024);
    if ( n > 1024 )
        return fmt("%" PRIu64 "K", n / 1024);
    return fmt("%" PRIu64, n);
}

inline void Driver::debug(const std::string_view& msg) {
    if ( ! _enable_debug )
        return;

    HILTI_RT_DEBUG("spicy-driver", msg);
}

void Driver::_debug_stats(const hilti::rt::ValueReference<hilti::rt::Stream>& data) {
    if ( ! _enable_debug )
        return;

    auto data_begin = data->begin().offset();
    auto data_end = data_begin + data->size();
    auto data_chunks = pretty_print_number(data->numberOfChunks());
    auto data_size_cur = pretty_print_number(data->size());
    auto data_size_total = pretty_print_number(data_end);

    debug(fmt("input : size-current=%s size-total=%s chunks-cur=%s offset-head=%" PRIu64 " offset-tail=%" PRIu64,
              data_size_cur, data_size_total, data_chunks, data_begin, data_end));

    auto ru = hilti::rt::resource_usage();
    auto memory_heap = pretty_print_number(ru.memory_heap);
    auto num_stacks = pretty_print_number(ru.num_fibers);
    auto max_stacks = pretty_print_number(ru.max_fibers);
    auto cached_stacks = pretty_print_number(ru.cached_fibers);

    debug(fmt("memory: heap=%s fibers-cur=%s fibers-cached=%s fibers-max=%s", memory_heap, num_stacks, cached_stacks,
              max_stacks));
}

void Driver::_debug_stats(size_t current_sessions) {
    if ( ! _enable_debug )
        return;

    auto num_sessions = pretty_print_number(current_sessions);
    auto total_sessions = pretty_print_number(_total_sessions);

    debug(fmt("sessions: current=%s total=%s", num_sessions, total_sessions));

    auto stats = hilti::rt::resource_usage();
    auto memory_heap = pretty_print_number(stats.memory_heap);
    auto num_stacks = pretty_print_number(stats.num_fibers);
    auto max_stacks = pretty_print_number(stats.max_fibers);
    auto cached_stacks = pretty_print_number(stats.cached_fibers);

    debug(fmt("memory  : heap=%s fibers-cur=%s fibers-cached=%s fibers-max=%s", memory_heap, num_stacks, cached_stacks,
              max_stacks));
}

Result<Nothing> Driver::listParsers(std::ostream& out) {
    if ( ! hilti::rt::isInitialized() )
        return Error("runtime not intialized");

    const auto& parsers = spicy::rt::parsers();

    if ( parsers.empty() ) {
        out << "No parsers available.\n";
        return Nothing();
    }

    out << "Available parsers:\n\n";

    for ( const auto& p : parsers ) {
        std::string description;
        std::string mime_types;
        std::string ports;

        if ( p->description.size() )
            description = fmt(" %s", p->description);

        if ( p->mime_types.size() )
            mime_types = fmt(" %s", p->mime_types);

        if ( p->ports.size() )
            ports = fmt(" %s", p->ports);

        out << fmt("  %15s %s%s%s\n", p->name, description, ports, mime_types);
    }

    out << "\n";
    return Nothing();
}

Result<const spicy::rt::Parser*> Driver::lookupParser(const std::string& name) {
    const auto& parsers = spicy::rt::parsers();

    if ( parsers.empty() )
        return Error("no parsers available");

    if ( name.empty() ) {
        if ( const auto& def = detail::globalState()->default_parser )
            return *def;
        else
            return Error("multiple parsers available, need to select one");
    }

    const auto& parsers_by_name = detail::globalState()->parsers_by_name;

    if ( auto p = parsers_by_name.find(name); p != parsers_by_name.end() ) {
        assert(! p->second.empty());

        if ( p->second.size() > 1 )
            return Error("multiple matching parsers found");

        return p->second.front();
    }
    else
        return hilti::rt::result::Error("no matching parser available");
}

Result<spicy::rt::ParsedUnit> Driver::processInput(const spicy::rt::Parser& parser, std::istream& in, int increment) {
    if ( ! hilti::rt::isInitialized() )
        return Error("runtime not initialized");

    char buffer[4096];
    hilti::rt::ValueReference<hilti::rt::Stream> data;
    std::optional<hilti::rt::Resumable> r;

    _debug_stats(data);

    spicy::rt::ParsedUnit unit;

    while ( in.good() && ! in.eof() ) {
        auto len = (increment > 0 ? increment : sizeof(buffer));

        in.read(buffer, len);

        if ( auto n = in.gcount() )
            data->append(hilti::rt::Bytes(buffer, n));

        if ( in.peek() == EOF )
            data->freeze();

        if ( ! r ) {
            debug(fmt("beginning parsing input (eod=%s)", data->isFrozen()));
            r = parser.parse3(unit, data, {});
        }
        else {
            debug(fmt("resuming parsing input (eod=%s)", data->isFrozen()));
            r->resume();
        }

        if ( *r ) {
            debug(fmt("finished parsing input (eod=%s)", data->isFrozen()));
            _debug_stats(data);
            break;
        }
        else {
            debug("parsing yielded");
            _debug_stats(data);
        }
    }

    return std::move(unit);
}

void driver::ParsingStateForDriver::_debug(const std::string_view& msg) {
    _driver->debug(hilti::rt::fmt("[%s] %s", _id, msg));
}

void driver::ParsingState::_debug(const std::string_view& msg, size_t size, const char* data) {
    _debug(hilti::rt::fmt("%s: |%s%s|", msg, hilti::rt::escapeBytes(std::string_view(data, std::min(size_t(40), size))),
                          size > 40 ? "..." : ""));
}

std::optional<hilti::rt::stream::Offset> driver::ParsingState::finish() {
    switch ( _type ) {
        case driver::ParsingType::Block: break;
        case driver::ParsingType::Stream: {
            _process(0, "", true);
        }
    }

    if ( _resumable )
        return _resumable->get<hilti::rt::stream::View>().offset();
    else
        return {};
}

driver::ParsingState::State driver::ParsingState::_process(size_t size, const char* data, bool eod) {
    assert(size == 0 || ! eod);

    if ( ! _parser ) {
        if ( size )
            _debug("no parser, further data ignored", size, data);

        return Done;
    }

    if ( _skip ) {
        if ( size )
            _debug("skipping, further data ignored", size, data);

        return Done;
    }

    try {
        switch ( _type ) {
            case ParsingType::Block: {
                _debug("block", size, data);

                auto input = hilti::rt::reference::make_value<hilti::rt::Stream>(data, size);
                input->freeze();

                _resumable = _parser->parse1(input, {});
                if ( ! _resumable )
                    hilti::rt::internalError("block-based parsing yielded");

                return Done;
            }

            case ParsingType::Stream: {
                if ( _done ) {
                    // Previous parsing has fully finished, we ignore all
                    // further input.
                    if ( size )
                        _debug("already finished, further data ignored", size, data);

                    return Done;
                }

                if ( ! _input ) {
                    // First chunk.
                    _debug("first data chunk", size, data);
                    _input = hilti::rt::reference::make_value<hilti::rt::Stream>(data, size);
                    if ( eod )
                        (*_input)->freeze();

                    _resumable = _parser->parse1(*_input, {});
                }

                else {
                    // Resume parsing.
                    assert(_input && _resumable);

                    if ( size )
                        (*_input)->append(data, size);

                    if ( eod ) {
                        _debug("end of data");
                        (*_input)->freeze();
                    }
                    else
                        _debug("next data chunk", size, data);

                    _resumable->resume();
                }

                if ( *_resumable ) {
                    // Done parsing.
                    _done = true;
                    _debug("parsing finished");
                    return Done;
                }
                else {
                    if ( eod )
                        hilti::rt::internalError("parsing yielded for final data chunk");

                    return Continue;
                }
            }
        }
    } catch ( const hilti::rt::Exception& e ) {
        _debug(e.what());
        _done = true;
        abort();
        throw;
    }

    hilti::rt::cannot_be_reached();
}

Result<hilti::rt::Nothing> Driver::processPreBatchedInput(std::istream& in) {
    std::string magic;
    std::getline(in, magic);

    if ( magic != std::string("!spicy-batch v1") )
        return hilti::rt::result::Error("input is not a Spicy batch file");

    std::unordered_map<std::string, driver::ParsingStateForDriver> states;

    while ( in.good() && ! in.eof() ) {
        std::string cmd;
        std::getline(in, cmd);
        cmd = hilti::rt::trim(cmd);

        if ( cmd.empty() )
            continue;

        auto m = hilti::rt::split(cmd);
        if ( m[0] == "@begin" ) {
            // @begin <id> <parser> <type>
            if ( m.size() != 4 )
                return hilti::rt::result::Error("unexpected number of argument for @begin");

            auto id = std::string(m[1]);
            auto parser_name = std::string(m[3]);

            driver::ParsingType type;

            if ( m[2] == "stream" )
                type = driver::ParsingType::Stream;
            else if ( m[2] == "block" )
                type = driver::ParsingType::Block;
            else
                return hilti::rt::result::Error(hilti::rt::fmt("unknown session type '%s'", m[2]));

            if ( auto parser = lookupParser(parser_name) ) {
                states.insert_or_assign(id, driver::ParsingStateForDriver(type, *parser, id, this));
                _total_sessions++;
            }
            else
                debug(hilti::rt::fmt("no parser for ID %s, skipping", id));
        }
        else if ( m[0] == "@data" ) {
            // @begin <id> <size>>p
            // [data]\n
            if ( m.size() != 3 )
                return hilti::rt::result::Error("unexpected number of argument for @data");

            auto id = std::string(m[1]);
            auto size = std::stoul(std::string(m[2]));

            char data[size];
            in.read(data, size);
            in.get(); // Eat newline.

            if ( in.eof() || in.fail() )
                return hilti::rt::result::Error("premature end of @data");

            auto s = states.find(id);
            if ( s != states.end() ) {
                try {
                    s->second.process(size, data);
                } catch ( const hilti::rt::Exception& e ) {
                    std::cout << hilti::rt::fmt("error for ID %s: %s\n", id, e.what());
                }
            }
        }
        else if ( m[0] == "@end" ) {
            // @end <id>
            if ( m.size() != 2 )
                return hilti::rt::result::Error("unexpected number of argument for @end");

            auto id = std::string(m[1]);

            auto s = states.find(id);
            if ( s != states.end() ) {
                try {
                    s->second.finish();
                } catch ( const hilti::rt::Exception& e ) {
                    std::cout << hilti::rt::fmt("error for ID %s: %s\n", id, e.what());
                }

                states.erase(s);
                _debug_stats(states.size());
            }
        }
        else
            return hilti::rt::result::Error(hilti::rt::fmt("unknown command '%s'", m[0]));
    }

    _debug_stats(states.size());
    return hilti::rt::Nothing();
}
