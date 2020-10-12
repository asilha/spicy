// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <optional>
#include <string>

#include <hilti/rt/result.h>

#include <spicy/rt/parser.h>

namespace spicy::rt {

class Driver;

namespace driver {

enum class ParsingType { Stream, Block };

/**
 * Abstract base class maintaining the parsing state during incremental input
 * processing.
 */
class ParsingState {
public:
    /**
     * Constructor.
     *
     * @param type of parsing; this determines how subsequent chunks of input
     * data are handled (stream-wise vs independent blocks)
     *
     * @param parser parser to use; can be left unset to either not perform
     * any parsing at all, or set it later through `setParser()`.
     */
    ParsingState(ParsingType type, const Parser* parser = nullptr) : _type(type), _parser(parser) {}

    /**
     * Returns false if a parser has neither been passed into the constructor
     * nor explicitly set through `setParser()`.
     */
    bool hasParser() const { return _parser != nullptr; }

    /**
     * Explicitly sets a parser to use. Once stream-based matching has
     * started, changing a parser won't have any effect.
     */
    void setParser(const Parser* parser) { _parser = parser; }

    /**
     * Returns true if parsing has finished due to either: regularly reaching
     * the end of input or end of grammar, a parsing error, explicit skipping
     * of remaining input.
     */
    bool isFinished() const { return _done || _skip; }

    /**
     * Explicitly skips any remaining input. Further calls to `process()` and
     * `finish()` will be ignored.
     */
    void skipRemaining() { _skip = true; }

    /** Returns true if `skipRemaining()` has been called previously. */
    bool isSkipping() const { return _skip; }

    /** Helper type for capturing return value of `process()`. */
    enum State {
        Done,    /**< parsing has fully finished */
        Continue /**< parsing remains ongoing and ready to accept for data */
    };

    /**
     * Feeds one chunk of data into parsing. If we're doing stream-based
     * parsing, this sends the data into the stream processing as the next
     * piece of input. If we're doing block-based parsing, the data must
     * constitute a complete self-contained block of input, so that the
     * parser can fully consume it as one unit instance.
     *
     * @param size length of data
     * @param data pointer to *size* bytes to feed into parsing
     * @returns Returns `State` indicating
     * if parsing remains ongoing or has finished.
     * @throws any exceptions (including in particular parse errors) are
     * passed through to caller
     */
    State process(size_t size, const char* data) { return _process(size, data, false); }

    /**
     * Finalizes parsing, signaling end-of-data to the parser. After calling
     * this, `process()` can no longer be called.
     *
     * @throws any exceptions (including in particular final parse errors)
     * are passed through to caller
     */
    std::optional<hilti::rt::stream::Offset> finish();

    /**
     * Resets parsing back to its original state as if no input had been sent
     * yet. Initialization information passed into the constructor, as well
     * as any parser explicitly set, is retained.
     */
    void reset() {
        _input.reset();
        _resumable.reset();
        _done = false;
        _skip = false;
    }

protected:
    /**
     * Virtual method to override by derived classed for recording debug
     * output.
     */
    virtual void _debug(const std::string_view& msg) = 0;

private:
    State _process(size_t size, const char* data, bool eod = true);
    void _debug(const std::string_view& msg, size_t size, const char* data);

    ParsingType _type;     /**< type of parsing */
    const Parser* _parser; /**< parser to use, or null if not specified */
    bool _skip = false;    /**< true if all further input is to be skipped */

    // State for stream matching only
    bool _done = false; /**< flag to indicate that stream matching has completed (either regularly or irregularly) */
    std::optional<hilti::rt::ValueReference<hilti::rt::Stream>> _input; /**< Current input data */
    std::optional<hilti::rt::Resumable> _resumable; /**< State for resuming parsing on next data chunk */
};

/** Specialized parsing state for use by *Driver*. */
class ParsingStateForDriver : public ParsingState {
public:
    /**
     * Constructor.
     *
     * @param type of parsing; this determines how subsequent chunks of input
     * data are handled (stream-wise vs independent blocks)
     *
     * @param parser parser to use; can be left unset to either not perform
     * any parsing at all, or set it later through `setParser()`.
     *
     * @param id textual ID to associate with state for use in debug messages
     *
     * @param driver driver owning this state
     */
    ParsingStateForDriver(ParsingType type, const Parser* parser, std::string id, Driver* driver)
        : ParsingState(type, parser), _id(id), _driver(driver) {}

    /** Returns the textual ID associated with the state. */
    const auto& id() const { return _id; }

protected:
    void _debug(const std::string_view& msg) override;

private:
    std::string _id;
    Driver* _driver;
};

} // namespace driver

/**
 * Runtime driver to retrieve and feed Spicy parsers.
 *
 * The HILTI/Spicy runtime environments must be managed externally, and must
 * have been initialized already before using any of the driver's
 * functionality.
 */
class Driver {
public:
    Driver() : _enable_debug(hilti::rt::isDebugVersion()) {}
    /**
     * Prints a human-readable list of all available parsers, retrieved from
     * the Spicy runtime system.
     *
     * @param out stream to print the summary to
     * @return an error if the list cannot be retrieved
     */
    hilti::rt::Result<hilti::rt::Nothing> listParsers(std::ostream& out);

    /**
     * Retrieves a parser by its name.
     *
     * @param name name of the parser to be retrieved, either as shown in the
     * output of `listParsers()`; or, alternatively, as a string rendering of a
     * port or MIME type as defined by a unit's properties. If no name is given
     * and there's only one parser available, that one is taken automatically.
     *
     * @return the parser, or an error if it could not be retrieved
     */
    hilti::rt::Result<const spicy::rt::Parser*> lookupParser(const std::string& name = "");

    /**
     * Feeds a parser with an input stream of data.
     *
     * @param parser parser to instantiate and feed
     * @param in stream to read input data from; will read until EOF is encountered
     * @param increment if non-zero, will feed the data in small chunks at a
     * time; this is mainly for testing parsers; incremental parsing
     *
     * @return error if the input couldn't be fed to the parser (excluding parse errors)
     * @throws HILTI or Spocy runtime error if the parser into trouble
     */
    hilti::rt::Result<spicy::rt::ParsedUnit> processInput(const spicy::rt::Parser& parser, std::istream& in,
                                                          int increment = 0);

    /**
     * Processes a batch of input streams given in Spicy's custom batch
     * format. See the documentation of `spicy-driver` for a reference of the
     * batch format.
     *
     * @param in an open stream to read the batch from
     * @returns appropriate error if there was a problem processing the batch
     */
    hilti::rt::Result<hilti::rt::Nothing> processPreBatchedInput(std::istream& in);

    /** Records a debug message to the `spicy-driver` runtime debug stream. */
    void debug(const std::string_view& msg);

private:
    void _debug_stats(const hilti::rt::ValueReference<hilti::rt::Stream>& data);
    void _debug_stats(size_t current_sessions);

    bool _enable_debug = false;
    uint64_t _total_sessions = 0;
};

} // namespace spicy::rt
