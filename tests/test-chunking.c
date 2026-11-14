#include <yaml.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

/*
 * Regression tests for attacker controlled input that crosses read boundaries.
 *
 * libyaml pulls bytes through yaml_read_handler_t.  Nothing in the API promises
 * that a UTF-8 sequence, a CRLF pair, a BOM, an anchor, an alias, a quoted
 * scalar or a piece of block structure arrives inside a single read: an
 * attacker feeding the parser from a socket chooses the boundaries.  These
 * tests drive identical bytes through the same pipeline with many different
 * chunk sizes and assert the following invariants.
 *
 *   1. For well formed input the token stream, the event stream and the loaded
 *      document (payload, marks and nesting) are independent of the chunking,
 *      including when a two, three or four byte character, an escape sequence
 *      or a BOM is split exactly inside the sequence.
 *
 *   2. For truncated characters, unclosed structures and over deep nesting the
 *      error category and position are chunking independent, and the pipeline
 *      scan -> parse -> load never turns invalid input into a usable document.
 *      A reader error is discovered lazily, so the number of tokens produced
 *      before it can grow when the reads are smaller; those tokens are only
 *      required to agree on the common prefix.  Scanner, parser and composer
 *      failures are deterministic and must agree exactly.
 *
 *   3. Repeated runs and cleanup after an error are deterministic: a failed
 *      parse leaves no queued state behind that a later parse can consume, the
 *      reader is never asked for zero bytes or for more than it is prepared to
 *      take, and the work spent on deeply nested hostile input is bounded by
 *      the nesting limit rather than by the input size.
 *
 * The tests use only the public API and the parser object members that the
 * existing tests (test-reader, test-nesting) already rely on.
 */

static int failures = 0;

static int
report_failure(const char *file, int line, const char *condition,
        const char *format, ...)
{
    va_list arguments;

    failures++;
    fprintf(stderr, "FAILED %s:%d: %s: ", file, line, condition);
    va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
    fputc('\n', stderr);

    return 0;
}

#define CHECK(condition, ...)                                                   \
    ((condition) ? 1 : report_failure(__FILE__, __LINE__, #condition,          \
                                      __VA_ARGS__))

/*
 * A generous ceiling on how many bytes the reader may ask a handler for in a
 * single call.  The library reads through a fixed size raw buffer, so a
 * request anywhere near this bound means the buffer grew in response to the
 * input, which is exactly what hostile input must not be able to cause.
 */
#define MAX_READ_REQUEST (1024 * 1024)

#define MAX_RECORDS 512

/*
 * A read handler serving a fixed byte sequence in application chosen pieces.
 * A piece is either a constant size (chunk) or the next entry of a repeating
 * pattern.  Every call is counted so the tests can check that the reader only
 * asks for what is left and cannot be kept busy forever.
 */

typedef struct {
    const unsigned char *data;
    size_t length;
    size_t position;
    const size_t *pattern;
    size_t pattern_length;
    size_t pattern_index;
    size_t single;
    size_t calls;
    size_t bytes_served;
    size_t max_request;
    size_t zero_sized_requests;
    long fail_on_call;          /* <= 0 means "never fail" */
} chunk_source;

static void
chunk_source_init(chunk_source *source, const unsigned char *data,
        size_t length, size_t chunk, const size_t *pattern,
        size_t pattern_length, long fail_on_call)
{
    memset(source, 0, sizeof(*source));
    source->data = data;
    source->length = length;
    source->fail_on_call = fail_on_call;

    if (chunk) {
        source->single = chunk;
        source->pattern = &source->single;
        source->pattern_length = 1;
    }
    else {
        source->pattern = pattern;
        source->pattern_length = pattern_length;
    }
}

static int
chunk_read_handler(void *data, unsigned char *buffer, size_t size,
        size_t *size_read)
{
    chunk_source *source = (chunk_source *)data;
    size_t request;

    source->calls++;
    if (size > source->max_request)
        source->max_request = size;
    if (!size)
        source->zero_sized_requests++;

    if (source->fail_on_call > 0
            && source->calls >= (size_t)source->fail_on_call) {
        *size_read = 0;
        return 0;
    }

    if (source->position >= source->length) {
        *size_read = 0;
        return 1;
    }

    request = source->pattern_length
        ? source->pattern[source->pattern_index % source->pattern_length]
        : source->length - source->position;
    source->pattern_index++;

    if (request > source->length - source->position)
        request = source->length - source->position;
    if (request > size)
        request = size;

    memcpy(buffer, source->data + source->position, request);
    source->position += request;
    source->bytes_served += request;
    *size_read = request;

    return 1;
}

static void
setup_parser(yaml_parser_t *parser, const unsigned char *data, size_t length,
        size_t chunk, const size_t *pattern, size_t pattern_length,
        long fail_on_call, chunk_source *source)
{
    chunk_source_init(source, data, length, chunk, pattern, pattern_length,
            fail_on_call);

    assert(yaml_parser_initialize(parser));
    if (chunk || pattern)
        yaml_parser_set_input(parser, chunk_read_handler, source);
    else
        yaml_parser_set_input_string(parser, data, length);
}

/*
 * Fingerprints of the scanner and parser output.
 */

typedef struct {
    int type;
    size_t start_index;
    size_t start_line;
    size_t start_column;
    size_t end_index;
    size_t end_line;
    size_t end_column;
    size_t length;
    int aux;                    /* scalar style or %YAML version */
    char *text;
    size_t text_length;
} token_record;

typedef struct {
    int type;
    size_t start_index;
    size_t start_line;
    size_t start_column;
    size_t end_index;
    size_t end_line;
    size_t end_column;
    char *text;
    size_t text_length;
} event_record;

typedef struct {
    int failed;
    int type;
    char problem[96];
    size_t problem_offset;
    int problem_value;
    size_t problem_mark_index;
    size_t problem_mark_line;
    size_t problem_mark_column;
    char context[96];
    size_t context_mark_index;
    size_t context_mark_line;
    size_t context_mark_column;
} error_record;

static void
copy_string(char *destination, size_t destination_size, const char *source)
{
    if (!source) {
        destination[0] = '\0';
        return;
    }

    strncpy(destination, source, destination_size - 1);
    destination[destination_size - 1] = '\0';
}

static void
text_release(char **text, size_t *text_length)
{
    free(*text);
    *text = NULL;
    *text_length = 0;
}

static void
text_replace(char **text, size_t *text_length, const unsigned char *value,
        size_t value_length)
{
    if (!value)
        value_length = 0;

    free(*text);
    *text = (char *)malloc(value_length + 1);
    assert(*text);
    if (value_length)
        memcpy(*text, value, value_length);
    (*text)[value_length] = '\0';
    *text_length = value_length;
}

static void
text_append(char **text, size_t *text_length, const unsigned char *value,
        size_t value_length)
{
    char *extended;

    if (!value || !value_length)
        return;

    extended = (char *)realloc(*text, *text_length + value_length + 1);
    assert(extended);
    memcpy(extended + *text_length, value, value_length);
    extended[*text_length + value_length] = '\0';
    *text = extended;
    *text_length += value_length;
}

static void
text_append_string(char **text, size_t *text_length, const char *value)
{
    text_append(text, text_length, (const unsigned char *)value,
            strlen(value));
}

static void
text_append_number(char **text, size_t *text_length, long value)
{
    char digits[32];
    size_t position = sizeof(digits) - 1;
    int negative = 0;
    char sign;

    digits[position] = '\0';
    if (value < 0) {
        negative = 1;
        value = -value;
    }

    do {
        digits[--position] = (char)('0' + (value % 10));
        value /= 10;
    } while (value);

    if (negative) {
        sign = '-';
        text_append(text, text_length, (const unsigned char *)&sign, 1);
    }

    text_append(text, text_length, (const unsigned char *)(digits + position),
            sizeof(digits) - 1 - position);
}

static void
token_record_from(token_record *record, const yaml_token_t *token)
{
    memset(record, 0, sizeof(*record));
    record->type = token->type;
    record->start_index = token->start_mark.index;
    record->start_line = token->start_mark.line;
    record->start_column = token->start_mark.column;
    record->end_index = token->end_mark.index;
    record->end_line = token->end_mark.line;
    record->end_column = token->end_mark.column;

    switch (token->type) {
        case YAML_SCALAR_TOKEN:
            record->length = token->data.scalar.length;
            record->aux = (int)token->data.scalar.style;
            text_replace(&record->text, &record->text_length,
                    token->data.scalar.value, token->data.scalar.length);
            break;
        case YAML_ANCHOR_TOKEN:
            text_replace(&record->text, &record->text_length,
                    token->data.anchor.value,
                    strlen((char *)token->data.anchor.value));
            break;
        case YAML_ALIAS_TOKEN:
            text_replace(&record->text, &record->text_length,
                    token->data.alias.value,
                    strlen((char *)token->data.alias.value));
            break;
        case YAML_TAG_TOKEN:
            text_replace(&record->text, &record->text_length,
                    token->data.tag.handle,
                    strlen((char *)token->data.tag.handle));
            text_append_string(&record->text, &record->text_length, " ");
            text_append(&record->text, &record->text_length,
                    token->data.tag.suffix,
                    strlen((char *)token->data.tag.suffix));
            break;
        case YAML_TAG_DIRECTIVE_TOKEN:
            text_replace(&record->text, &record->text_length,
                    token->data.tag_directive.handle,
                    strlen((char *)token->data.tag_directive.handle));
            text_append_string(&record->text, &record->text_length, " ");
            text_append(&record->text, &record->text_length,
                    token->data.tag_directive.prefix,
                    strlen((char *)token->data.tag_directive.prefix));
            break;
        case YAML_VERSION_DIRECTIVE_TOKEN:
            record->aux = token->data.version_directive.major * 100
                + token->data.version_directive.minor;
            break;
        default:
            break;
    }
}

static void
token_record_delete(token_record *record)
{
    text_release(&record->text, &record->text_length);
    memset(record, 0, sizeof(*record));
}

static int
token_record_equal(const token_record *expected, const token_record *actual,
        const char *case_name, size_t chunk)
{
    if (expected->type != actual->type)
        return CHECK(0, "%s chunk=%lu: token type %d != %d", case_name,
                (unsigned long)chunk, actual->type, expected->type);

    if (expected->start_index != actual->start_index
            || expected->start_line != actual->start_line
            || expected->start_column != actual->start_column)
        return CHECK(0, "%s chunk=%lu: token %d start mark %lu:%lu:%lu "
                "!= %lu:%lu:%lu", case_name, (unsigned long)chunk,
                actual->type, (unsigned long)actual->start_index,
                (unsigned long)actual->start_line,
                (unsigned long)actual->start_column,
                (unsigned long)expected->start_index,
                (unsigned long)expected->start_line,
                (unsigned long)expected->start_column);

    if (expected->end_index != actual->end_index
            || expected->end_line != actual->end_line
            || expected->end_column != actual->end_column)
        return CHECK(0, "%s chunk=%lu: token %d end mark %lu:%lu:%lu "
                "!= %lu:%lu:%lu", case_name, (unsigned long)chunk,
                actual->type, (unsigned long)actual->end_index,
                (unsigned long)actual->end_line,
                (unsigned long)actual->end_column,
                (unsigned long)expected->end_index,
                (unsigned long)expected->end_line,
                (unsigned long)expected->end_column);

    if (expected->length != actual->length || expected->aux != actual->aux)
        return CHECK(0, "%s chunk=%lu: token %d length %lu style %d != %lu %d",
                case_name, (unsigned long)chunk, actual->type,
                (unsigned long)actual->length, actual->aux,
                (unsigned long)expected->length, expected->aux);

    if (expected->text_length != actual->text_length
            || memcmp(expected->text ? expected->text : "",
                      actual->text ? actual->text : "",
                      expected->text_length))
        return CHECK(0, "%s chunk=%lu: token %d payload differs", case_name,
                (unsigned long)chunk, actual->type);

    return 1;
}

static void
event_record_from(event_record *record, const yaml_event_t *event)
{
    memset(record, 0, sizeof(*record));
    record->type = event->type;
    record->start_index = event->start_mark.index;
    record->start_line = event->start_mark.line;
    record->start_column = event->start_mark.column;
    record->end_index = event->end_mark.index;
    record->end_line = event->end_mark.line;
    record->end_column = event->end_mark.column;

    switch (event->type) {
        case YAML_SCALAR_EVENT:
            text_replace(&record->text, &record->text_length,
                    event->data.scalar.value, event->data.scalar.length);
            text_append_string(&record->text, &record->text_length,
                    "|anchor=");
            text_append(&record->text, &record->text_length,
                    event->data.scalar.anchor,
                    event->data.scalar.anchor
                        ? strlen((char *)event->data.scalar.anchor) : 0);
            text_append_string(&record->text, &record->text_length, "|tag=");
            text_append(&record->text, &record->text_length,
                    event->data.scalar.tag,
                    event->data.scalar.tag
                        ? strlen((char *)event->data.scalar.tag) : 0);
            text_append_string(&record->text, &record->text_length,
                    "|style=");
            text_append_number(&record->text, &record->text_length,
                    (int)event->data.scalar.style);
            text_append_string(&record->text, &record->text_length,
                    "|implicit=");
            text_append_number(&record->text, &record->text_length,
                    event->data.scalar.plain_implicit);
            text_append_number(&record->text, &record->text_length,
                    event->data.scalar.quoted_implicit);
            break;
        case YAML_ALIAS_EVENT:
            text_replace(&record->text, &record->text_length,
                    event->data.alias.anchor,
                    strlen((char *)event->data.alias.anchor));
            break;
        case YAML_SEQUENCE_START_EVENT:
            text_replace(&record->text, &record->text_length,
                    event->data.sequence_start.anchor,
                    event->data.sequence_start.anchor
                        ? strlen((char *)event->data.sequence_start.anchor) : 0);
            text_append_string(&record->text, &record->text_length, "|");
            text_append(&record->text, &record->text_length,
                    event->data.sequence_start.tag,
                    event->data.sequence_start.tag
                        ? strlen((char *)event->data.sequence_start.tag) : 0);
            break;
        case YAML_MAPPING_START_EVENT:
            text_replace(&record->text, &record->text_length,
                    event->data.mapping_start.anchor,
                    event->data.mapping_start.anchor
                        ? strlen((char *)event->data.mapping_start.anchor) : 0);
            text_append_string(&record->text, &record->text_length, "|");
            text_append(&record->text, &record->text_length,
                    event->data.mapping_start.tag,
                    event->data.mapping_start.tag
                        ? strlen((char *)event->data.mapping_start.tag) : 0);
            break;
        default:
            break;
    }
}

static void
event_record_delete(event_record *record)
{
    text_release(&record->text, &record->text_length);
    memset(record, 0, sizeof(*record));
}

static int
event_record_equal(const event_record *expected, const event_record *actual,
        const char *case_name, size_t chunk)
{
    if (expected->type != actual->type)
        return CHECK(0, "%s chunk=%lu: event type %d != %d", case_name,
                (unsigned long)chunk, actual->type, expected->type);

    if (expected->start_index != actual->start_index
            || expected->start_line != actual->start_line
            || expected->start_column != actual->start_column
            || expected->end_index != actual->end_index
            || expected->end_line != actual->end_line
            || expected->end_column != actual->end_column)
        return CHECK(0, "%s chunk=%lu: event %d marks %lu:%lu:%lu-%lu:%lu:%lu "
                "!= %lu:%lu:%lu-%lu:%lu:%lu", case_name, (unsigned long)chunk,
                actual->type, (unsigned long)actual->start_index,
                (unsigned long)actual->start_line,
                (unsigned long)actual->start_column,
                (unsigned long)actual->end_index,
                (unsigned long)actual->end_line,
                (unsigned long)actual->end_column,
                (unsigned long)expected->start_index,
                (unsigned long)expected->start_line,
                (unsigned long)expected->start_column,
                (unsigned long)expected->end_index,
                (unsigned long)expected->end_line,
                (unsigned long)expected->end_column);

    if (expected->text_length != actual->text_length
            || memcmp(expected->text ? expected->text : "",
                      actual->text ? actual->text : "",
                      expected->text_length))
        return CHECK(0, "%s chunk=%lu: event %d payload differs", case_name,
                (unsigned long)chunk, actual->type);

    return 1;
}

static void
error_record_from(error_record *record, const yaml_parser_t *parser, int failed)
{
    memset(record, 0, sizeof(*record));
    record->failed = failed;
    record->type = parser->error;
    record->problem_offset = parser->problem_offset;
    record->problem_value = parser->problem_value;
    record->problem_mark_index = parser->problem_mark.index;
    record->problem_mark_line = parser->problem_mark.line;
    record->problem_mark_column = parser->problem_mark.column;
    record->context_mark_index = parser->context_mark.index;
    record->context_mark_line = parser->context_mark.line;
    record->context_mark_column = parser->context_mark.column;
    copy_string(record->problem, sizeof(record->problem), parser->problem);
    copy_string(record->context, sizeof(record->context), parser->context);
}

static int
error_record_equal(const error_record *expected, const error_record *actual,
        const char *case_name, size_t chunk)
{
    if (expected->failed != actual->failed)
        return CHECK(0, "%s chunk=%lu: failure presence %d != %d", case_name,
                (unsigned long)chunk, actual->failed, expected->failed);

    if (expected->type != actual->type)
        return CHECK(0, "%s chunk=%lu: error type %d != %d", case_name,
                (unsigned long)chunk, actual->type, expected->type);

    if (strcmp(expected->problem, actual->problem))
        return CHECK(0, "%s chunk=%lu: problem '%s' != '%s'", case_name,
                (unsigned long)chunk, actual->problem, expected->problem);

    if (expected->problem_offset != actual->problem_offset
            || expected->problem_value != actual->problem_value)
        return CHECK(0, "%s chunk=%lu: problem offset %lu value %d != %lu %d",
                case_name, (unsigned long)chunk,
                (unsigned long)actual->problem_offset, actual->problem_value,
                (unsigned long)expected->problem_offset,
                expected->problem_value);

    if (expected->problem_mark_index != actual->problem_mark_index
            || expected->problem_mark_line != actual->problem_mark_line
            || expected->problem_mark_column != actual->problem_mark_column)
        return CHECK(0, "%s chunk=%lu: problem mark %lu:%lu:%lu != "
                "%lu:%lu:%lu", case_name, (unsigned long)chunk,
                (unsigned long)actual->problem_mark_index,
                (unsigned long)actual->problem_mark_line,
                (unsigned long)actual->problem_mark_column,
                (unsigned long)expected->problem_mark_index,
                (unsigned long)expected->problem_mark_line,
                (unsigned long)expected->problem_mark_column);

    if (strcmp(expected->context, actual->context))
        return CHECK(0, "%s chunk=%lu: context '%s' != '%s'", case_name,
                (unsigned long)chunk, actual->context, expected->context);

    if (expected->context_mark_index != actual->context_mark_index
            || expected->context_mark_line != actual->context_mark_line
            || expected->context_mark_column != actual->context_mark_column)
        return CHECK(0, "%s chunk=%lu: context mark %lu:%lu:%lu != "
                "%lu:%lu:%lu", case_name, (unsigned long)chunk,
                (unsigned long)actual->context_mark_index,
                (unsigned long)actual->context_mark_line,
                (unsigned long)actual->context_mark_column,
                (unsigned long)expected->context_mark_index,
                (unsigned long)expected->context_mark_line,
                (unsigned long)expected->context_mark_column);

    return 1;
}

/*
 * Stage runners.
 */

typedef struct {
    int failed;
    size_t steps;
    size_t calls;
    size_t bytes_served;
    size_t max_request;
    size_t zero_sized_requests;
    int post_error_stable;
} stage_stats;

static int
scan_stage(const unsigned char *data, size_t length, size_t chunk,
        const size_t *pattern, size_t pattern_length, long fail_on_call,
        size_t step_budget, token_record *records, size_t max_records,
        size_t *count, error_record *error, stage_stats *stats)
{
    yaml_parser_t parser;
    yaml_token_t token;
    chunk_source source;
    size_t steps = 0;
    size_t queued_before;
    size_t queued_after;
    size_t calls_before;
    int failed = 0;
    int stable = 1;
    int i;

    memset(stats, 0, sizeof(*stats));
    *count = 0;
    setup_parser(&parser, data, length, chunk, pattern, pattern_length,
            fail_on_call, &source);

    for (;;) {
        if (steps++ > step_budget) {
            CHECK(0, "scan: step budget %lu exhausted (possible endless loop)",
                    (unsigned long)step_budget);
            failed = 1;
            break;
        }
        if (!yaml_parser_scan(&parser, &token)) {
            failed = 1;
            break;
        }
        if (token.type == YAML_STREAM_END_TOKEN) {
            yaml_token_delete(&token);
            break;
        }
        if (*count >= max_records) {
            CHECK(0, "scan: more than %lu tokens",
                    (unsigned long)max_records);
            failed = 1;
            yaml_token_delete(&token);
            break;
        }
        token_record_from(&records[*count], &token);
        (*count)++;
        yaml_token_delete(&token);
    }

    error_record_from(error, &parser, failed);
    stats->failed = failed;
    stats->steps = steps;
    stats->calls = source.calls;
    stats->bytes_served = source.bytes_served;
    stats->max_request = source.max_request;
    stats->zero_sized_requests = source.zero_sized_requests;

    /*
     * Once the scanner has failed it must not hand out anything else, must
     * not consume more input and must not drain tokens that were queued
     * before the failure.  Those queued tokens disappear together with the
     * parser, so a later parse can never observe them.
     */
    if (failed) {
        queued_before = (size_t)(parser.tokens.tail - parser.tokens.head);
        calls_before = source.calls;

        for (i = 0; i < 3; i++) {
            yaml_token_t extra;
            memset(&extra, 0xAA, sizeof(extra));
            if (!yaml_parser_scan(&parser, &extra)
                    || extra.type != YAML_NO_TOKEN)
                stable = 0;
            memset(&extra, 0, sizeof(extra));
        }

        queued_after = (size_t)(parser.tokens.tail - parser.tokens.head);
        if (queued_after != queued_before || source.calls != calls_before)
            stable = 0;
    }

    stats->post_error_stable = stable;
    yaml_parser_delete(&parser);

    return !failed;
}

static int
parse_stage(const unsigned char *data, size_t length, size_t chunk,
        const size_t *pattern, size_t pattern_length, long fail_on_call,
        size_t step_budget, event_record *records, size_t max_records,
        size_t *count, error_record *error, stage_stats *stats)
{
    yaml_parser_t parser;
    yaml_event_t event;
    chunk_source source;
    size_t steps = 0;
    size_t calls_before;
    int failed = 0;
    int stable = 1;
    int i;

    memset(stats, 0, sizeof(*stats));
    *count = 0;
    setup_parser(&parser, data, length, chunk, pattern, pattern_length,
            fail_on_call, &source);

    for (;;) {
        if (steps++ > step_budget) {
            CHECK(0, "parse: step budget %lu exhausted (possible endless loop)",
                    (unsigned long)step_budget);
            failed = 1;
            break;
        }
        if (!yaml_parser_parse(&parser, &event)) {
            failed = 1;
            break;
        }
        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            break;
        }
        if (*count >= max_records) {
            CHECK(0, "parse: more than %lu events",
                    (unsigned long)max_records);
            failed = 1;
            yaml_event_delete(&event);
            break;
        }
        event_record_from(&records[*count], &event);
        (*count)++;
        yaml_event_delete(&event);
    }

    error_record_from(error, &parser, failed);
    stats->failed = failed;
    stats->steps = steps;
    stats->calls = source.calls;
    stats->bytes_served = source.bytes_served;
    stats->max_request = source.max_request;
    stats->zero_sized_requests = source.zero_sized_requests;

    if (failed) {
        calls_before = source.calls;
        for (i = 0; i < 3; i++) {
            yaml_event_t extra;
            memset(&extra, 0xAA, sizeof(extra));
            if (!yaml_parser_parse(&parser, &extra)
                    || extra.type != YAML_NO_EVENT)
                stable = 0;
            memset(&extra, 0, sizeof(extra));
        }
        if (source.calls != calls_before)
            stable = 0;
    }

    stats->post_error_stable = stable;
    yaml_parser_delete(&parser);

    return !failed;
}

/*
 * Textual digest of a composed document.  It records the node type, tag,
 * scalar payload and style, and the exact shape of the tree, so any change
 * caused by how an input is split shows up as a difference.
 */

static void
document_digest(yaml_document_t *document, yaml_node_t *node, int depth,
        char **text, size_t *text_length)
{
    int index;

    if (!node || depth > 16) {
        text_append_string(text, text_length, "<cut>");
        return;
    }

    text_append_string(text, text_length, "(");
    text_append_number(text, text_length, depth);
    text_append_string(text, text_length, ",");
    text_append_number(text, text_length, (int)node->type);
    text_append_string(text, text_length, ",");
    text_append(text, text_length, node->tag,
            node->tag ? strlen((char *)node->tag) : 0);

    switch (node->type) {
        case YAML_SCALAR_NODE:
            text_append_string(text, text_length, ",");
            text_append_number(text, text_length,
                    (long)node->data.scalar.length);
            text_append_string(text, text_length, ",");
            text_append_number(text, text_length,
                    (int)node->data.scalar.style);
            text_append_string(text, text_length, ":");
            text_append(text, text_length, node->data.scalar.value,
                    node->data.scalar.length);
            break;

        case YAML_SEQUENCE_NODE:
            for (index = 0;
                    index < (int)(node->data.sequence.items.top
                        - node->data.sequence.items.start); index++) {
                text_append_string(text, text_length, "[");
                document_digest(document,
                        yaml_document_get_node(document,
                            node->data.sequence.items.start[index]),
                        depth + 1, text, text_length);
                text_append_string(text, text_length, "]");
            }
            break;

        case YAML_MAPPING_NODE:
            for (index = 0;
                    index < (int)(node->data.mapping.pairs.top
                        - node->data.mapping.pairs.start); index++) {
                yaml_node_pair_t pair = node->data.mapping.pairs.start[index];
                text_append_string(text, text_length, "<");
                document_digest(document,
                        yaml_document_get_node(document, pair.key),
                        depth + 1, text, text_length);
                text_append_string(text, text_length, "=");
                document_digest(document,
                        yaml_document_get_node(document, pair.value),
                        depth + 1, text, text_length);
                text_append_string(text, text_length, ">");
            }
            break;

        default:
            text_append_string(text, text_length, "?");
            break;
    }

    text_append_string(text, text_length, ")");
}

typedef struct {
    int failed;
    int root_type;
    size_t calls;
    size_t bytes_served;
} load_stats;

static int
load_stage(const unsigned char *data, size_t length, size_t chunk,
        const size_t *pattern, size_t pattern_length, long fail_on_call,
        char **digest, size_t *digest_length, error_record *error,
        load_stats *stats)
{
    yaml_parser_t parser;
    yaml_document_t document;
    yaml_node_t *root;
    chunk_source source;
    int success;

    memset(stats, 0, sizeof(*stats));
    setup_parser(&parser, data, length, chunk, pattern, pattern_length,
            fail_on_call, &source);

    memset(&document, 0, sizeof(document));
    success = yaml_parser_load(&parser, &document);
    root = yaml_document_get_root_node(&document);

    error_record_from(error, &parser, !success);
    stats->failed = !success;
    stats->root_type = root ? (int)root->type : -1;
    stats->calls = source.calls;
    stats->bytes_served = source.bytes_served;

    if (success && root)
        document_digest(&document, root, 0, digest, digest_length);

    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

    return success;
}

/*
 * Inputs and shared chunk configurations.
 */

typedef struct {
    const char *name;
    const unsigned char *data;
    size_t length;
} test_input;

static const size_t small_chunks[] = { 1, 2, 3, 4, 5, 7, 8, 13, 64, 1000 };
static const size_t irregular_pattern[] = { 1, 2, 3, 5, 7, 11, 4, 6, 1, 9 };

static size_t
step_budget_for(size_t length)
{
    size_t budget = length * 8 + 1024;

    return budget < 131072 ? budget : 131072;
}

static int
check_reader_contract(const char *case_name, size_t chunk,
        const stage_stats *stats, size_t length)
{
    if (stats->zero_sized_requests)
        return CHECK(0, "%s chunk=%lu: %lu zero sized read requests",
                case_name, (unsigned long)chunk,
                (unsigned long)stats->zero_sized_requests);

    if (stats->max_request > MAX_READ_REQUEST)
        return CHECK(0, "%s chunk=%lu: reader requested %lu bytes in one "
                "call, above the %d byte ceiling", case_name,
                (unsigned long)chunk, (unsigned long)stats->max_request,
                MAX_READ_REQUEST);

    if (stats->bytes_served > length)
        return CHECK(0, "%s chunk=%lu: reader consumed %lu of %lu bytes",
                case_name, (unsigned long)chunk,
                (unsigned long)stats->bytes_served, (unsigned long)length);

    return 1;
}

/*
 * Well formed input: token stream, event stream and loaded document must be
 * identical for every chunking and for the string interface.
 */

static int
check_well_formed(const test_input *input)
{
    token_record reference_tokens[MAX_RECORDS];
    token_record tokens[MAX_RECORDS];
    event_record reference_events[MAX_RECORDS];
    event_record events[MAX_RECORDS];
    error_record reference_scan_error;
    error_record reference_parse_error;
    error_record reference_load_error;
    error_record scan_error;
    error_record parse_error;
    error_record load_error;
    stage_stats scan_stats;
    stage_stats parse_stats;
    load_stats load_stats;
    char *reference_digest = NULL;
    char *digest = NULL;
    size_t reference_digest_length = 0;
    size_t digest_length = 0;
    size_t reference_token_count = 0;
    size_t reference_event_count = 0;
    size_t token_count = 0;
    size_t event_count = 0;
    size_t i;
    size_t j;
    int reference_root;
    int ok = 1;

    /* Reference run: one contiguous buffer through the string interface. */
    if (!scan_stage(input->data, input->length, 0, NULL, 0, 0,
                step_budget_for(input->length), reference_tokens, MAX_RECORDS,
                &reference_token_count, &reference_scan_error, &scan_stats))
        return CHECK(0, "%s: reference scan failed: %s", input->name,
                reference_scan_error.problem);

    if (!parse_stage(input->data, input->length, 0, NULL, 0, 0,
                step_budget_for(input->length), reference_events, MAX_RECORDS,
                &reference_event_count, &reference_parse_error, &parse_stats))
        return CHECK(0, "%s: reference parse failed: %s", input->name,
                reference_parse_error.problem);

    if (!load_stage(input->data, input->length, 0, NULL, 0, 0,
                &reference_digest, &reference_digest_length,
                &reference_load_error, &load_stats))
        return CHECK(0, "%s: reference load failed: %s", input->name,
                reference_load_error.problem);

    /*
     * An empty stream loads successfully but has no root node, so the digest
     * is legitimately absent for it.
     */
    reference_root = load_stats.root_type;
    if (reference_root == -1 && reference_digest_length != 0)
        return CHECK(0, "%s: document digest without a root node",
                input->name);

    if (input->length) {
        /*
         * The generic input handler delivering everything in one call must
         * agree with the string interface.
         */
        token_count = 0;
        if (!scan_stage(input->data, input->length, input->length, NULL, 0, 0,
                    step_budget_for(input->length), tokens, MAX_RECORDS,
                    &token_count, &scan_error, &scan_stats)) {
            ok = CHECK(0, "%s: single gulp scan failed: %s", input->name,
                    scan_error.problem);
        }
        else {
            if (!error_record_equal(&reference_scan_error, &scan_error,
                        input->name, input->length))
                ok = 0;
            if (token_count != reference_token_count)
                ok = CHECK(0, "%s: single gulp token count %lu != %lu",
                        input->name, (unsigned long)token_count,
                        (unsigned long)reference_token_count) && ok;
            for (j = 0; ok && j < reference_token_count; j++)
                ok = token_record_equal(&reference_tokens[j], &tokens[j],
                        input->name, input->length);
            ok = check_reader_contract(input->name, input->length, &scan_stats,
                    input->length) && ok;
        }
        for (j = 0; j < token_count && j < MAX_RECORDS; j++)
            token_record_delete(&tokens[j]);
        if (!ok)
            goto cleanup;
    }

    /*
     * Irregular pattern: reads repeatedly end inside indicators, quotes and
     * multi byte sequences.
     */
    token_count = 0;
    if (!scan_stage(input->data, input->length, 0, irregular_pattern,
                sizeof(irregular_pattern) / sizeof(irregular_pattern[0]), 0,
                step_budget_for(input->length) + input->length * 2, tokens,
                MAX_RECORDS, &token_count, &scan_error, &scan_stats)) {
        ok = CHECK(0, "%s: patterned scan failed: %s", input->name,
                scan_error.problem);
    }
    else {
        if (!error_record_equal(&reference_scan_error, &scan_error,
                    input->name, 0))
            ok = 0;
        if (token_count != reference_token_count)
            ok = CHECK(0, "%s: patterned token count %lu != %lu", input->name,
                    (unsigned long)token_count,
                    (unsigned long)reference_token_count) && ok;
        for (j = 0; ok && j < reference_token_count; j++)
            ok = token_record_equal(&reference_tokens[j], &tokens[j],
                    input->name, 0);
        ok = check_reader_contract(input->name, 0, &scan_stats,
                input->length) && ok;
    }
    for (j = 0; j < token_count && j < MAX_RECORDS; j++)
        token_record_delete(&tokens[j]);
    if (!ok)
        goto cleanup;

    for (i = 0; i < sizeof(small_chunks) / sizeof(small_chunks[0]); i++) {
        size_t chunk = small_chunks[i];

        if (chunk > input->length)
            continue;

        /* Scanning. */
        token_count = 0;
        if (!scan_stage(input->data, input->length, chunk, NULL, 0, 0,
                    step_budget_for(input->length) + input->length * 2,
                    tokens, MAX_RECORDS, &token_count, &scan_error,
                    &scan_stats)) {
            ok = CHECK(0, "%s chunk=%lu: scan failed: %s", input->name,
                    (unsigned long)chunk, scan_error.problem);
            break;
        }
        if (!error_record_equal(&reference_scan_error, &scan_error,
                    input->name, chunk))
            ok = 0;
        if (token_count != reference_token_count) {
            ok = CHECK(0, "%s chunk=%lu: token count %lu != %lu", input->name,
                    (unsigned long)chunk, (unsigned long)token_count,
                    (unsigned long)reference_token_count) && ok;
        }
        for (j = 0; ok && j < reference_token_count; j++)
            ok = token_record_equal(&reference_tokens[j], &tokens[j],
                    input->name, chunk);
        for (j = 0; j < token_count && j < MAX_RECORDS; j++)
            token_record_delete(&tokens[j]);
        ok = check_reader_contract(input->name, chunk, &scan_stats,
                input->length) && ok;
        if (!ok)
            break;

        /* Event parsing. */
        event_count = 0;
        if (!parse_stage(input->data, input->length, chunk, NULL, 0, 0,
                    step_budget_for(input->length) + input->length * 2,
                    events, MAX_RECORDS, &event_count, &parse_error,
                    &parse_stats)) {
            ok = CHECK(0, "%s chunk=%lu: parse failed: %s", input->name,
                    (unsigned long)chunk, parse_error.problem);
            break;
        }
        if (!error_record_equal(&reference_parse_error, &parse_error,
                    input->name, chunk))
            ok = 0;
        if (event_count != reference_event_count) {
            ok = CHECK(0, "%s chunk=%lu: event count %lu != %lu", input->name,
                    (unsigned long)chunk, (unsigned long)event_count,
                    (unsigned long)reference_event_count) && ok;
        }
        for (j = 0; ok && j < reference_event_count; j++)
            ok = event_record_equal(&reference_events[j], &events[j],
                    input->name, chunk);
        for (j = 0; j < event_count && j < MAX_RECORDS; j++)
            event_record_delete(&events[j]);
        ok = check_reader_contract(input->name, chunk, &parse_stats,
                input->length) && ok;
        if (!ok)
            break;

        /* Document loading. */
        digest = NULL;
        digest_length = 0;
        if (!load_stage(input->data, input->length, chunk, NULL, 0, 0,
                    &digest, &digest_length, &load_error, &load_stats)) {
            ok = CHECK(0, "%s chunk=%lu: load failed: %s", input->name,
                    (unsigned long)chunk, load_error.problem);
            break;
        }
        if (!error_record_equal(&reference_load_error, &load_error,
                    input->name, chunk))
            ok = 0;
        if (load_stats.root_type != reference_root
                || digest_length != reference_digest_length
                || memcmp(digest ? digest : "",
                    reference_digest ? reference_digest : "",
                    digest_length)) {
            ok = CHECK(0, "%s chunk=%lu: composed document differs (root %d "
                    "vs %d, digest %lu vs %lu bytes)", input->name,
                    (unsigned long)chunk, load_stats.root_type,
                    reference_root, (unsigned long)digest_length,
                    (unsigned long)reference_digest_length) && ok;
        }
        free(digest);
        digest = NULL;
        if (!ok)
            break;
    }

cleanup:
    for (j = 0; j < reference_token_count && j < MAX_RECORDS; j++)
        token_record_delete(&reference_tokens[j]);
    for (j = 0; j < reference_event_count && j < MAX_RECORDS; j++)
        event_record_delete(&reference_events[j]);
    free(reference_digest);
    free(digest);

    return ok;
}

/*
 * Malformed input: the error category and position must be chunking
 * independent, and no stage may turn the input into a usable document.
 *
 * expected_stage: 0 = reading/scanning, 1 = parsing, 2 = composing.
 */

static int
check_malformed(const test_input *input, int expected_error_type,
        const char *expected_problem, int expected_stage)
{
    token_record reference_tokens[MAX_RECORDS];
    token_record tokens[MAX_RECORDS];
    event_record reference_events[MAX_RECORDS];
    event_record events[MAX_RECORDS];
    error_record reference_scan_error;
    error_record reference_parse_error;
    error_record reference_load_error;
    error_record scan_error;
    error_record parse_error;
    error_record load_error;
    stage_stats scan_stats;
    stage_stats parse_stats;
    load_stats load_stats;
    char *digest = NULL;
    size_t digest_length = 0;
    size_t reference_token_count = 0;
    size_t reference_event_count = 0;
    size_t token_count = 0;
    size_t event_count = 0;
    size_t i;
    size_t j;
    int scan_failed;
    int parse_failed;
    int load_failed;
    int ok = 1;

    scan_failed = !scan_stage(input->data, input->length, 0, NULL, 0, 0,
            step_budget_for(input->length), reference_tokens, MAX_RECORDS,
            &reference_token_count, &reference_scan_error, &scan_stats);
    parse_failed = !parse_stage(input->data, input->length, 0, NULL, 0, 0,
            step_budget_for(input->length), reference_events, MAX_RECORDS,
            &reference_event_count, &reference_parse_error, &parse_stats);
    load_failed = !load_stage(input->data, input->length, 0, NULL, 0, 0,
            &digest, &digest_length, &reference_load_error, &load_stats);
    free(digest);
    digest = NULL;

    /*
     * The pipeline must reject the input somewhere, and a rejected load must
     * never expose a root node.
     */
    if (!scan_failed && !parse_failed && !load_failed) {
        ok = CHECK(0, "%s: hostile input accepted by every stage",
                input->name);
        goto cleanup;
    }
    if (load_failed && load_stats.root_type != -1) {
        ok = CHECK(0, "%s: failed load still exposes root node type %d",
                input->name, load_stats.root_type);
        goto cleanup;
    }
    if (expected_stage == 0 && !scan_failed)
        ok = CHECK(0, "%s: expected the reader/scanner to reject the input",
                input->name);
    else if (expected_stage == 1 && !parse_failed)
        ok = CHECK(0, "%s: expected the parser to reject the input",
                input->name);
    else if (expected_stage == 2 && !load_failed)
        ok = CHECK(0, "%s: expected the composer to reject the input",
                input->name);
    if (!ok)
        goto cleanup;

    /*
     * Pin the reference error descriptor: the category produced by the stage
     * that fails, plus the problem text.
     */
    {
        const error_record *failing = scan_failed ? &reference_scan_error
            : parse_failed ? &reference_parse_error : &reference_load_error;

        if (failing->type != expected_error_type)
            ok = CHECK(0, "%s: error type %d != expected %d", input->name,
                    failing->type, expected_error_type);
        if (ok && expected_problem
                && strcmp(failing->problem, expected_problem))
            ok = CHECK(0, "%s: problem '%s' != expected '%s'", input->name,
                    failing->problem, expected_problem);
        if (!ok)
            goto cleanup;
    }

    if (scan_failed && !CHECK(scan_stats.post_error_stable,
                "%s: scanner keeps changing state after an error",
                input->name))
        ok = 0;

    for (i = 0; ok && i < sizeof(small_chunks) / sizeof(small_chunks[0]); i++) {
        size_t chunk = small_chunks[i];

        if (chunk > input->length)
            continue;

        /*
         * Scanning.  A reader error is discovered lazily, so the number of
         * tokens produced before it can grow with smaller chunks; the error
         * descriptor and the already produced tokens must not change.
         */
        token_count = 0;
        if (!scan_stage(input->data, input->length, chunk, NULL, 0, 0,
                    step_budget_for(input->length) + input->length * 2,
                    tokens, MAX_RECORDS, &token_count, &scan_error,
                    &scan_stats)) {
            if (!error_record_equal(&reference_scan_error, &scan_error,
                        input->name, chunk))
                ok = 0;
            if (!CHECK(scan_stats.post_error_stable,
                        "%s chunk=%lu: scanner keeps changing state after an "
                        "error", input->name, (unsigned long)chunk))
                ok = 0;
        }
        else {
            if (!error_record_equal(&reference_scan_error, &scan_error,
                        input->name, chunk))
                ok = 0;
            if (token_count != reference_token_count)
                ok = CHECK(0, "%s chunk=%lu: token count %lu != %lu",
                        input->name, (unsigned long)chunk,
                        (unsigned long)token_count,
                        (unsigned long)reference_token_count) && ok;
        }

        /* Produced tokens must agree on the common prefix. */
        for (j = 0; ok && j < token_count && j < reference_token_count; j++)
            ok = token_record_equal(&reference_tokens[j], &tokens[j],
                    input->name, chunk);
        for (j = 0; j < token_count && j < MAX_RECORDS; j++)
            token_record_delete(&tokens[j]);
        ok = check_reader_contract(input->name, chunk, &scan_stats,
                input->length) && ok;
        if (!ok)
            break;

        /*
         * Event parsing.  Scanner and parser errors are deterministic, so the
         * event count must match; a reader error again only freezes a prefix.
         */
        event_count = 0;
        if (!parse_stage(input->data, input->length, chunk, NULL, 0, 0,
                    step_budget_for(input->length) + input->length * 2,
                    events, MAX_RECORDS, &event_count, &parse_error,
                    &parse_stats)) {
            if (!error_record_equal(&reference_parse_error, &parse_error,
                        input->name, chunk))
                ok = 0;
            if (!CHECK(parse_stats.post_error_stable,
                        "%s chunk=%lu: parser keeps changing state after an "
                        "error", input->name, (unsigned long)chunk))
                ok = 0;
        }
        else if (!error_record_equal(&reference_parse_error, &parse_error,
                    input->name, chunk)) {
            ok = 0;
        }
        else if (reference_parse_error.type != YAML_READER_ERROR
                && event_count != reference_event_count) {
            ok = CHECK(0, "%s chunk=%lu: event count %lu != %lu", input->name,
                    (unsigned long)chunk, (unsigned long)event_count,
                    (unsigned long)reference_event_count) && ok;
        }

        for (j = 0; ok && j < event_count && j < reference_event_count; j++)
            ok = event_record_equal(&reference_events[j], &events[j],
                    input->name, chunk);
        for (j = 0; j < event_count && j < MAX_RECORDS; j++)
            event_record_delete(&events[j]);
        if (!ok)
            break;

        /*
         * Loading.  Whatever the chunking, a failed load yields no document
         * and the composer error descriptor stays identical.
         */
        digest = NULL;
        digest_length = 0;
        if (load_stage(input->data, input->length, chunk, NULL, 0, 0,
                    &digest, &digest_length, &load_error, &load_stats)) {
            ok = CHECK(0, "%s chunk=%lu: hostile input loaded a document "
                    "(root type %d)", input->name, (unsigned long)chunk,
                    load_stats.root_type);
            free(digest);
            digest = NULL;
            break;
        }
        if (load_stats.root_type != -1)
            ok = CHECK(0, "%s chunk=%lu: failed load exposes a root node",
                    input->name, (unsigned long)chunk) && ok;
        if (!error_record_equal(&reference_load_error, &load_error,
                    input->name, chunk))
            ok = 0;
        free(digest);
        digest = NULL;
        if (!ok)
            break;
    }

cleanup:
    for (j = 0; j < reference_token_count && j < MAX_RECORDS; j++)
        token_record_delete(&reference_tokens[j]);
    for (j = 0; j < reference_event_count && j < MAX_RECORDS; j++)
        event_record_delete(&reference_events[j]);

    return ok;
}

/*
 * Nesting limits and bounded work.
 */

static int
scan_depth_input(const unsigned char *data, size_t length, int expect_failure,
        const char *case_name)
{
    token_record reference[MAX_RECORDS];
    token_record records[MAX_RECORDS];
    error_record reference_error;
    error_record error;
    stage_stats stats;
    size_t reference_count = 0;
    size_t count = 0;
    size_t i;
    size_t j;
    int ok = 1;

    if (!scan_stage(data, length, 0, NULL, 0, 0, 131072, reference,
                MAX_RECORDS, &reference_count, &reference_error, &stats)) {
        if (!expect_failure)
            ok = CHECK(0, "%s: contiguous scan failed: %s", case_name,
                    reference_error.problem);
    }
    else if (expect_failure) {
        ok = CHECK(0, "%s: contiguous scan accepted input beyond the limit",
                case_name);
    }

    for (i = 0; ok && i < 3; i++) {
        size_t chunk = i + 1;

        count = 0;
        if (!scan_stage(data, length, chunk, NULL, 0, 0, 131072, records,
                    MAX_RECORDS, &count, &error, &stats)) {
            if (!expect_failure)
                ok = CHECK(0, "%s chunk=%lu: scan failed: %s", case_name,
                        (unsigned long)chunk, error.problem);
            else
                ok = error_record_equal(&reference_error, &error, case_name,
                        chunk);
        }
        else if (expect_failure) {
            ok = CHECK(0, "%s chunk=%lu: scan accepted input beyond the limit",
                    case_name, (unsigned long)chunk);
        }
        else {
            ok = error_record_equal(&reference_error, &error, case_name, chunk);
            if (ok && count != reference_count)
                ok = CHECK(0, "%s chunk=%lu: token count %lu != %lu",
                        case_name, (unsigned long)chunk, (unsigned long)count,
                        (unsigned long)reference_count);
            for (j = 0; ok && j < reference_count && j < count; j++)
                ok = token_record_equal(&reference[j], &records[j], case_name,
                        chunk);
        }
        for (j = 0; j < count && j < MAX_RECORDS; j++)
            token_record_delete(&records[j]);
    }

    for (j = 0; j < reference_count && j < MAX_RECORDS; j++)
        token_record_delete(&reference[j]);

    return ok;
}

static int
check_flow_depth(size_t depth, int expect_failure)
{
    unsigned char *input = (unsigned char *)malloc(depth ? depth : 1);
    int ok;

    assert(input);
    memset(input, '[', depth);

    ok = scan_depth_input(input, depth, expect_failure, "flow depth");
    free(input);

    return ok;
}

static int
check_block_depth(size_t depth, int expect_failure)
{
    size_t length = depth * (depth + 5) / 2 + 16;
    unsigned char *input = (unsigned char *)malloc(length);
    size_t position = 0;
    size_t i;
    size_t j;
    int ok;

    assert(input);
    for (i = 0; i < depth; i++) {
        for (j = 0; j < i; j++)
            input[position++] = ' ';
        input[position++] = (unsigned char)('a' + (i % 26));
        input[position++] = ':';
        input[position++] = '\n';
    }

    ok = scan_depth_input(input, position, expect_failure, "block depth");
    free(input);

    return ok;
}

/*
 * Deeply nested hostile input must be rejected after an amount of work
 * governed by the nesting limit, not by the input size, and the reader may
 * never be driven past the bytes it actually has.
 */

static int
check_bounded_deep_read(int saved_limit)
{
    size_t depth = 100000;
    unsigned char *input = (unsigned char *)malloc(depth);
    token_record records[MAX_RECORDS];
    error_record error;
    stage_stats stats;
    size_t count = 0;
    int limit = 64;
    int ok = 1;

    assert(input);
    memset(input, '[', depth);

    yaml_set_max_nest_level(limit);

    if (!scan_stage(input, depth, 1, NULL, 0, 0, (size_t)limit + 512,
                records, MAX_RECORDS, &count, &error, &stats)) {
        if (error.type != YAML_SCANNER_ERROR
                || strcmp(error.problem, "exceeded maximum nesting depth")
                || strcmp(error.context, "while increasing flow level"))
            ok = CHECK(0, "bounded deep read: unexpected error %d '%s' in '%s'",
                    error.type, error.problem, error.context);

        if (ok && !CHECK(stats.bytes_served <= (size_t)limit * 2 + 32,
                    "bounded deep read: consumed %lu bytes for a limit of %d",
                    (unsigned long)stats.bytes_served, limit))
            ok = 0;
        if (ok && !CHECK(stats.calls <= (size_t)limit * 2 + 32,
                    "bounded deep read: %lu read calls for a limit of %d",
                    (unsigned long)stats.calls, limit))
            ok = 0;
        if (ok && !CHECK(stats.post_error_stable,
                    "bounded deep read: scanner keeps changing state after "
                    "rejecting the input"))
            ok = 0;
    }
    else {
        ok = CHECK(0, "bounded deep read: hostile input accepted");
    }

    /* The same rejection must happen for a contiguous buffer. */
    if (ok) {
        size_t contiguous_count = 0;

        if (!scan_stage(input, depth, 0, NULL, 0, 0, (size_t)limit + 512,
                    records, MAX_RECORDS, &contiguous_count, &error, &stats)) {
            if (error.type != YAML_SCANNER_ERROR
                    || strcmp(error.problem,
                        "exceeded maximum nesting depth"))
                ok = CHECK(0, "bounded deep read: contiguous error %d '%s'",
                        error.type, error.problem);
        }
        else {
            ok = CHECK(0, "bounded deep read: contiguous input accepted");
        }
    }

    yaml_set_max_nest_level(saved_limit);
    free(input);

    return ok;
}

/*
 * Repeated chunking, handler failures and reuse of memory after an error.
 */

static int
check_repeated_and_cleanup(void)
{
    static const unsigned char broken[] =
        "base: &anc !tag/x 'q''uoted'\n"
        "alias: *anc\n"
        "tail: \"trunc\xc3";
    static const unsigned char good[] =
        "base: &anc !tag/x 'q''uoted'\n"
        "alias: *anc\n"
        "multi: \"caf\xc3\xa9 \xe6\x97\xa5 \xf0\x9f\x98\x80\"\n"
        "flow: [1, {x: [y]}]\n";
    token_record reference[MAX_RECORDS];
    token_record records[MAX_RECORDS];
    error_record reference_error;
    error_record broken_error;
    error_record error;
    stage_stats stats;
    size_t reference_count = 0;
    size_t broken_count = 0;
    size_t count = 0;
    size_t i;
    size_t j;
    int ok = 1;

    /* Reference stream for the well formed document. */
    if (!scan_stage(good, sizeof(good) - 1, 0, NULL, 0, 0, 65536, reference,
                MAX_RECORDS, &reference_count, &reference_error, &stats))
        return CHECK(0, "cleanup: reference scan failed: %s",
                reference_error.problem);

    /*
     * Reference descriptor for the broken input, taken from a contiguous run.
     */
    if (scan_stage(broken, sizeof(broken) - 1, 0, NULL, 0, 0, 65536, records,
                MAX_RECORDS, &broken_count, &broken_error, &stats)) {
        ok = CHECK(0, "cleanup: broken input unexpectedly scanned");
    }
    for (j = 0; j < broken_count && j < MAX_RECORDS; j++)
        token_record_delete(&records[j]);

    /*
     * Chunk the broken input repeatedly.  Every run must fail with the very
     * same descriptor and leave no observable leftovers.
     */
    for (i = 0; ok && i < 3; i++) {
        count = 0;
        if (!scan_stage(broken, sizeof(broken) - 1, 3, NULL, 0, 0, 65536,
                    records, MAX_RECORDS, &count, &error, &stats)) {
            if (!error_record_equal(&broken_error, &error, "cleanup", 3))
                ok = 0;
            if (!CHECK(stats.post_error_stable,
                        "cleanup run %lu: scanner keeps changing state after "
                        "an error", (unsigned long)i))
                ok = 0;
        }
        else {
            ok = CHECK(0, "cleanup run %lu: broken input accepted",
                    (unsigned long)i);
        }
        for (j = 0; j < count && j < MAX_RECORDS; j++)
            token_record_delete(&records[j]);
    }

    /*
     * Delete the parser after the failure, initialize a fresh one and check
     * that the good stream is produced with its original marks.  Stale state
     * left by the damaged run would show up as a shifted position.
     */
    if (ok) {
        yaml_parser_t parser;
        yaml_token_t token;
        size_t good_count = 0;
        int failed = 0;
        int extra;

        memset(&parser, 0, sizeof(parser));
        assert(yaml_parser_initialize(&parser));
        yaml_parser_set_input_string(&parser, broken, sizeof(broken) - 1);
        while (!failed) {
            if (!yaml_parser_scan(&parser, &token))
                failed = 1;
            else if (token.type == YAML_STREAM_END_TOKEN) {
                yaml_token_delete(&token);
                break;
            }
            else
                yaml_token_delete(&token);
        }
        if (!CHECK(failed, "cleanup: broken input unexpectedly scanned"))
            ok = 0;
        yaml_parser_delete(&parser);

        memset(&parser, 0, sizeof(parser));
        assert(yaml_parser_initialize(&parser));
        yaml_parser_set_input_string(&parser, good, sizeof(good) - 1);
        for (;;) {
            if (!CHECK(yaml_parser_scan(&parser, &token),
                        "cleanup: reused parser failed on good input"))
                break;
            if (token.type == YAML_STREAM_END_TOKEN) {
                yaml_token_delete(&token);
                break;
            }
            if (good_count < MAX_RECORDS)
                token_record_from(&records[good_count], &token);
            good_count++;
            yaml_token_delete(&token);
        }
        if (good_count != reference_count)
            ok = CHECK(0, "cleanup: reused parser produced %lu tokens instead "
                    "of %lu", (unsigned long)good_count,
                    (unsigned long)reference_count) && ok;
        for (j = 0; ok && j < good_count && j < reference_count
                && j < MAX_RECORDS; j++)
            ok = token_record_equal(&reference[j], &records[j],
                    "cleanup-reused", 0);
        for (j = 0; j < good_count && j < MAX_RECORDS; j++)
            token_record_delete(&records[j]);

        /*
         * After STREAM-END the scanner answers with an empty token instead of
         * continuing to consume input.
         */
        extra = yaml_parser_scan(&parser, &token);
        if (!CHECK(extra, "cleanup: scanner failed after STREAM-END")
                || !CHECK(token.type == YAML_NO_TOKEN,
                    "cleanup: scanner produced token type %d after STREAM-END",
                    token.type))
            ok = 0;
        yaml_parser_delete(&parser);
    }

    /*
     * A read handler failure must surface as a reader error and as a failed
     * load without a root node, not as a truncated but valid document.
     */
    if (ok) {
        char *digest = NULL;
        size_t digest_length = 0;
        load_stats load_stats;
        error_record handler_error;

        if (load_stage(good, sizeof(good) - 1, 1, NULL, 0, 2, &digest,
                    &digest_length, &handler_error, &load_stats)) {
            ok = CHECK(0, "cleanup: read handler failure was ignored");
        }
        else if (handler_error.type != YAML_READER_ERROR
                || strcmp(handler_error.problem, "input error")
                || load_stats.root_type != -1) {
            ok = CHECK(0, "cleanup: handler failure reported as %d '%s' with "
                    "root type %d", handler_error.type, handler_error.problem,
                    load_stats.root_type);
        }
        free(digest);
    }

    for (j = 0; j < reference_count && j < MAX_RECORDS; j++)
        token_record_delete(&reference[j]);

    return ok;
}

/*
 * A payload that crosses the reader's raw buffer seam in the middle of a
 * scalar, an anchor and a four byte character.  These cases use their own
 * chunk set so that the seam is hit exactly.
 */

static int
check_boundary_payload(const unsigned char *document, size_t length,
        const char *case_name)
{
    static const size_t boundary_chunks[] = {
        1, 2, 3, 4095, 4096, 16380, 16381, 16382, 16383, 16384, 16385, 16386,
        32768
    };
    token_record reference[MAX_RECORDS];
    token_record records[MAX_RECORDS];
    error_record reference_error;
    error_record error;
    stage_stats stats;
    size_t reference_count = 0;
    size_t count = 0;
    size_t i;
    size_t j;
    int ok = 1;

    if (!scan_stage(document, length, 0, NULL, 0, 0, 131072, reference,
                MAX_RECORDS, &reference_count, &reference_error, &stats))
        return CHECK(0, "%s: reference scan failed: %s", case_name,
                reference_error.problem);

    for (i = 0; ok && i < sizeof(boundary_chunks) / sizeof(boundary_chunks[0]);
            i++) {
        count = 0;
        if (!scan_stage(document, length, boundary_chunks[i], NULL, 0, 0,
                    131072, records, MAX_RECORDS, &count, &error, &stats)) {
            ok = CHECK(0, "%s chunk=%lu: scan failed: %s", case_name,
                    (unsigned long)boundary_chunks[i], error.problem);
            break;
        }
        if (!error_record_equal(&reference_error, &error, case_name,
                    boundary_chunks[i]))
            ok = 0;
        if (count != reference_count)
            ok = CHECK(0, "%s chunk=%lu: token count %lu != %lu", case_name,
                    (unsigned long)boundary_chunks[i], (unsigned long)count,
                    (unsigned long)reference_count) && ok;
        for (j = 0; ok && j < reference_count; j++)
            ok = token_record_equal(&reference[j], &records[j], case_name,
                    boundary_chunks[i]);
        for (j = 0; j < count && j < MAX_RECORDS; j++)
            token_record_delete(&records[j]);
        ok = check_reader_contract(case_name, boundary_chunks[i], &stats,
                length) && ok;
    }

    for (j = 0; j < reference_count && j < MAX_RECORDS; j++)
        token_record_delete(&reference[j]);

    return ok;
}

static int
run_boundary_inputs(void)
{
    size_t size = 40000;
    unsigned char *document = (unsigned char *)malloc(size + 16);
    size_t i;
    int ok = 1;

    assert(document);

    /* Long double quoted scalar with the seam inside the payload. */
    document[0] = 'k';
    document[1] = ':';
    document[2] = ' ';
    document[3] = '"';
    for (i = 4; i < size + 4; i++)
        document[i] = 'a';
    document[size + 4] = '"';
    document[size + 5] = '\n';
    ok = check_boundary_payload(document, size + 6, "long-scalar-quoted") && ok;

    /* The same payload as a plain scalar: the seam must not end the token. */
    memset(document, 'a', size);
    document[size] = '\n';
    ok = check_boundary_payload(document, size + 1, "long-scalar-plain") && ok;

    /* A long anchor value. */
    document[0] = '&';
    for (i = 1; i <= size; i++)
        document[i] = 'n';
    document[size + 1] = ' ';
    document[size + 2] = 'x';
    document[size + 3] = '\n';
    ok = check_boundary_payload(document, size + 4, "long-anchor") && ok;

    /*
     * A four byte character whose first byte sits just before the seam, so
     * the reader sees one leading and one continuation byte in the first
     * buffer and must wait for the rest instead of reporting a truncation.
     */
    memset(document, 'a', size);
    document[0] = 'k';
    document[1] = ':';
    document[2] = ' ';
    document[3] = '"';
    document[16383] = 0xf0;
    document[16384] = 0x9f;
    document[16385] = 0x98;
    document[16386] = 0x80;
    document[size - 2] = '"';
    document[size - 1] = '\n';
    ok = check_boundary_payload(document, size, "emoji-at-seam") && ok;

    free(document);

    return ok;
}

/*
 * Input corpora.
 */

static int
run_valid_inputs(void)
{
    int ok = 1;

    /*
     * One document exercising anchors, aliases, tags, single and double
     * quoted scalars with escapes, a block mapping, a block scalar, flow
     * collections, a BOM and two, three and four byte characters.  The
     * leading BOM is split by chunk sizes 1, 2 and 3.
     */
    {
        static const unsigned char document[] =
            "\xef\xbb\xbf"
            "%YAML 1.1\n"
            "---\n"
            "base: &anc !tag/x 'q''uoted'\n"
            "alias: *anc\n"
            "double: \"esc \\u00e9\\t\\\\\"\n"
            "block:\n"
            "  k1: \"caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x98\x80\"\n"
            "  k2: |\n"
            "    literal\n"
            "flow: [1, {x: [y]}, *anc]\n"
            "plain: caf\xc3\xa9 \xe6\x97\xa5\n";
        test_input input;

        input.name = "features";
        input.data = document;
        input.length = sizeof(document) - 1;
        ok = check_well_formed(&input);
    }

    /* CRLF line breaks split exactly between '\r' and '\n'. */
    {
        static const unsigned char document[] =
            "a: 1\r\n"
            "b: \"caf\xc3\xa9\"\r\n"
            "c:\r\n"
            "  - x\r\n"
            "  - \"y\"\r\n";
        test_input input;

        input.name = "crlf";
        input.data = document;
        input.length = sizeof(document) - 1;
        ok = check_well_formed(&input) && ok;
    }

    /* UTF-16LE and UTF-16BE with a surrogate pair after a split BOM. */
    {
        static const unsigned char le[] = {
            0xff, 0xfe,
            'a', 0, ':', 0, ' ', 0,
            '"', 0, 0x3d, 0xd8, 0x00, 0xde, '"', 0,
            '\n', 0,
            'b', 0, ':', 0, ' ', 0, '1', 0, '\n', 0
        };
        static const unsigned char be[] = {
            0xfe, 0xff,
            0, 'a', 0, ':', 0, ' ', 0, '"',
            0xd8, 0x3d, 0xde, 0x00,
            0, '"', 0, '\n',
            0, 'b', 0, ':', 0, ' ',
            0, '1', 0, '\n'
        };
        test_input input;

        input.name = "utf16le";
        input.data = le;
        input.length = sizeof(le);
        ok = check_well_formed(&input) && ok;

        input.name = "utf16be";
        input.data = be;
        input.length = sizeof(be);
        ok = check_well_formed(&input) && ok;
    }

    /* Several documents: chunking must not blur the document borders. */
    {
        static const unsigned char document[] =
            "---\n"
            "a: &anc 1\n"
            "b: *anc\n"
            "...\n"
            "---\n"
            "c: [2, {d: e}]\n";
        test_input input;

        input.name = "multi-document";
        input.data = document;
        input.length = sizeof(document) - 1;
        ok = check_well_formed(&input) && ok;
    }

    /* Empty and comment only input are still valid streams. */
    {
        static const unsigned char empty[] = "";
        static const unsigned char comment[] = "# only a comment\n";
        test_input input;

        input.name = "empty";
        input.data = empty;
        input.length = 0;
        ok = check_well_formed(&input) && ok;

        input.name = "comment-only";
        input.data = comment;
        input.length = sizeof(comment) - 1;
        ok = check_well_formed(&input) && ok;
    }

    return ok;
}

static int
run_malformed_inputs(void)
{
    static const unsigned char trunc_2[] = "a: \"x\xc3";
    static const unsigned char trunc_3[] = "a: \"\xe2\x82";
    static const unsigned char trunc_4[] = "a: \"\xf0\x90\x80";
    static const unsigned char trunc_in_flow[] = "[{a: \"x\xc3";
    static const unsigned char bad_continuation[] = "a: \"\xe2\x28\xa1\"";
    static const unsigned char lone_continuation[] = "a: \x80";
    static const unsigned char overlong[] = "a: \xc0\xaf";
    static const unsigned char surrogate[] = "a: \xed\xa0\x80";
    static const unsigned char too_large[] = "a: \xf4\x90\x80\x80";
    static const unsigned char control[] = "a: \x01";
    static const unsigned char single_quoted[] = "a: 'bc";
    static const unsigned char double_quoted[] = "a: \"bc";
    static const unsigned char escape_at_eof[] = "a: \"bc\\";
    static const unsigned char bare_alias[] = "*";
    static const unsigned char bare_anchor[] = "&";
    static const unsigned char empty_tag[] = "a: !<";
    static const unsigned char tab_indent[] = "a:\n\tb: 1";
    static const unsigned char unclosed_sequence[] = "a: [1, 2";
    static const unsigned char unclosed_nested_sequence[] = "[a, [b";
    static const unsigned char unclosed_mapping[] = "{a: {b: 1}";
    static const unsigned char undefined_alias[] = "a: *nope";
    static const unsigned char duplicate_anchor[] = "a: &x 1\nb: &x 2";
    static const unsigned char utf16_odd[] = {
        0xff, 0xfe, 'a', 0, ':', 0, ' ', 0, 'x'
    };
    static const unsigned char utf16_lone_high[] = {
        0xff, 0xfe, 'a', 0, ':', 0, ' ', 0, 0x3d, 0xd8
    };
    static const unsigned char utf8_bom_truncated[] = { 0xef, 0xbb };
    test_input input;
    int ok = 1;

    /* Truncated multi byte characters; the byte offset must be stable. */
    input.name = "truncated-2-byte";
    input.data = trunc_2;
    input.length = sizeof(trunc_2) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "incomplete UTF-8 octet sequence", 0) && ok;

    input.name = "truncated-3-byte";
    input.data = trunc_3;
    input.length = sizeof(trunc_3) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "incomplete UTF-8 octet sequence", 0) && ok;

    input.name = "truncated-4-byte";
    input.data = trunc_4;
    input.length = sizeof(trunc_4) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "incomplete UTF-8 octet sequence", 0) && ok;

    input.name = "truncated-in-flow";
    input.data = trunc_in_flow;
    input.length = sizeof(trunc_in_flow) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "incomplete UTF-8 octet sequence", 0) && ok;

    /* Invalid but complete encodings. */
    input.name = "bad-continuation";
    input.data = bad_continuation;
    input.length = sizeof(bad_continuation) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "invalid trailing UTF-8 octet", 0) && ok;

    input.name = "lone-continuation";
    input.data = lone_continuation;
    input.length = sizeof(lone_continuation) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "invalid leading UTF-8 octet", 0) && ok;

    input.name = "overlong";
    input.data = overlong;
    input.length = sizeof(overlong) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "invalid length of a UTF-8 sequence", 0) && ok;

    input.name = "surrogate";
    input.data = surrogate;
    input.length = sizeof(surrogate) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "invalid Unicode character", 0) && ok;

    input.name = "too-large";
    input.data = too_large;
    input.length = sizeof(too_large) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "invalid Unicode character", 0) && ok;

    input.name = "control-character";
    input.data = control;
    input.length = sizeof(control) - 1;
    ok = check_malformed(&input, YAML_READER_ERROR,
            "control characters are not allowed", 0) && ok;

    /* Unclosed and otherwise malformed scalar structures. */
    input.name = "single-quoted";
    input.data = single_quoted;
    input.length = sizeof(single_quoted) - 1;
    ok = check_malformed(&input, YAML_SCANNER_ERROR,
            "found unexpected end of stream", 0) && ok;

    input.name = "double-quoted";
    input.data = double_quoted;
    input.length = sizeof(double_quoted) - 1;
    ok = check_malformed(&input, YAML_SCANNER_ERROR,
            "found unexpected end of stream", 0) && ok;

    input.name = "escape-at-eof";
    input.data = escape_at_eof;
    input.length = sizeof(escape_at_eof) - 1;
    ok = check_malformed(&input, YAML_SCANNER_ERROR,
            "found unknown escape character", 0) && ok;

    input.name = "bare-alias";
    input.data = bare_alias;
    input.length = sizeof(bare_alias) - 1;
    ok = check_malformed(&input, YAML_SCANNER_ERROR,
            "did not find expected alphabetic or numeric character", 0) && ok;

    input.name = "bare-anchor";
    input.data = bare_anchor;
    input.length = sizeof(bare_anchor) - 1;
    ok = check_malformed(&input, YAML_SCANNER_ERROR,
            "did not find expected alphabetic or numeric character", 0) && ok;

    input.name = "empty-tag";
    input.data = empty_tag;
    input.length = sizeof(empty_tag) - 1;
    ok = check_malformed(&input, YAML_SCANNER_ERROR,
            "did not find expected tag URI", 0) && ok;

    input.name = "tab-indent";
    input.data = tab_indent;
    input.length = sizeof(tab_indent) - 1;
    ok = check_malformed(&input, YAML_SCANNER_ERROR,
            "found character that cannot start any token", 0) && ok;

    /*
     * Unclosed flow collections scan without error; the parser is the stage
     * that must reject them.
     */
    input.name = "unclosed-sequence";
    input.data = unclosed_sequence;
    input.length = sizeof(unclosed_sequence) - 1;
    ok = check_malformed(&input, YAML_PARSER_ERROR,
            "did not find expected ',' or ']'", 1) && ok;

    input.name = "unclosed-nested-sequence";
    input.data = unclosed_nested_sequence;
    input.length = sizeof(unclosed_nested_sequence) - 1;
    ok = check_malformed(&input, YAML_PARSER_ERROR,
            "did not find expected ',' or ']'", 1) && ok;

    input.name = "unclosed-mapping";
    input.data = unclosed_mapping;
    input.length = sizeof(unclosed_mapping) - 1;
    ok = check_malformed(&input, YAML_PARSER_ERROR,
            "did not find expected ',' or '}'", 1) && ok;

    /*
     * Composer level failures: the scanner and the parser accept them, but
     * loading must not produce a document.
     */
    input.name = "undefined-alias";
    input.data = undefined_alias;
    input.length = sizeof(undefined_alias) - 1;
    ok = check_malformed(&input, YAML_COMPOSER_ERROR,
            "found undefined alias", 2) && ok;

    input.name = "duplicate-anchor";
    input.data = duplicate_anchor;
    input.length = sizeof(duplicate_anchor) - 1;
    ok = check_malformed(&input, YAML_COMPOSER_ERROR,
            "second occurrence", 2) && ok;

    /* UTF-16 truncation. */
    input.name = "utf16-odd";
    input.data = utf16_odd;
    input.length = sizeof(utf16_odd);
    ok = check_malformed(&input, YAML_READER_ERROR,
            "incomplete UTF-16 character", 0) && ok;

    input.name = "utf16-lone-high";
    input.data = utf16_lone_high;
    input.length = sizeof(utf16_lone_high);
    ok = check_malformed(&input, YAML_READER_ERROR,
            "incomplete UTF-16 surrogate pair", 0) && ok;

    input.name = "utf8-bom-truncated";
    input.data = utf8_bom_truncated;
    input.length = sizeof(utf8_bom_truncated);
    ok = check_malformed(&input, YAML_READER_ERROR,
            "incomplete UTF-8 octet sequence", 0) && ok;

    return ok;
}

static int
run_nesting_limits(void)
{
    int saved_limit = yaml_get_max_nest_level();
    int ok = 1;

    yaml_set_max_nest_level(64);

    /* Flow collections at the limit (64) are fine, one more is rejected. */
    ok = check_flow_depth(64, 0) && ok;
    ok = check_flow_depth(65, 1) && ok;

    /* Block nesting rejects the level that would exceed the limit. */
    ok = check_block_depth(63, 0) && ok;
    ok = check_block_depth(64, 1) && ok;

    ok = check_bounded_deep_read(saved_limit) && ok;

    if (yaml_get_max_nest_level() != saved_limit)
        ok = CHECK(0, "nesting limit was not restored (%d != %d)",
                yaml_get_max_nest_level(), saved_limit) && ok;

    return ok;
}

int
main(void)
{
    int ok = 1;

    printf("checking chunk boundary invariance on well formed input...\n");
    ok = run_valid_inputs() && ok;

    printf("checking scalars that straddle the reader buffer seam...\n");
    ok = run_boundary_inputs() && ok;

    printf("checking chunk boundary invariance on malformed input...\n");
    ok = run_malformed_inputs() && ok;

    printf("checking nesting limits and bounded reads...\n");
    ok = run_nesting_limits() && ok;

    printf("checking repeated chunking and cleanup after errors...\n");
    ok = check_repeated_and_cleanup() && ok;

    printf("%s: %d failure(s)\n", (ok && !failures) ? "SUCCESS" : "FAILURE",
            failures);

    return (ok && !failures) ? 0 : 1;
}
