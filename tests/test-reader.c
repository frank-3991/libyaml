#include <yaml.h>

YAML_DECLARE(int)
yaml_parser_update_buffer(yaml_parser_t *parser, size_t length);

#include <stdlib.h>
#include <stdio.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

/*
 * Test cases are stolen from
 * http://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
 */

typedef struct {
    char *title;
    char *test;
    int result;
} test_case;

test_case utf8_sequences[] = {
    /* {"title", "test 1|test 2|...|test N!", (0 or 1)}, */

    {"a simple test", "'test' is '\xd0\xbf\xd1\x80\xd0\xbe\xd0\xb2\xd0\xb5\xd1\x80\xd0\xba\xd0\xb0' in Russian!", 1},
    {"an empty line", "!", 1},

    {"u-0 is a control character", "\x00!", 0},
    {"u-80 is a control character", "\xc2\x80!", 0},
    {"u-800 is valid", "\xe0\xa0\x80!", 1},
    {"u-10000 is valid", "\xf0\x90\x80\x80!", 1},
    {"5 bytes sequences are not allowed", "\xf8\x88\x80\x80\x80!", 0},
    {"6 bytes sequences are not allowed", "\xfc\x84\x80\x80\x80\x80!", 0},

    {"u-7f is a control character", "\x7f!", 0},
    {"u-7FF is valid", "\xdf\xbf!", 1},
    {"u-FFFF is a control character", "\xef\xbf\xbf!", 0},
    {"u-1FFFFF is too large", "\xf7\xbf\xbf\xbf!", 0},
    {"u-3FFFFFF is 5 bytes", "\xfb\xbf\xbf\xbf\xbf!", 0},
    {"u-7FFFFFFF is 6 bytes", "\xfd\xbf\xbf\xbf\xbf\xbf!", 0},

    {"u-D7FF", "\xed\x9f\xbf!", 1},
    {"u-E000", "\xee\x80\x80!", 1},
    {"u-FFFD", "\xef\xbf\xbd!", 1},
    {"u-10FFFF", "\xf4\x8f\xbf\xbf!", 1},
    {"u-110000", "\xf4\x90\x80\x80!", 0},

    {"first continuation byte", "\x80!", 0},
    {"last continuation byte", "\xbf!", 0},

    {"2 continuation bytes", "\x80\xbf!", 0},
    {"3 continuation bytes", "\x80\xbf\x80!", 0},
    {"4 continuation bytes", "\x80\xbf\x80\xbf!", 0},
    {"5 continuation bytes", "\x80\xbf\x80\xbf\x80!", 0},
    {"6 continuation bytes", "\x80\xbf\x80\xbf\x80\xbf!", 0},
    {"7 continuation bytes", "\x80\xbf\x80\xbf\x80\xbf\x80!", 0},

    {"sequence of all 64 possible continuation bytes",
     "\x80|\x81|\x82|\x83|\x84|\x85|\x86|\x87|\x88|\x89|\x8a|\x8b|\x8c|\x8d|\x8e|\x8f|"
     "\x90|\x91|\x92|\x93|\x94|\x95|\x96|\x97|\x98|\x99|\x9a|\x9b|\x9c|\x9d|\x9e|\x9f|"
     "\xa0|\xa1|\xa2|\xa3|\xa4|\xa5|\xa6|\xa7|\xa8|\xa9|\xaa|\xab|\xac|\xad|\xae|\xaf|"
     "\xb0|\xb1|\xb2|\xb3|\xb4|\xb5|\xb6|\xb7|\xb8|\xb9|\xba|\xbb|\xbc|\xbd|\xbe|\xbf!", 0},
    {"32 first bytes of 2-byte sequences {0xc0-0xdf}",
     "\xc0 |\xc1 |\xc2 |\xc3 |\xc4 |\xc5 |\xc6 |\xc7 |\xc8 |\xc9 |\xca |\xcb |\xcc |\xcd |\xce |\xcf |"
     "\xd0 |\xd1 |\xd2 |\xd3 |\xd4 |\xd5 |\xd6 |\xd7 |\xd8 |\xd9 |\xda |\xdb |\xdc |\xdd |\xde |\xdf !", 0},
    {"16 first bytes of 3-byte sequences {0xe0-0xef}",
     "\xe0 |\xe1 |\xe2 |\xe3 |\xe4 |\xe5 |\xe6 |\xe7 |\xe8 |\xe9 |\xea |\xeb |\xec |\xed |\xee |\xef !", 0},
    {"8 first bytes of 4-byte sequences {0xf0-0xf7}", "\xf0 |\xf1 |\xf2 |\xf3 |\xf4 |\xf5 |\xf6 |\xf7 !", 0},
    {"4 first bytes of 5-byte sequences {0xf8-0xfb}", "\xf8 |\xf9 |\xfa |\xfb !", 0},
    {"2 first bytes of 6-byte sequences {0xfc-0xfd}", "\xfc |\xfd !", 0},

    {"sequences with last byte missing {u-0}",
     "\xc0|\xe0\x80|\xf0\x80\x80|\xf8\x80\x80\x80|\xfc\x80\x80\x80\x80!", 0},
    {"sequences with last byte missing {u-...FF}",
     "\xdf|\xef\xbf|\xf7\xbf\xbf|\xfb\xbf\xbf\xbf|\xfd\xbf\xbf\xbf\xbf!", 0},

    {"impossible bytes", "\xfe|\xff|\xfe\xfe\xff\xff!", 0},

    {"overlong sequences {u-2f}",
     "\xc0\xaf|\xe0\x80\xaf|\xf0\x80\x80\xaf|\xf8\x80\x80\x80\xaf|\xfc\x80\x80\x80\x80\xaf!", 0},

    {"maximum overlong sequences",
     "\xc1\xbf|\xe0\x9f\xbf|\xf0\x8f\xbf\xbf|\xf8\x87\xbf\xbf\xbf|\xfc\x83\xbf\xbf\xbf\xbf!", 0},

    {"overlong representation of the NUL character",
     "\xc0\x80|\xe0\x80\x80|\xf0\x80\x80\x80|\xf8\x80\x80\x80\x80|\xfc\x80\x80\x80\x80\x80!", 0},

    {"single UTF-16 surrogates",
     "\xed\xa0\x80|\xed\xad\xbf|\xed\xae\x80|\xed\xaf\xbf|\xed\xb0\x80|\xed\xbe\x80|\xed\xbf\xbf!", 0},

    {"paired UTF-16 surrogates",
     "\xed\xa0\x80\xed\xb0\x80|\xed\xa0\x80\xed\xbf\xbf|\xed\xad\xbf\xed\xb0\x80|"
     "\xed\xad\xbf\xed\xbf\xbf|\xed\xae\x80\xed\xb0\x80|\xed\xae\x80\xed\xbf\xbf|"
     "\xed\xaf\xbf\xed\xb0\x80|\xed\xaf\xbf\xed\xbf\xbf!", 0},

    {"other illegal code positions", "\xef\xbf\xbe|\xef\xbf\xbf!", 0},

    {NULL, NULL, 0}
};

test_case boms[] = {
    
    /* {"title", "test!", length}, */
    
    {"no bom (utf-8)", "Hi is \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82!", 13},
    {"bom (utf-8)", "\xef\xbb\xbfHi is \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82!", 13},
    {"bom (utf-16-le)", "\xff\xfeH\x00i\x00 \x00i\x00s\x00 \x00\x1f\x04@\x04""8\x04""2\x04""5\x04""B\x04!", 13},
    {"bom (utf-16-be)", "\xfe\xff\x00H\x00i\x00 \x00i\x00s\x00 \x04\x1f\x04@\x04""8\x04""2\x04""5\x04""B!", 13},
    {NULL, NULL, 0}
};

char *bom_original = "Hi is \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82";

int check_utf8_sequences(void)
{
    yaml_parser_t parser;
    int failed = 0;
    int k;
    printf("checking utf-8 sequences...\n");
    for (k = 0; utf8_sequences[k].test; k++) {
        char *title = utf8_sequences[k].title;
        int check = utf8_sequences[k].result;
        int result;
        char *start = utf8_sequences[k].test;
        char *end = start;
        printf("\t%s:\n", title);
        while(1) {
            while (*end != '|' && *end != '!') end++;
            yaml_parser_initialize(&parser);
            yaml_parser_set_input_string(&parser, (unsigned char *)start, end-start);
            result = yaml_parser_update_buffer(&parser, end-start);
            if (result != check) {
                printf("\t\t- ");
                failed ++;
            }
            else {
                printf("\t\t+ ");
            }
            if (!parser.error) {
                printf("(no error)\n");
            }
            else if (parser.error == YAML_READER_ERROR) {
                if (parser.problem_value != -1) {
                    printf("(reader error: %s: #%X at %ld)\n",
                            parser.problem, parser.problem_value, (long)parser.problem_offset);
                }
                else {
                    printf("(reader error: %s at %ld)\n",
                            parser.problem, (long)parser.problem_offset);
                }
            }
            if (*end == '!') break;
            start = ++end;
            yaml_parser_delete(&parser);
        };
        printf("\n");
    }
    printf("checking utf-8 sequences: %d fail(s)\n", failed);
    return failed;
}

int check_boms(void)
{
    yaml_parser_t parser;
    int failed = 0;
    int k;
    printf("checking boms...\n");
    for (k = 0; boms[k].test; k++) {
        char *title = boms[k].title;
        int check = boms[k].result;
        int result;
        char *start = boms[k].test;
        char *end = start;
        while (*end != '!') end++;
        printf("\t%s: ", title);
        yaml_parser_initialize(&parser);
        yaml_parser_set_input_string(&parser, (unsigned char *)start, end-start);
        result = yaml_parser_update_buffer(&parser, end-start);
        if (!result) {
            printf("- (reader error: %s at %ld)\n", parser.problem, (long)parser.problem_offset);
            failed++;
        }
        else {
            if (parser.unread != check) {
                printf("- (length=%ld while expected length=%d)\n", (long)parser.unread, check);
                failed++;
            }
            else if (memcmp(parser.buffer.start, bom_original, check) != 0) {
                printf("- (value '%s' does not equal to the original value '%s')\n", parser.buffer.start, bom_original);
                failed++;
            }
            else {
                printf("+\n");
            }
        }
        yaml_parser_delete(&parser);
    }
    printf("checking boms: %d fail(s)\n", failed);
    return failed;
}

#define LONG    100000

int check_long_utf8(void)
{
    yaml_parser_t parser;
    int k = 0;
    int j;
    int failed = 0;
    unsigned char ch0, ch1;
    unsigned char *buffer = (unsigned char *)malloc(3+LONG*2);
    assert(buffer);
    printf("checking a long utf8 sequence...\n");
    buffer[k++] = '\xef';
    buffer[k++] = '\xbb';
    buffer[k++] = '\xbf';
    for (j = 0; j < LONG; j ++) {
        if (j % 2) {
            buffer[k++] = '\xd0';
            buffer[k++] = '\x90';
        }
        else {
            buffer[k++] = '\xd0';
            buffer[k++] = '\xaf';
        }
    }
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, buffer, 3+LONG*2);
    for (k = 0; k < LONG; k++) {
        if (!parser.unread) {
            if (!yaml_parser_update_buffer(&parser, 1)) {
                printf("\treader error: %s at %ld\n", parser.problem, (long)parser.problem_offset);
                failed = 1;
                break;
            }
        }
        if (!parser.unread) {
            printf("\tnot enough characters at %d\n", k);
            failed = 1;
            break;
        }
        if (k % 2) {
            ch0 = '\xd0';
            ch1 = '\x90';
        }
        else {
            ch0 = '\xd0';
            ch1 = '\xaf';
        }
        if (parser.buffer.pointer[0] != ch0 || parser.buffer.pointer[1] != ch1) {
            printf("\tincorrect UTF-8 sequence: %X %X instead of %X %X\n",
                    (int)parser.buffer.pointer[0], (int)parser.buffer.pointer[1],
                    (int)ch0, (int)ch1);
            failed = 1;
            break;
        }
        parser.buffer.pointer += 2;
        parser.unread -= 1;
    }
    if (!failed) {
        if (!yaml_parser_update_buffer(&parser, 1)) {
            printf("\treader error: %s at %ld\n", parser.problem, (long)parser.problem_offset);
            failed = 1;
        }
        else if (parser.buffer.pointer[0] != '\0') {
            printf("\texpected NUL, found %X (eof=%d, unread=%ld)\n", (int)parser.buffer.pointer[0], parser.eof, (long)parser.unread);
            failed = 1;
        }
    }
    yaml_parser_delete(&parser);
    free(buffer);
    printf("checking a long utf8 sequence: %d fail(s)\n", failed);
    return failed;
}

int check_long_utf16(void)
{
    yaml_parser_t parser;
    int k = 0;
    int j;
    int failed = 0;
    unsigned char ch0, ch1;
    unsigned char *buffer = (unsigned char *)malloc(2+LONG*2);
    assert(buffer);
    printf("checking a long utf16 sequence...\n");
    buffer[k++] = '\xff';
    buffer[k++] = '\xfe';
    for (j = 0; j < LONG; j ++) {
        if (j % 2) {
            buffer[k++] = '\x10';
            buffer[k++] = '\x04';
        }
        else {
            buffer[k++] = '/';
            buffer[k++] = '\x04';
        }
    }
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_string(&parser, buffer, 2+LONG*2);
    for (k = 0; k < LONG; k++) {
        if (!parser.unread) {
            if (!yaml_parser_update_buffer(&parser, 1)) {
                printf("\treader error: %s at %ld\n", parser.problem, (long)parser.problem_offset);
                failed = 1;
                break;
            }
        }
        if (!parser.unread) {
            printf("\tnot enough characters at %d\n", k);
            failed = 1;
            break;
        }
        if (k % 2) {
            ch0 = '\xd0';
            ch1 = '\x90';
        }
        else {
            ch0 = '\xd0';
            ch1 = '\xaf';
        }
        if (parser.buffer.pointer[0] != ch0 || parser.buffer.pointer[1] != ch1) {
            printf("\tincorrect UTF-8 sequence: %X %X instead of %X %X\n",
                    (int)parser.buffer.pointer[0], (int)parser.buffer.pointer[1],
                    (int)ch0, (int)ch1);
            failed = 1;
            break;
        }
        parser.buffer.pointer += 2;
        parser.unread -= 1;
    }
    if (!failed) {
        if (!yaml_parser_update_buffer(&parser, 1)) {
            printf("\treader error: %s at %ld\n", parser.problem, (long)parser.problem_offset);
            failed = 1;
        }
        else if (parser.buffer.pointer[0] != '\0') {
            printf("\texpected NUL, found %X (eof=%d, unread=%ld)\n", (int)parser.buffer.pointer[0], parser.eof, (long)parser.unread);
            failed = 1;
        }
    }
    yaml_parser_delete(&parser);
    free(buffer);
    printf("checking a long utf16 sequence: %d fail(s)\n", failed);
    return failed;
}

/*
 * Chunking independence of the reader diagnostics.
 *
 * The read handler decides how many bytes the parser sees per call, and the
 * input is untrusted: an attacker feeding the parser from a socket picks
 * those boundaries.  The reader converts the whole raw buffer in one pass, so
 * before the fix an invalid byte was reported as soon as the decoder walked
 * over it.  With a large chunk that happened before any event was produced;
 * with a small chunk the events for the preceding characters came out first.
 *
 * These tests drive the same bytes through a handler with many chunk sizes and
 * require the reader diagnostics (category, offset and value) and the number
 * and order of the events produced before them to be identical.  That pins the
 * rejected byte's position to the original input and keeps hostile bytes from
 * being read as a valid document just because they arrived in a big chunk.
 */

typedef struct {
    const unsigned char *data;
    size_t length;
    size_t position;
    size_t chunk;
} chunked_source;

static int
chunked_read_handler(void *data, unsigned char *buffer, size_t size,
        size_t *size_read)
{
    chunked_source *source = (chunked_source *)data;
    size_t remaining = source->length - source->position;

    if (!remaining) {
        *size_read = 0;
        return 1;
    }
    if (size > source->chunk)
        size = source->chunk;
    if (size > remaining)
        size = remaining;

    memcpy(buffer, source->data + source->position, size);
    source->position += size;
    *size_read = size;

    return 1;
}

typedef struct {
    int type;
    int failed;
    char problem[64];
    size_t offset;
    int value;
    size_t event_count;
    int events[32];
} read_outcome;

static void
run_chunked(const unsigned char *data, size_t length, int whole, size_t chunk,
        read_outcome *outcome)
{
    yaml_parser_t parser;
    yaml_event_t event;
    chunked_source source;

    memset(outcome, 0, sizeof(*outcome));
    source.data = data;
    source.length = length;
    source.position = 0;
    source.chunk = chunk;

    assert(yaml_parser_initialize(&parser));
    if (whole)
        yaml_parser_set_input_string(&parser, data, length);
    else
        yaml_parser_set_input(&parser, chunked_read_handler, &source);

    for (;;) {
        if (!yaml_parser_parse(&parser, &event)) {
            outcome->failed = 1;
            outcome->type = parser.error;
            outcome->offset = parser.problem_offset;
            outcome->value = parser.problem_value;
            if (parser.problem) {
                strncpy(outcome->problem, parser.problem,
                        sizeof(outcome->problem) - 1);
                outcome->problem[sizeof(outcome->problem) - 1] = '\0';
            }
            break;
        }
        if (outcome->event_count < 32)
            outcome->events[outcome->event_count] = event.type;
        outcome->event_count++;
        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            break;
        }
        yaml_event_delete(&event);
        if (outcome->event_count > 64) {
            outcome->failed = 1;
            outcome->type = -1;
            break;
        }
    }

    yaml_parser_delete(&parser);
}

static int
check_chunking(const char *title, const unsigned char *data, size_t length,
        int expect_failure)
{
    static const size_t chunks[] = { 1, 2, 3, 4, 5, 7, 13, 64, 16384 };
    read_outcome reference;
    read_outcome current;
    size_t i;
    int failed = 0;

    run_chunked(data, length, 1, 0, &reference);

    if (expect_failure != reference.failed) {
        printf("\t%s: contiguous read %s, expected the opposite\n", title,
                reference.failed ? "failed" : "succeeded");
        return 1;
    }

    for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        size_t j;

        run_chunked(data, length, 0, chunks[i], &current);

        if (current.failed != reference.failed
                || current.type != reference.type
                || current.offset != reference.offset
                || current.value != reference.value
                || strcmp(current.problem, reference.problem)) {
            printf("\t%s: chunk=%lu reported %d '%s' at %lu/#%X, "
                    "contiguous read reported %d '%s' at %lu/#%X\n", title,
                    (unsigned long)chunks[i], current.type, current.problem,
                    (unsigned long)current.offset, current.value,
                    reference.type, reference.problem,
                    (unsigned long)reference.offset, reference.value);
            failed++;
            continue;
        }

        /*
         * The diagnostic must be reached at the same point of the character
         * stream, so the events produced before it must match exactly too.
         * Anything else would mean the invalid byte was reported earlier or
         * later depending on how the bytes happened to be split.
         */
        if (current.event_count != reference.event_count) {
            printf("\t%s: chunk=%lu produced %lu events before the error, "
                    "contiguous read produced %lu\n", title,
                    (unsigned long)chunks[i],
                    (unsigned long)current.event_count,
                    (unsigned long)reference.event_count);
            failed++;
            continue;
        }
        for (j = 0; j < reference.event_count && j < 32; j++) {
            if (current.events[j] != reference.events[j]) {
                printf("\t%s: chunk=%lu event %lu is %d, contiguous read "
                        "has %d\n", title, (unsigned long)chunks[i],
                        (unsigned long)j, current.events[j],
                        reference.events[j]);
                failed++;
                break;
            }
        }
    }

    printf("\t%s: %s\n", title, failed ? "-" : "+");
    return failed;
}

/*
 * A read handler that fails after a fixed number of bytes.  Whatever the chunk
 * size, a failure at byte N must be reported as "input error" and must stay
 * distinguishable from an encoding problem: hostile bytes must not turn an
 * interrupted stream into a parsed one, or the other way round.
 */

typedef struct {
    const unsigned char *data;
    size_t length;
    size_t position;
    size_t chunk;
    size_t failure_position;
} failing_source;

static int
failing_read_handler(void *data, unsigned char *buffer, size_t size,
        size_t *size_read)
{
    failing_source *source = (failing_source *)data;
    size_t remaining;

    if (source->position >= source->failure_position) {
        *size_read = 0;
        return 0;
    }

    remaining = source->length - source->position;
    if (!remaining) {
        *size_read = 0;
        return 1;
    }
    if (size > source->chunk)
        size = source->chunk;
    if (size > remaining)
        size = remaining;
    if (size > source->failure_position - source->position)
        size = source->failure_position - source->position;

    memcpy(buffer, source->data + source->position, size);
    source->position += size;
    *size_read = size;

    return 1;
}

static int
check_handler_failure(const char *title, const unsigned char *data,
        size_t length, size_t failure_position)
{
    static const size_t chunks[] = { 1, 2, 3, 4, 5, 7, 13, 64, 16384 };
    int expected_type = -1;
    size_t expected_events = 0;
    size_t expected_offset = 0;
    size_t i;
    int failed = 0;

    for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
        yaml_parser_t parser;
        yaml_event_t event;
        failing_source source;
        size_t events = 0;
        int type;
        size_t offset;

        source.data = data;
        source.length = length;
        source.position = 0;
        source.chunk = chunks[i];
        source.failure_position = failure_position;

        assert(yaml_parser_initialize(&parser));
        yaml_parser_set_input(&parser, failing_read_handler, &source);

        for (;;) {
            assert(events <= 64);
            if (!yaml_parser_parse(&parser, &event))
                break;
            events++;
            if (event.type == YAML_STREAM_END_EVENT) {
                yaml_event_delete(&event);
                break;
            }
            yaml_event_delete(&event);
        }

        type = parser.error;
        offset = parser.problem_offset;
        yaml_parser_delete(&parser);

        if (!i) {
            expected_type = type;
            expected_events = events;
            expected_offset = offset;
        }
        else if (type != expected_type || events != expected_events
                || offset != expected_offset) {
            printf("\t%s: chunk=%lu reported type %d at offset %lu after %lu "
                    "events, chunk=1 reported type %d at offset %lu after %lu "
                    "events\n", title, (unsigned long)chunks[i], type,
                    (unsigned long)offset, (unsigned long)events,
                    expected_type, (unsigned long)expected_offset,
                    (unsigned long)expected_events);
            failed++;
        }
    }

    /*
     * The failure must be an "input error", never an encoding diagnostic: an
     * interrupted stream is not the same thing as malformed bytes.
     */
    if (expected_type != YAML_READER_ERROR) {
        printf("\t%s: interrupted input reported error type %d\n", title,
                expected_type);
        failed++;
    }

    printf("\t%s: %s\n", title, failed ? "-" : "+");
    return failed;
}

int check_interrupted_input(void)
{
    static const unsigned char valid[] = "a: caf\xc3\xa9\nb: [1, 2]\n";
    static const unsigned char with_bad_byte[] = "a: caf\xc3\xa9\nb: \xff\n";
    int failed = 0;

    printf("checking interrupted input diagnostics...\n");

    failed += check_handler_failure("interrupted before any byte", valid,
            sizeof(valid) - 1, 0);
    failed += check_handler_failure("interrupted inside a multibyte character",
            valid, sizeof(valid) - 1, 9);
    failed += check_handler_failure("interrupted in the last line", valid,
            sizeof(valid) - 1, sizeof(valid) - 3);
    failed += check_handler_failure("interrupted before the invalid byte",
            with_bad_byte, sizeof(with_bad_byte) - 1, 12);
    failed += check_handler_failure("interrupted at the invalid byte",
            with_bad_byte, sizeof(with_bad_byte) - 1, 13);

    printf("checking interrupted input diagnostics: %d fail(s)\n", failed);
    return failed;
}

int check_chunked_diagnostics(void)
{
    static const unsigned char valid[] = "a: caf\xc3\xa9 \xe6\x97\xa5\n";
    static const unsigned char split_2[] = "a: \xd0\xbf\xd1\x80\n";
    static const unsigned char split_4[] = "a: \xf0\x9f\x98\x80\n";
    static const unsigned char bom_valid[] =
        "\xef\xbb\xbf" "a: \xe6\x97\xa5\n";
    static const unsigned char bom_bad_cont[] =
        "\xef\xbb\xbf" "a: \xe0\xa0\x41\n";
    static const unsigned char bom_truncated[] =
        "\xef\xbb\xbf" "a: \xe0\xa0";
    static const unsigned char bad_cont_near_valid[] =
        "a: b\xc3\xa9\xe0\xa0\x41\n";
    static const unsigned char bad_lead_near_valid[] = "a: b\xff\n";
    static const unsigned char doc_then_bad[] = "a: b\n\xff";
    static const unsigned char docs_then_bad[] =
        "a: b\n---\nc: d\n---\ne: \xff";
    static const unsigned char utf16_valid[] =
        "\xff\xfe" "H\x00i\x00 \x00x\x00";
    static const unsigned char utf16_truncated[] = "\xff\xfe" "H";
    static const unsigned char utf16_bad_surrogate[] = "\xff\xfe\x00\xdc";
    int failed = 0;

    printf("checking chunked reader diagnostics...\n");

    failed += check_chunking("valid utf-8", valid, sizeof(valid) - 1, 0);
    failed += check_chunking("split 2-byte character", split_2,
            sizeof(split_2) - 1, 0);
    failed += check_chunking("split 4-byte character", split_4,
            sizeof(split_4) - 1, 0);
    failed += check_chunking("bom at stream head", bom_valid,
            sizeof(bom_valid) - 1, 0);
    failed += check_chunking("bom plus invalid continuation", bom_bad_cont,
            sizeof(bom_bad_cont) - 1, 1);
    failed += check_chunking("bom plus truncated character", bom_truncated,
            sizeof(bom_truncated) - 1, 1);
    failed += check_chunking("invalid continuation after valid characters",
            bad_cont_near_valid, sizeof(bad_cont_near_valid) - 1, 1);
    failed += check_chunking("invalid lead byte after valid characters",
            bad_lead_near_valid, sizeof(bad_lead_near_valid) - 1, 1);
    failed += check_chunking("one document then an invalid byte", doc_then_bad,
            sizeof(doc_then_bad) - 1, 1);
    failed += check_chunking("two documents then an invalid byte",
            docs_then_bad, sizeof(docs_then_bad) - 1, 1);
    failed += check_chunking("valid utf-16", utf16_valid,
            sizeof(utf16_valid) - 1, 0);
    failed += check_chunking("truncated utf-16", utf16_truncated,
            sizeof(utf16_truncated) - 1, 1);
    failed += check_chunking("invalid utf-16 surrogate", utf16_bad_surrogate,
            sizeof(utf16_bad_surrogate) - 1, 1);

    printf("checking chunked reader diagnostics: %d fail(s)\n", failed);
    return failed;
}

int
main(void)
{
    return check_utf8_sequences() + check_boms() + check_long_utf8()
        + check_long_utf16() + check_chunked_diagnostics()
        + check_interrupted_input();
}
