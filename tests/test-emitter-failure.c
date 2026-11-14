#include <yaml.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

/*
 * Tests for the emitter's behaviour when the write handler fails.
 *
 * A failed write means the output is an incomplete prefix of the intended
 * stream.  The emitter must therefore:
 *   - report the failure to the caller and never report success afterwards;
 *   - stop writing characters;
 *   - drop every event it owns without double-freeing or leaking, even if
 *     events are re-submitted or the emitter is destroyed afterwards;
 *   - keep producing identical bytes for documents that are written
 *     successfully, in UTF-8 and UTF-16.
 */

/*
 * A write sink that can be told to fail after a number of successful calls.
 * It records everything it accepted so the produced bytes can be inspected.
 */

#define SINK_CAPACITY 65536

typedef struct {
    unsigned char data[SINK_CAPACITY];
    size_t size;
    int calls;
    int fail_from;      /* fail when calls >= fail_from; -1 means never */
} sink_t;

static void
sink_init(sink_t *sink, int fail_from)
{
    memset(sink, 0, sizeof(*sink));
    sink->fail_from = fail_from;
}

static int
sink_write(void *data, unsigned char *buffer, size_t size)
{
    sink_t *sink = (sink_t *)data;

    if (sink->fail_from >= 0 && sink->calls >= sink->fail_from) {
        sink->calls ++;
        return 0;
    }
    if (sink->size + size > SINK_CAPACITY) {
        sink->calls ++;
        return 0;
    }

    memcpy(sink->data + sink->size, buffer, size);
    sink->size += size;
    sink->calls ++;

    return 1;
}

/*
 * Emit a two-document stream into the given sink.
 *
 * Returns the result of every step so a test can assert on it.
 */

typedef struct {
    int stream_start;
    int first_doc_start;
    int first_scalar;
    int first_doc_end;
    int second_doc_start;
    int sequence_start;
    int sequence_items;
    int sequence_end;
    int second_doc_end;
    int stream_end;
} results_t;

static void
emit_two_documents(yaml_emitter_t *emitter, sink_t *sink, results_t *results)
{
    yaml_event_t event;
    yaml_char_t *payload;

    memset(results, 0, sizeof(*results));

    /* A payload large enough to make the emitter flush in the middle. */

    payload = (yaml_char_t *)malloc(40000);
    assert(payload);
    memset(payload, 'a', 39999);
    payload[39999] = '\0';

    assert(yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING));
    results->stream_start = yaml_emitter_emit(emitter, &event);

    assert(yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1));
    results->first_doc_start = yaml_emitter_emit(emitter, &event);

    assert(yaml_scalar_event_initialize(&event, NULL, NULL, payload, -1,
                1, 1, YAML_PLAIN_SCALAR_STYLE));
    results->first_scalar = yaml_emitter_emit(emitter, &event);

    assert(yaml_document_end_event_initialize(&event, 1));
    results->first_doc_end = yaml_emitter_emit(emitter, &event);

    assert(yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1));
    results->second_doc_start = yaml_emitter_emit(emitter, &event);

    assert(yaml_sequence_start_event_initialize(&event, NULL, NULL, 1,
                YAML_BLOCK_SEQUENCE_STYLE));
    results->sequence_start = yaml_emitter_emit(emitter, &event);

    assert(yaml_scalar_event_initialize(&event, NULL, NULL,
                (yaml_char_t *)"beta", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE));
    results->sequence_items = yaml_emitter_emit(emitter, &event);

    assert(yaml_sequence_end_event_initialize(&event));
    results->sequence_end = yaml_emitter_emit(emitter, &event);

    assert(yaml_document_end_event_initialize(&event, 1));
    results->second_doc_end = yaml_emitter_emit(emitter, &event);

    assert(yaml_stream_end_event_initialize(&event));
    results->stream_end = yaml_emitter_emit(emitter, &event);

    free(payload);
    (void)sink;
}

/*
 * Return the index of the first step that reported failure, or -1 if the
 * whole stream was emitted successfully.
 */

static int
first_failing_step(results_t *results)
{
    int steps[10];
    int step;

    steps[0] = results->stream_start;
    steps[1] = results->first_doc_start;
    steps[2] = results->first_scalar;
    steps[3] = results->first_doc_end;
    steps[4] = results->second_doc_start;
    steps[5] = results->sequence_start;
    steps[6] = results->sequence_items;
    steps[7] = results->sequence_end;
    steps[8] = results->second_doc_end;
    steps[9] = results->stream_end;

    for (step = 0; step < 10; step ++) {
        if (!steps[step])
            return step;
    }

    return -1;
}

/*
 * Assert that every step from the first failure on reports failure, and that
 * no further characters were written beyond what had already been accepted.
 */

static void
check_failure_is_final(results_t *results, sink_t *sink)
{
    size_t size_after_failure;
    int step;

    step = first_failing_step(results);
    assert(step >= 0);

    size_after_failure = sink->size;

    for (; step < 10; step ++) {
        int result = 0;
        switch (step) {
            case 0: result = results->stream_start; break;
            case 1: result = results->first_doc_start; break;
            case 2: result = results->first_scalar; break;
            case 3: result = results->first_doc_end; break;
            case 4: result = results->second_doc_start; break;
            case 5: result = results->sequence_start; break;
            case 6: result = results->sequence_items; break;
            case 7: result = results->sequence_end; break;
            case 8: result = results->second_doc_end; break;
            case 9: result = results->stream_end; break;
            default: assert(0);
        }
        assert(!result);
    }

    assert(sink->size == size_after_failure);
}

/*
 * Test 1: the write handler fails on the very first flush.
 */

static void
test_failure_on_first_write(void)
{
    yaml_emitter_t emitter;
    sink_t sink;
    results_t results;
    yaml_event_t event;

    printf("Test 1: write fails on the first flush ... ");
    fflush(stdout);

    sink_init(&sink, 0);
    assert(yaml_emitter_initialize(&emitter));
    yaml_emitter_set_output(&emitter, sink_write, &sink);

    emit_two_documents(&emitter, &sink, &results);

    assert(results.stream_start);
    assert(results.first_doc_start);
    check_failure_is_final(&results, &sink);
    assert(sink.size == 0);
    assert(emitter.error == YAML_WRITER_ERROR);

    /* Even a valid new stream is refused; the event is still consumed. */

    assert(yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1));
    assert(!yaml_emitter_emit(&emitter, &event));
    assert(sink.size == 0);

    /* Flushing must not pretend the stream is complete. */

    assert(!yaml_emitter_flush(&emitter));
    assert(sink.size == 0);

    yaml_emitter_delete(&emitter);

    printf("OK\n");
}

/*
 * Test 2: the write handler fails after some output was already accepted.
 */

static void
test_failure_after_partial_output(void)
{
    yaml_emitter_t emitter;
    sink_t sink;
    results_t results;
    size_t written_before_failure;

    printf("Test 2: write fails after partial output ... ");
    fflush(stdout);

    sink_init(&sink, 1);
    assert(yaml_emitter_initialize(&emitter));
    yaml_emitter_set_output(&emitter, sink_write, &sink);

    emit_two_documents(&emitter, &sink, &results);

    assert(results.stream_start);
    assert(results.first_doc_start);

    written_before_failure = sink.size;
    assert(written_before_failure > 0);
    assert(written_before_failure < SINK_CAPACITY);
    check_failure_is_final(&results, &sink);

    /* A partial prefix must never be reported as a complete stream. */

    assert(sink.size != 25);
    assert(emitter.error == YAML_WRITER_ERROR);

    assert(!yaml_emitter_flush(&emitter));
    assert(sink.size == written_before_failure);

    yaml_emitter_delete(&emitter);

    printf("OK\n");
}

/*
 * Test 3: events submitted after a failure are neither replayed nor leaked.
 */

static void
test_no_replay_after_failure(void)
{
    yaml_emitter_t emitter;
    sink_t sink;
    yaml_event_t event;
    int k;

    printf("Test 3: no event replay after a failure ... ");
    fflush(stdout);

    sink_init(&sink, 0);
    assert(yaml_emitter_initialize(&emitter));
    yaml_emitter_set_output(&emitter, sink_write, &sink);

    assert(yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING));
    assert(yaml_emitter_emit(&emitter, &event));

    assert(yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1));
    assert(yaml_emitter_emit(&emitter, &event));

    /*
     * Force the failure with events that own allocated memory, so an early
     * free, a double free or a leak would show up under a memory checker.
     * Several events are queued because the emitter accumulates them before
     * writing a document, so the failure happens with a non-empty queue.
     */

    for (k = 0; k < 16; k ++) {
        assert(yaml_scalar_event_initialize(&event, (yaml_char_t *)"anchor",
                    (yaml_char_t *)"!tag", (yaml_char_t *)"value", -1, 1, 1,
                    YAML_PLAIN_SCALAR_STYLE));
        (void)yaml_emitter_emit(&emitter, &event);
    }
    assert(emitter.error != 0);

    /* Re-submitting every kind of event must fail and free the event. */

    for (k = 0; k < 4; k ++) {
        yaml_event_t zeroed;
        memset(&zeroed, 0, sizeof(zeroed));

        switch (k) {
            case 0:
                assert(yaml_document_start_event_initialize(&event, NULL,
                            NULL, NULL, 1));
                break;
            case 1:
                assert(yaml_sequence_start_event_initialize(&event,
                            (yaml_char_t *)"anchor", (yaml_char_t *)"!tag", 0,
                            YAML_BLOCK_SEQUENCE_STYLE));
                break;
            case 2:
                assert(yaml_scalar_event_initialize(&event,
                            (yaml_char_t *)"anchor", (yaml_char_t *)"!tag",
                            (yaml_char_t *)"value", -1, 0, 0,
                            YAML_PLAIN_SCALAR_STYLE));
                break;
            default:
                assert(yaml_alias_event_initialize(&event,
                            (yaml_char_t *)"anchor"));
                break;
        }
        assert(yaml_emitter_emit(&emitter, &event) == 0);
        /* The emitter has released the event: its contents are cleared. */
        assert(memcmp(&event, &zeroed, sizeof(event)) == 0);
        yaml_event_delete(&event);
    }

    yaml_emitter_delete(&emitter);

    /*
     * Releasing the terminal state twice (or after other calls) must not free
     * anything a second time; this run is meant to be checked with a memory
     * checker.
     */

    sink_init(&sink, 0);
    assert(yaml_emitter_initialize(&emitter));
    yaml_emitter_set_output(&emitter, sink_write, &sink);
    assert(yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING));
    assert(yaml_emitter_emit(&emitter, &event));
    assert(yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1));
    assert(yaml_emitter_emit(&emitter, &event));
    {
        yaml_char_t *payload = (yaml_char_t *)malloc(40000);
        int j;

        assert(payload);
        memset(payload, 'a', 39999);
        payload[39999] = '\0';

        for (j = 0; j < 8; j ++) {
            assert(yaml_sequence_start_event_initialize(&event,
                        (yaml_char_t *)"anchor", (yaml_char_t *)"!tag", 0,
                        YAML_BLOCK_SEQUENCE_STYLE));
            (void)yaml_emitter_emit(&emitter, &event);
            assert(yaml_scalar_event_initialize(&event, NULL, NULL, payload,
                        -1, 1, 1, YAML_PLAIN_SCALAR_STYLE));
            (void)yaml_emitter_emit(&emitter, &event);
        }

        free(payload);
    }
    assert(emitter.error != 0);
    assert(!yaml_emitter_flush(&emitter));
    yaml_emitter_delete(&emitter);

    /* Creating a fresh emitter must produce a complete document again. */

    sink_init(&sink, -1);
    assert(yaml_emitter_initialize(&emitter));
    yaml_emitter_set_output(&emitter, sink_write, &sink);
    assert(yaml_emitter_open(&emitter));
    {
        yaml_document_t document;
        assert(yaml_document_initialize(&document, NULL, NULL, NULL, 1, 1));
        assert(yaml_document_add_scalar(&document, NULL,
                    (yaml_char_t *)"value", -1, YAML_PLAIN_SCALAR_STYLE));
        assert(yaml_emitter_dump(&emitter, &document));
    }
    assert(yaml_emitter_close(&emitter));
    assert(sink.size == strlen("value\n"));
    assert(memcmp(sink.data, "value\n", sink.size) == 0);
    yaml_emitter_delete(&emitter);

    printf("OK\n");
}

/*
 * Test 4: the dumper API reports failure and keeps its ownership promises.
 */

static void
test_dump_failure(void)
{
    yaml_emitter_t emitter;
    sink_t sink;
    yaml_document_t document;
    yaml_document_t another_document;
    yaml_char_t *payload;
    int root, key, value;

    printf("Test 4: dump reports failure and stays terminal ... ");
    fflush(stdout);

    payload = (yaml_char_t *)malloc(40000);
    assert(payload);
    memset(payload, 'a', 39999);
    payload[39999] = '\0';

    sink_init(&sink, 1);
    assert(yaml_emitter_initialize(&emitter));
    yaml_emitter_set_output(&emitter, sink_write, &sink);

    assert(yaml_document_initialize(&document, NULL, NULL, NULL, 1, 1));
    root = yaml_document_add_mapping(&document, NULL, YAML_BLOCK_MAPPING_STYLE);
    key = yaml_document_add_scalar(&document, NULL, (yaml_char_t *)"key", -1,
            YAML_PLAIN_SCALAR_STYLE);
    value = yaml_document_add_scalar(&document, NULL, payload, -1,
            YAML_PLAIN_SCALAR_STYLE);
    assert(root && key && value);
    assert(yaml_document_append_mapping_pair(&document, root, key, value));

    /* The document is consumed whether the dump succeeds or fails. */

    assert(!yaml_emitter_dump(&emitter, &document));
    assert(emitter.error == YAML_WRITER_ERROR);
    yaml_document_delete(&document);

    assert(!yaml_emitter_close(&emitter));

    /* A second document is swallowed and dropped without touching output. */

    {
        size_t size_before = sink.size;
        assert(yaml_document_initialize(&another_document, NULL, NULL, NULL,
                    1, 1));
        assert(yaml_document_add_scalar(&another_document, NULL,
                    (yaml_char_t *)"other", -1, YAML_PLAIN_SCALAR_STYLE));
        assert(!yaml_emitter_dump(&emitter, &another_document));
        assert(sink.size == size_before);
    }

    yaml_emitter_delete(&emitter);
    free(payload);

    printf("OK\n");
}

/*
 * Test 5: successful output is unchanged, byte for byte, in every encoding.
 */

static const unsigned char expected_utf8[] = {
    0x61, 0x6C, 0x70, 0x68, 0x61, 0x0A, 0x2D, 0x2D, 0x2D, 0x0A, 0x2D, 0x20,
    0x62, 0x65, 0x74, 0x61, 0x0A, 0x2D, 0x20, 0x67, 0x61, 0x6D, 0x6D, 0x61,
    0x0A
};

static const unsigned char expected_utf16le[] = {
    0xFF, 0xFE, 0x61, 0x00, 0x6C, 0x00, 0x70, 0x00, 0x68, 0x00, 0x61, 0x00,
    0x0A, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x0A, 0x00, 0x2D, 0x00,
    0x20, 0x00, 0x62, 0x00, 0x65, 0x00, 0x74, 0x00, 0x61, 0x00, 0x0A, 0x00,
    0x2D, 0x00, 0x20, 0x00, 0x67, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x6D, 0x00,
    0x61, 0x00, 0x0A, 0x00
};

static const unsigned char expected_utf16be[] = {
    0xFE, 0xFF, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x70, 0x00, 0x68, 0x00, 0x61,
    0x00, 0x0A, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x2D, 0x00, 0x0A, 0x00, 0x2D,
    0x00, 0x20, 0x00, 0x62, 0x00, 0x65, 0x00, 0x74, 0x00, 0x61, 0x00, 0x0A,
    0x00, 0x2D, 0x00, 0x20, 0x00, 0x67, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x6D,
    0x00, 0x61, 0x00, 0x0A
};

static void
check_encoding(yaml_encoding_t encoding, const unsigned char *expected,
        size_t expected_size)
{
    yaml_emitter_t emitter;
    yaml_event_t event;
    unsigned char buffer[256];
    size_t written = 0;

    memset(buffer, 0, sizeof(buffer));
    assert(yaml_emitter_initialize(&emitter));
    yaml_emitter_set_encoding(&emitter, encoding);
    yaml_emitter_set_output_string(&emitter, buffer, sizeof(buffer), &written);

    assert(yaml_stream_start_event_initialize(&event, encoding));
    assert(yaml_emitter_emit(&emitter, &event));

    assert(yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1));
    assert(yaml_emitter_emit(&emitter, &event));
    assert(yaml_scalar_event_initialize(&event, NULL, NULL,
                (yaml_char_t *)"alpha", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE));
    assert(yaml_emitter_emit(&emitter, &event));
    assert(yaml_document_end_event_initialize(&event, 1));
    assert(yaml_emitter_emit(&emitter, &event));

    assert(yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1));
    assert(yaml_emitter_emit(&emitter, &event));
    assert(yaml_sequence_start_event_initialize(&event, NULL, NULL, 1,
                YAML_BLOCK_SEQUENCE_STYLE));
    assert(yaml_emitter_emit(&emitter, &event));
    assert(yaml_scalar_event_initialize(&event, NULL, NULL,
                (yaml_char_t *)"beta", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE));
    assert(yaml_emitter_emit(&emitter, &event));
    assert(yaml_scalar_event_initialize(&event, NULL, NULL,
                (yaml_char_t *)"gamma", -1, 1, 1, YAML_PLAIN_SCALAR_STYLE));
    assert(yaml_emitter_emit(&emitter, &event));
    assert(yaml_sequence_end_event_initialize(&event));
    assert(yaml_emitter_emit(&emitter, &event));
    assert(yaml_document_end_event_initialize(&event, 1));
    assert(yaml_emitter_emit(&emitter, &event));

    assert(yaml_stream_end_event_initialize(&event));
    assert(yaml_emitter_emit(&emitter, &event));

    assert(written == expected_size);
    assert(memcmp(buffer, expected, expected_size) == 0);

    yaml_emitter_delete(&emitter);
}

static void
test_successful_output_unchanged(void)
{
    printf("Test 5: multi-document output unchanged for UTF-8/UTF-16 ... ");
    fflush(stdout);

    check_encoding(YAML_UTF8_ENCODING, expected_utf8, sizeof(expected_utf8));
    check_encoding(YAML_UTF16LE_ENCODING, expected_utf16le,
            sizeof(expected_utf16le));
    check_encoding(YAML_UTF16BE_ENCODING, expected_utf16be,
            sizeof(expected_utf16be));

    printf("OK\n");
}

int
main(void)
{
    test_failure_on_first_write();
    test_failure_after_partial_output();
    test_no_replay_after_failure();
    test_dump_failure();
    test_successful_output_unchanged();

    return 0;
}
