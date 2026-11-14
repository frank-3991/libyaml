#include <yaml.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

/*
 * Tests for the configurable recursion/reference budget.
 *
 * The same inputs are exercised through the event API (yaml_parser_parse)
 * and the document API (yaml_parser_load), both as a single in-memory
 * string and through a read handler that delivers the input in fixed-size
 * chunks, so that whole-read and chunked-read results can be compared.
 */

struct chunk_input {
    const unsigned char *data;
    size_t size;
    size_t pos;
    size_t chunk;
};

static int
chunk_read_handler(void *data, unsigned char *buffer, size_t size,
        size_t *size_read)
{
    struct chunk_input *in = (struct chunk_input *)data;
    size_t want = size;
    size_t left = in->size - in->pos;

    if (want > left)
        want = left;
    if (in->chunk && want > in->chunk)
        want = in->chunk;

    if (want)
        memcpy(buffer, in->data + in->pos, want);
    in->pos += want;
    *size_read = want;
    return 1;
}

static void
init_parser(yaml_parser_t *parser, const char *input, size_t length,
        int budget, struct chunk_input *in, size_t chunk)
{
    assert(yaml_parser_initialize(parser));
    yaml_parser_set_recursion_budget(parser, budget);

    if (chunk == 0) {
        yaml_parser_set_input_string(parser,
                (const unsigned char *)input, length);
    }
    else {
        in->data = (const unsigned char *)input;
        in->size = length;
        in->pos = 0;
        in->chunk = chunk;
        yaml_parser_set_input(parser, chunk_read_handler, in);
    }
}

/*
 * Drive the event API until stream end or an error.
 * Returns 1 if the parser reported an error, 0 if the whole stream parsed.
 */

static int
parse_events(const char *input, size_t length, int budget, size_t chunk)
{
    yaml_parser_t parser;
    yaml_event_t event;
    struct chunk_input in;
    int error = 0;

    init_parser(&parser, input, length, budget, &in, chunk);

    for (;;) {
        if (!yaml_parser_parse(&parser, &event)) {
            error = 1;
            break;
        }
        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            break;
        }
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    return error;
}

/*
 * Load the first document using a parser owned by the caller.
 * Returns 1 on error, 0 on success.  The parser stays valid either way so
 * the caller can inspect and delete it.
 */

static int
load_document(const char *input, size_t length, int budget, size_t chunk,
        yaml_parser_t *parser, yaml_document_t *doc)
{
    struct chunk_input in;

    memset(doc, 0, sizeof(*doc));
    init_parser(parser, input, length, budget, &in, chunk);

    if (yaml_parser_load(parser, doc))
        return 0;
    return 1;
}

static void
check_parity(const char *name, const char *input, int budget, int expect_error)
{
    size_t length = strlen(input);
    size_t chunks[] = { 0, 1, 3, 64 };
    size_t i;

    for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i ++) {
        int event_error = parse_events(input, length, budget, chunks[i]);
        yaml_parser_t parser;
        yaml_document_t doc;
        int load_error = load_document(input, length, budget, chunks[i],
                &parser, &doc);

        if (load_error) {
            /* A rejected document must leave no usable root node. */
            assert(yaml_document_get_root_node(&doc) == NULL);
            assert(parser.error != YAML_NO_ERROR);
            assert(parser.problem != NULL);
        }
        else {
            yaml_document_delete(&doc);
        }
        yaml_parser_delete(&parser);

        if (event_error != expect_error || load_error != expect_error) {
            fprintf(stderr, "FAIL %s (chunk=%zu): event=%d load=%d want=%d\n",
                    name, chunks[i], event_error, load_error, expect_error);
            assert(0);
        }
    }

    printf("OK  %-30s budget=%d -> %s (event/load, all chunk sizes)\n",
            name, budget, expect_error ? "rejected" : "accepted");
}

int
main(void)
{
    /* Feature macro is published by the header. */
#ifdef LIBYAML_FEATURE_RECURSION_BUDGET
    printf("LIBYAML_FEATURE_RECURSION_BUDGET defined\n");
#else
    assert(0);
#endif

    /* Getter/setter semantics. */
    {
        yaml_parser_t parser;
        assert(yaml_parser_initialize(&parser));
        assert(yaml_parser_get_recursion_budget(&parser) == 0);
        yaml_parser_set_recursion_budget(&parser, 7);
        assert(yaml_parser_get_recursion_budget(&parser) == 7);
        yaml_parser_set_recursion_budget(&parser, -3);
        assert(yaml_parser_get_recursion_budget(&parser) == 0);
        yaml_parser_set_recursion_budget(&parser, 0);
        assert(yaml_parser_get_recursion_budget(&parser) == 0);
        yaml_parser_delete(&parser);
        printf("OK  getter/setter semantics\n");
    }

    /* 1. Disabled by default: a cyclic document still parses and loads. */
    check_parity("disabled: cyclic alias",
            "a: &a {b: *a}\n", 0, 0);

    /* Disabled by default: the event API keeps its historical tolerance. */
    {
        const char *dup = "x: &k 1\ny: &k 2\n";
        const char *undef = "a: *nope\n";
        size_t chunks[] = { 0, 1, 7 };
        size_t i;

        for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i ++) {
            assert(parse_events(dup, strlen(dup), 0, chunks[i]) == 0);
            assert(parse_events(undef, strlen(undef), 0, chunks[i]) == 0);
        }
        printf("OK  disabled: event API keeps legacy tolerance\n");
    }

    /* 2. Enabled, in budget: shared aliases keep identical node identity. */
    {
        const char *input = "a: &x 1\nb: *x\nc: *x\n";
        yaml_parser_t parser;
        yaml_document_t doc;
        yaml_node_t *anchor_node = NULL;
        int alias_hits = 0;
        yaml_node_t *root;
        yaml_node_pair_t *pair;

        assert(load_document(input, strlen(input), 10, 0,
                    &parser, &doc) == 0);

        root = yaml_document_get_root_node(&doc);
        assert(root && root->type == YAML_MAPPING_NODE);

        /* The anchor node is the value of the "a" key. */
        for (pair = root->data.mapping.pairs.start;
                pair != root->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key = yaml_document_get_node(&doc, pair->key);
            yaml_node_t *value = yaml_document_get_node(&doc, pair->value);
            if (key && key->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "a") == 0)
                anchor_node = value;
        }
        assert(anchor_node != NULL);

        /* Every alias must resolve to the very same node as the anchor. */
        for (pair = root->data.mapping.pairs.start;
                pair != root->data.mapping.pairs.top; pair ++) {
            yaml_node_t *key = yaml_document_get_node(&doc, pair->key);
            yaml_node_t *value = yaml_document_get_node(&doc, pair->value);
            if (key && key->type == YAML_SCALAR_NODE &&
                    strcmp((char *)key->data.scalar.value, "a") != 0) {
                assert(value == anchor_node);
                alias_hits ++;
            }
        }
        assert(alias_hits == 2);

        yaml_document_delete(&doc);
        yaml_parser_delete(&parser);
        printf("OK  shared aliases preserve node identity\n");
    }

    /* 3. Budget overflow from ordinary nesting. */
    check_parity("budget overflow: nesting",
            "[[[[[[[[[]]]]]]]]]\n", 2, 1);

    /* 4. Cyclic alias to an open collection. */
    check_parity("cyclic alias",
            "a: &a {b: *a}\n", 100, 1);

    /* 5. Undefined alias. */
    check_parity("undefined alias",
            "a: *nope\n", 100, 1);

    /* 6. Duplicate anchor. */
    check_parity("duplicate anchor",
            "x: &k 1\ny: &k 2\n", 100, 1);

    /* 7. Alias expansion itself consumes the shared budget. */
    check_parity("budget exhausted by aliases",
            "a: &x 1\nb: *x\nc: *x\nd: *x\n", 1, 1);

    /* 8. Same input with exact headroom stays accepted (boundary check). */
    check_parity("boundary: exact budget",
            "a: &x 1\nb: *x\n", 2, 0);

    /* 9. Each document in a stream receives a fresh budget. */
    {
        const char *input = "---\n- 1\n- 2\n---\n- &a\n  - 1\n  - *a\n";
        yaml_parser_t parser;
        yaml_document_t doc;
        struct chunk_input in;
        int first, second;

        init_parser(&parser, input, strlen(input), 2, &in, 0);

        first = yaml_parser_load(&parser, &doc);
        assert(first);
        assert(yaml_document_get_root_node(&doc) != NULL);
        yaml_document_delete(&doc);

        second = yaml_parser_load(&parser, &doc);
        /* The cyclic second document is rejected, the first was accepted. */
        assert(second == 0);
        assert(parser.error != YAML_NO_ERROR);

        yaml_parser_delete(&parser);
        printf("OK  budget is reset per document\n");
    }

    printf("\nAll recursion budget tests passed.\n");
    return 0;
}
