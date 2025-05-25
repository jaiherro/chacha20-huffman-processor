/**
 * test_file_list.c - File list management tests
 */

#include "test_utils.h"
#include "utils/file_list.h"
#include <stdlib.h>
#include <string.h>

#define TEST_FILE_LIST "test_list.dat"

/* Test basic file list operations */
static int test_file_list_basic(void)
{
    printf("  - Basic operations... ");

    file_list_t   list;
    file_entry_t *entry;

    /* Initialise */
    ASSERT_EQUAL(file_list_init(&list), 0, "Init failed");
    ASSERT_EQUAL(list.count, 0, "Initial count should be 0"); /* Add entries */
    ASSERT_EQUAL(file_list_add(&list, "input1.txt", "file1.txt", 1000, 500), 0,
                 "Add 1 failed");
    ASSERT_EQUAL(file_list_add(&list, "input2.txt", "file2.doc", 2000, 1800), 0,
                 "Add 2 failed");
    ASSERT_EQUAL(list.count, 2, "Count should be 2");

    /* Find entry */
    entry = file_list_find(&list, "file1");
    ASSERT_TRUE(entry != NULL, "Should find file1");
    ASSERT_EQUAL(entry->original_size, 1000, "Original size mismatch");
    ASSERT_EQUAL(entry->processed_size, 500, "Processed size mismatch");

    /* Find non-existent */
    entry = file_list_find(&list, "notexist");
    ASSERT_TRUE(entry == NULL, "Should not find non-existent file");

    file_list_free(&list);
    printf("PASS\n");
    return TEST_PASS;
}

/* Test save and load */
static int test_file_list_persistence(void)
{
    printf("  - Save/load persistence... ");

    file_list_t   list1, list2;
    file_entry_t *entry; /* Create and populate list */
    file_list_init(&list1);
    file_list_add(&list1, "input1.txt", "test1.bin", 5000, 4500);
    file_list_add(&list1, "input2.txt", "test2.jpg", 10000, 9500);
    file_list_add(&list1, "input3.txt", "test3.pdf", 20000, 18000);

    /* Save */
    ASSERT_EQUAL(file_list_save(&list1, TEST_FILE_LIST), 0, "Save failed");

    /* Load into new list */
    file_list_init(&list2);
    ASSERT_EQUAL(file_list_load(&list2, TEST_FILE_LIST), 0, "Load failed");

    /* Verify loaded data */
    ASSERT_EQUAL(list2.count, 3, "Loaded count mismatch");

    entry = file_list_find(&list2, "test2");
    ASSERT_TRUE(entry != NULL, "Should find test2 after load");
    ASSERT_EQUAL(entry->original_size, 10000, "Loaded size mismatch");

    file_list_free(&list1);
    file_list_free(&list2);

    /* Clean up test file */
    remove(TEST_FILE_LIST);

    printf("PASS\n");
    return TEST_PASS;
}

/* Test get recent entries */
static int test_file_list_recent(void)
{
    printf("  - Get recent entries... ");

    file_list_t   list;
    file_entry_t *recent[3];
    unsigned long count;

    file_list_init(&list); /* Add entries in sequence */
    file_list_add(&list, "input_old.txt", "old.txt", 100, 90);
    file_list_add(&list, "input_medium.txt", "medium.txt", 200, 180);
    file_list_add(&list, "input_new.txt", "new.txt", 300, 270);
    file_list_add(&list, "input_newest.txt", "newest.txt", 400, 360);

    /* Get 3 most recent */
    count = file_list_get_recent(&list, 3, recent);
    ASSERT_EQUAL(count, 3, "Should get 3 recent entries");

    /* Verify order (most recent first) */
    ASSERT_TRUE(strcmp(recent[0]->output_filename, "newest.txt") == 0,
                "First should be newest");
    ASSERT_TRUE(strcmp(recent[1]->output_filename, "new.txt") == 0,
                "Second should be new");
    ASSERT_TRUE(strcmp(recent[2]->output_filename, "medium.txt") == 0,
                "Third should be medium");

    file_list_free(&list);
    printf("PASS\n");
    return TEST_PASS;
}

int run_file_list_tests(void)
{
    printf("\n--- File List Tests ---\n");

    if (test_file_list_basic() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_persistence() != TEST_PASS)
        return TEST_FAIL;
    if (test_file_list_recent() != TEST_PASS)
        return TEST_FAIL;

    printf("File list tests: ALL PASSED\n");
    return TEST_PASS;
}