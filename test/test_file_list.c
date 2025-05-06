#include "utils/file_list.h"
#include "test_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h> // For remove()

#define TEST_LIST_FILENAME "test_list.dat"

// Helper to clean up test file
static void cleanup_test_file(void) {
    remove(TEST_LIST_FILENAME);
}

// Test case 1: Initialize and free an empty list
static int test_fl_init_free(void) {
    file_list_t list;
    int result = file_list_init(&list);
    ASSERT_EQUAL_INT(0, result, "file_list_init failed");
    ASSERT_EQUAL_INT(0, list.count, "Initial count should be 0");
    ASSERT_NULL(list.head, "Initial head should be NULL");
    ASSERT_NULL(list.tail, "Initial tail should be NULL");
    ASSERT_EQUAL_INT(1, list.next_sequence_num, "Initial sequence number should be 1");

    file_list_free(&list);
    // Check again after free (should be same as initial state)
    ASSERT_EQUAL_INT(0, list.count, "Count after free should be 0");
    ASSERT_NULL(list.head, "Head after free should be NULL");
    ASSERT_NULL(list.tail, "Tail after free should be NULL");
    ASSERT_EQUAL_INT(1, list.next_sequence_num, "Sequence number after free should be 1");

    return 1; // Success
}

// Test case 2: Add entries to the list
static int test_fl_add(void) {
    file_list_t list;
    file_list_init(&list);

    int result = file_list_add(&list, "file1.txt", 100, 50);
    ASSERT_EQUAL_INT(0, result, "file_list_add (1) failed");
    ASSERT_EQUAL_INT(1, list.count, "Count should be 1 after first add");
    ASSERT_NOT_NULL(list.head, "Head should not be NULL after add");
    ASSERT_NOT_NULL(list.tail, "Tail should not be NULL after add");
    ASSERT_EQUAL_INT(1, list.head->sequence_num, "First sequence number should be 1");
    ASSERT_EQUAL_INT(2, list.next_sequence_num, "Next sequence number should be 2");
    ASSERT_EQUAL_INT(0, strcmp(list.head->filename, "file1.txt"), "Filename mismatch (1)");
    ASSERT_EQUAL_INT(100, list.head->original_size, "Original size mismatch (1)");
    ASSERT_EQUAL_INT(50, list.head->processed_size, "Processed size mismatch (1)");
    ASSERT_EQUAL_INT(list.head, list.tail, "Head and tail should be same for single element");

    result = file_list_add(&list, "file2.log", 2000, 1500);
    ASSERT_EQUAL_INT(0, result, "file_list_add (2) failed");
    ASSERT_EQUAL_INT(2, list.count, "Count should be 2 after second add");
    ASSERT_NOT_NULL(list.tail, "Tail should not be NULL");
    ASSERT_EQUAL_INT(2, list.tail->sequence_num, "Second sequence number should be 2");
    ASSERT_EQUAL_INT(3, list.next_sequence_num, "Next sequence number should be 3");
    ASSERT_EQUAL_INT(0, strcmp(list.tail->filename, "file2.log"), "Filename mismatch (2)");
    ASSERT_NOT_EQUAL_INT(list.head, list.tail, "Head and tail should differ for two elements");
    ASSERT_EQUAL_INT(list.tail, list.head->next, "Second element not linked correctly");

    file_list_free(&list);
    return 1; // Success
}

// Test case 3: Find entries in the list
static int test_fl_find(void) {
    file_list_t list;
    file_list_init(&list);
    file_list_add(&list, "document_final_v2.txt", 1024, 512);
    file_list_add(&list, "image.jpg", 4096, 4000);
    file_list_add(&list, "archive.zip", 10000, 8000);

    file_entry_t *found;

    // Find exact match
    found = file_list_find(&list, "image.jpg");
    ASSERT_NOT_NULL(found, "Failed to find exact match 'image.jpg'");
    ASSERT_EQUAL_INT(0, strcmp(found->filename, "image.jpg"), "Found wrong file for exact match");

    // Find partial match
    found = file_list_find(&list, "final_v2");
    ASSERT_NOT_NULL(found, "Failed to find partial match 'final_v2'");
    ASSERT_EQUAL_INT(0, strcmp(found->filename, "document_final_v2.txt"), "Found wrong file for partial match");

    // Find case-sensitive match (should work if strstr is case-sensitive)
    found = file_list_find(&list, "Archive"); // Assuming case-sensitive
    ASSERT_NULL(found, "Should not find case-insensitive match 'Archive'");

    // Find non-existent file
    found = file_list_find(&list, "nonexistent.dat");
    ASSERT_NULL(found, "Should not find non-existent file");

    file_list_free(&list);
    return 1; // Success
}


// Test case 4: Save and load the list
static int test_fl_save_load(void) {
    cleanup_test_file(); // Ensure no old file exists
    file_list_t list_save;
    file_list_init(&list_save);
    file_list_add(&list_save, "save_test1.bin", 1, 1);
    file_list_add(&list_save, "save_test2.tmp", 9999, 5555);
    ASSERT_EQUAL_INT(3, list_save.next_sequence_num, "Sequence number before save mismatch");

    // Save the list
    int result = file_list_save(&list_save, TEST_LIST_FILENAME);
    ASSERT_EQUAL_INT(0, result, "file_list_save failed");

    // Load the list into a new structure
    file_list_t list_load;
    file_list_init(&list_load); // Initialize before load
    result = file_list_load(&list_load, TEST_LIST_FILENAME);
    ASSERT_EQUAL_INT(0, result, "file_list_load failed");

    // Verify loaded list
    ASSERT_EQUAL_INT(list_save.count, list_load.count, "Loaded count mismatch");
    ASSERT_EQUAL_INT(list_save.next_sequence_num, list_load.next_sequence_num, "Loaded sequence number mismatch");
    ASSERT_NOT_NULL(list_load.head, "Loaded head is NULL");
    ASSERT_NOT_NULL(list_load.tail, "Loaded tail is NULL");

    // Check first element
    ASSERT_EQUAL_INT(0, strcmp(list_load.head->filename, "save_test1.bin"), "Loaded filename (1) mismatch");
    ASSERT_EQUAL_INT(1, list_load.head->sequence_num, "Loaded sequence num (1) mismatch");
    ASSERT_EQUAL_INT(1, list_load.head->original_size, "Loaded original size (1) mismatch");
    ASSERT_EQUAL_INT(1, list_load.head->processed_size, "Loaded processed size (1) mismatch");

    // Check second element
    ASSERT_NOT_NULL(list_load.head->next, "Loaded second element link is NULL");
    ASSERT_EQUAL_INT(list_load.tail, list_load.head->next, "Loaded tail pointer mismatch");
    ASSERT_EQUAL_INT(0, strcmp(list_load.tail->filename, "save_test2.tmp"), "Loaded filename (2) mismatch");
    ASSERT_EQUAL_INT(2, list_load.tail->sequence_num, "Loaded sequence num (2) mismatch");
    ASSERT_EQUAL_INT(9999, list_load.tail->original_size, "Loaded original size (2) mismatch");
    ASSERT_EQUAL_INT(5555, list_load.tail->processed_size, "Loaded processed size (2) mismatch");

    file_list_free(&list_save);
    file_list_free(&list_load);
    cleanup_test_file();
    return 1; // Success
}

// Test case 5: Load non-existent file
static int test_fl_load_nonexistent(void) {
    cleanup_test_file(); // Ensure file does not exist
    file_list_t list;
    file_list_init(&list);

    int result = file_list_load(&list, TEST_LIST_FILENAME);
    ASSERT_NOT_EQUAL_INT(0, result, "file_list_load should fail for non-existent file");
    // List should remain empty
    ASSERT_EQUAL_INT(0, list.count, "Count should be 0 after failed load");
    ASSERT_NULL(list.head, "Head should be NULL after failed load");

    file_list_free(&list);
    return 1; // Success
}


// Function to run all file list tests
int run_file_list_tests(void) {
    START_TEST_SUITE("File List Utility");

    RUN_TEST(test_fl_init_free);
    RUN_TEST(test_fl_add);
    RUN_TEST(test_fl_find);
    RUN_TEST(test_fl_save_load);
    RUN_TEST(test_fl_load_nonexistent);
    // Add more tests (e.g., get_recent, edge cases for save/load)

    END_TEST_SUITE();
}
