#include "test_utils.h"
#include "utils/file_list.h"
#include <stdlib.h> // For malloc, free
#include <unistd.h> // For unlink (or _unlink on Windows)

#ifdef _WIN32
#include <io.h>     // For _unlink
#define unlink _unlink
#else
#include <unistd.h> // For unlink
#endif


#define TEST_LIST_FILE "test_list.dat"

// Test initialization
static int test_list_init() {
    file_list_t list;
    int result = file_list_init(&list);
    int init_ok = check_equal_int(0, result, "file_list_init failed");
    int head_null = check_null(list.head, "list.head not NULL after init");
    int tail_null = check_null(list.tail, "list.tail not NULL after init");
    int count_zero = check_equal_size(0, list.count, "list.count not 0 after init");
    int seq_ok = check_equal_int(1, list.next_sequence_num, "list.next_sequence_num not 1 after init");
    file_list_free(&list); // Clean up (should be safe)
    return init_ok && head_null && tail_null && count_zero && seq_ok;
}

// Test adding items
static int test_list_add() {
    file_list_t list;
    file_list_init(&list);

    int res1 = file_list_add(&list, "file1.txt", 100, 50);
    int add1_ok = check_equal_int(0, res1, "file_list_add (1) failed");
    int count1_ok = check_equal_size(1, list.count, "list.count not 1 after first add");
    int head1_ok = check_not_null(list.head, "list.head NULL after first add");
    int tail1_ok = check_not_null(list.tail, "list.tail NULL after first add");
    int head_tail_ok1 = check(list.head == list.tail, "list.head != list.tail for single item");
    int name1_ok = head1_ok && check_equal_int(0, strcmp(list.head->filename, "file1.txt"), "Filename mismatch (1)");
    int seq1_ok = head1_ok && check_equal_int(1, list.head->sequence_num, "Sequence number mismatch (1)");

    int res2 = file_list_add(&list, "file2.log", 2000, 1500);
    int add2_ok = check_equal_int(0, res2, "file_list_add (2) failed");
    int count2_ok = check_equal_size(2, list.count, "list.count not 2 after second add");
    int head2_ok = check_not_null(list.head, "list.head NULL after second add");
    int tail2_ok = check_not_null(list.tail, "list.tail NULL after second add");
    int head_tail_ok2 = check(list.head != list.tail, "list.head == list.tail for two items");
    int name2_ok = tail2_ok && check_equal_int(0, strcmp(list.tail->filename, "file2.log"), "Filename mismatch (2)");
    int seq2_ok = tail2_ok && check_equal_int(2, list.tail->sequence_num, "Sequence number mismatch (2)");
    int next_ok = head1_ok && head2_ok && check(list.head->next == list.tail, "list.head->next != list.tail");
    int seq_num_ok = check_equal_int(3, list.next_sequence_num, "list.next_sequence_num not 3 after two adds");

    file_list_free(&list); // Clean up
    return add1_ok && count1_ok && head1_ok && tail1_ok && head_tail_ok1 && name1_ok && seq1_ok &&
           add2_ok && count2_ok && head2_ok && tail2_ok && head_tail_ok2 && name2_ok && seq2_ok && 
           next_ok && seq_num_ok;
}

// Test finding items
static int test_list_find() {
    file_list_t list;
    file_list_init(&list);
    file_list_add(&list, "document_final_v2.txt", 1024, 800);
    file_list_add(&list, "archive.zip", 50000, 45000);
    file_list_add(&list, "image.png", 256, 200);

    file_entry_t *found1 = file_list_find(&list, "archive.zip");
    int find1_ok = check_not_null(found1, "Did not find 'archive.zip'");
    int name1_ok = find1_ok && check_equal_int(0, strcmp(found1->filename, "archive.zip"), "Found wrong file for 'archive.zip'");

    file_entry_t *found2 = file_list_find(&list, "document"); // Partial match
    int find2_ok = check_not_null(found2, "Did not find partial 'document'");
    int name2_ok = find2_ok && check_equal_int(0, strcmp(found2->filename, "document_final_v2.txt"), "Found wrong file for partial 'document'");

    file_entry_t *found3 = file_list_find(&list, "nonexistent.dat");
    int find3_ok = check_null(found3, "Found 'nonexistent.dat' which shouldn't exist");

    file_list_free(&list);
    return find1_ok && name1_ok && find2_ok && name2_ok && find3_ok;
}

// Test saving and loading the list
static int test_list_save_load() {
    file_list_t list_orig, list_loaded;
    file_list_init(&list_orig);
    file_list_add(&list_orig, "save_test_1.c", 500, 400);
    file_list_add(&list_orig, "save_test_2.h", 100, 90);

    // Save
    int save_res = file_list_save(&list_orig, TEST_LIST_FILE);
    int save_ok = check_equal_int(0, save_res, "file_list_save failed");
    if (!save_ok) { file_list_free(&list_orig); unlink(TEST_LIST_FILE); return 0; }

    // Load into a new list
    file_list_init(&list_loaded);
    int load_res = file_list_load(&list_loaded, TEST_LIST_FILE);
    int load_ok = check_equal_int(0, load_res, "file_list_load failed");
    if (!load_ok) { file_list_free(&list_orig); file_list_free(&list_loaded); unlink(TEST_LIST_FILE); return 0; }

    // Compare
    int count_ok = check_equal_size(list_orig.count, list_loaded.count, "Loaded list count mismatch");
    int seq_num_ok = check_equal_int(list_orig.next_sequence_num, list_loaded.next_sequence_num, "Loaded next_sequence_num mismatch");
    if (!count_ok || !seq_num_ok) { file_list_free(&list_orig); file_list_free(&list_loaded); unlink(TEST_LIST_FILE); return 0; }

    file_entry_t *curr_orig = list_orig.head;
    file_entry_t *curr_loaded = list_loaded.head;
    int content_ok = 1;
    while(curr_orig != NULL && curr_loaded != NULL) {
        if (!check_equal_int(0, strcmp(curr_orig->filename, curr_loaded->filename), "Loaded filename mismatch") ||
            !check_equal_size(curr_orig->original_size, curr_loaded->original_size, "Loaded original_size mismatch") ||
            !check_equal_size(curr_orig->processed_size, curr_loaded->processed_size, "Loaded processed_size mismatch") ||
            !check_equal_int(curr_orig->sequence_num, curr_loaded->sequence_num, "Loaded sequence_num mismatch")) {
             content_ok = 0;
             break;
         }
        curr_orig = curr_orig->next;
        curr_loaded = curr_loaded->next;
    }
    // Also check that both lists ended at the same time
    content_ok = content_ok && check(curr_orig == NULL && curr_loaded == NULL, "Loaded list structure mismatch");


    // Clean up
    file_list_free(&list_orig);
    file_list_free(&list_loaded);
    unlink(TEST_LIST_FILE); // Delete the test file

    return count_ok && content_ok && seq_num_ok;
}


// Test suite runner for File List tests
void run_file_list_tests() {
    TEST_START("File List");
    RUN_TEST(test_list_init);
    RUN_TEST(test_list_add);
    RUN_TEST(test_list_find);
    RUN_TEST(test_list_save_load);
    // Add more tests: get_recent, empty list save/load
    TEST_END("File List");
}