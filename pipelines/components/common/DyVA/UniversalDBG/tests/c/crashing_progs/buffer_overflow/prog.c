#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#define BUFFER_SIZE 10

void perform_innocuous_task1() {
    int x = 5;
    int y = 10;
    int result = x + y;
    printf("Task 1 result: %d\n", result);
}

void perform_innocuous_task2() {
    char str1[20] = "Hello";
    char str2[20] = "World";
    strcat(str1, " ");
    strcat(str1, str2);
    printf("Task 2 result: %s\n", str1);
}

void modify_data(char *data) {
    for (int i = 0; i < strlen(data); i++) {
        if (i % 2 == 0) {
            data[i] = toupper(data[i]);
        } else {
            data[i] = tolower(data[i]);
        }
    }
}

void append_data(char *data) {
    char append_text[20] = "12345";  // Change size to fit scenario
    if (strlen(data) + strlen(append_text) < 100) {  // Incorrect check that leads to unsafe behavior
        strcat(data, append_text);
    }
}

void process_data(char *data) {
    char another_buffer[20];  // Increase size for demonstration
    strcpy(another_buffer, data);  // Directly copy which can overflow another_buffer if data is too large

    printf("Processing modified data: %s\n", data);
    printf("Another function called with buffer: %s\n", another_buffer);
}

void worker_function() {
    static char buffer[BUFFER_SIZE];
    printf("Enter some text: ");
    fgets(buffer, 100, stdin);  
    buffer[strcspn(buffer, "\n")] = 0;

    modify_data(buffer);
    append_data(buffer);
    process_data(buffer);
}

void menu() {
    int choice;
    bool run = true;
    int count = 0;

    while (run) {
        printf("\n--- Menu ---\n");
        printf("1. Perform Task 1\n");
        printf("2. Perform Task 2\n");
        printf("3. Enter Data\n");
        printf("4. Exit\n");
        printf("Select an option: ");
        scanf("%d", &choice);
        getchar();  // Consume newline character left by scanf

        switch (choice) {
            case 1:
                perform_innocuous_task1();
                break;
            case 2:
                perform_innocuous_task2();
                break;
            case 3:
                if (++count >= 3) {
                    worker_function();
                } else {
                    printf("Data entry not yet allowed. Please explore other options.\n");
                }
                break;
            case 4:
                run = false;
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid option. Please try again.\n");
                break;
        }
    }
}

int main() {
    menu();
    return 0;
}

