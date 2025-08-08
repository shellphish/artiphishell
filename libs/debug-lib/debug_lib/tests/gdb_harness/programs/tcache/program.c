#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CHUNKS 16

char *chunks[MAX_CHUNKS];
size_t chunk_sizes[MAX_CHUNKS];

void allocate_chunk() {
    int index = -1;
    for (int i = 0; i < MAX_CHUNKS; i++) {
        if (chunks[i] == NULL) {
            index = i;
            break;
        }
    }

    if (index == -1) {
        printf("Maximum number of chunks reached.\n");
        return;
    }

    size_t size;
    printf("Enter size of the new chunk: ");
    scanf("%zu", &size);
    getchar(); // Consume the newline

    chunks[index] = (char *)malloc(size);
    if (chunks[index] == NULL) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return;
    }
    chunk_sizes[index] = size;
    printf("Chunk %d allocated with size %zu bytes.\n", index, size);
}

void write_to_chunk() {
    int index;
    printf("Enter index of chunk to write to (0-%d): ", MAX_CHUNKS - 1);
    scanf("%d", &index);
    getchar(); // Consume newline

    printf("Enter data to write to chunk: ");
    fgets(chunks[index], chunk_sizes[index], stdin);
    chunks[index][strcspn(chunks[index], "\n")] = 0; // Remove newline character
    printf("Data written to chunk %d.\n", index);
}

void free_chunk() {
    int index;
    printf("Enter index of chunk to free (0-%d): ", MAX_CHUNKS - 1);
    scanf("%d", &index);
    getchar(); // Consume newline

    if (index < 0 || index >= MAX_CHUNKS || chunks[index] == NULL) {
        printf("Invalid index or no chunk to free at this index.\n");
        return;
    }

    free(chunks[index]);
    printf("Chunk %d freed.\n", index);
}

void list_chunks() {
    printf("Listing allocated chunks:\n");
    for (int i = 0; i < MAX_CHUNKS; i++) {
        printf("Chunk %d: Size %zu, Status %s\n", i, chunk_sizes[i], chunks[i] ? "Allocated" : "Freed");
    }
}

void menu() {
    int choice;
    int running = 1;

    while (running) {
        printf("\n--- Menu ---\n");
        printf("1. Allocate Chunk\n");
        printf("2. Write to Chunk\n");
        printf("3. Free Chunk\n");
        printf("4. List Chunks\n");
        printf("5. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar(); // Consume the newline

        switch (choice) {
            case 1:
                allocate_chunk();
                break;
            case 2:
                write_to_chunk();
                break;
            case 3:
                free_chunk();
                break;
            case 4:
                list_chunks();
                break;
            case 5:
                // Free all chunks before exiting
                for (int i = 0; i < MAX_CHUNKS; i++) {
                    if (chunks[i] != NULL) {
                        free(chunks[i]);
                        chunks[i] = NULL;
                    }
                }
                running = 0;
                break;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }
}

int main() {
    memset(chunks, 0, sizeof(chunks)); // Initialize all pointers to NULL
    memset(chunk_sizes, 0, sizeof(chunk_sizes)); // Initialize all sizes to 0
    menu();
    return 0;
}

