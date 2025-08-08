
Given these two snippets of code for the file src/myapp/modules/user_session_manager.c

# Snippet 1
```
[File: src/myapp/modules/user_session_manager.c (812 lines total)]
(356 lines above)
357: void manage_user_session(session_t *session, config_t *config) {
358:     if (session->is_active) {
359:         update_session_timestamp(session);
360:         return;
361:     }
362: 
363:     if (config->require_auth) {
364:         authenticate_user(session->user_id);
365:     }
366: }
(455 lines below)
```

# Snippet 2
```
[File: src/myapp/modules/user_session_manager.c (812 lines total)]
(405 lines above)
406: void process_session_data(session_t *session) {
407:     char *data_ptr = session->data;
408:     if (data_ptr) {
409:         process_data(data_ptr, session->data_length);
410:     } else {
411:         log_error("Session data is NULL");
412:     }
413: }
(399 lines below)
```

The patch report that wants to edit lines 358 to 361 and lines from 408 to 412 looks like this:

```
<patch_report>
    <change>
        <file>src/myapp/modules/user_session_manager.c</file>
        <line>
            <start>358</start>
            <end>361</end>
        </line>
        <original>        if (session->is_active) {
            update_session_timestamp(session);
            return;
        }</original>
        <patched>         if (session->is_active) {
            update_session_timestamp(session);
            log_info("Session timestamp updated for active session ID: %d", session->id);
            return;
        }</patched>
    </change>
    <change>
        <file>src/myapp/modules/user_session_manager.c</file>
        <line>
            <start>408</start>
            <end>412</end>
        </line>
        <original>        if (data_ptr) {
            process_data(data_ptr, session->data_length);
        } else {
            log_error("Session data is NULL");
        }</original>
        <patched>         if (data_ptr) {
            process_data(data_ptr, session->data_length);
            log_info("Processed session data of length: %zu", session->data_length);
        } else {
            log_error("Session data is NULL for session ID: %d", session->id);
        }</patched>
    </change>
</patch_report>
```