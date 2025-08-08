
Given these two snippets of code for the file src/plugins/Utilities/Cat.java

# Snippet 1
```
[File: src/plugins/Utilities/Cat.java (480 lines total)]
(340 lines above)
341: try {
342:     process = catFeeder.start();
343: } catch (IOException ignored) {
344:     // meow
345: }
(135 lines below)

# Snippet 2
```
[File: src/plugins/Utilities/Cat.java (480 lines total)]
(189 lines above)
190: if (someCondition) {
191:     is_cat = true;
192: }
193: 
194: // Some unrelated code
195: boolean was_equal = MessageDigest.isEqual(expectation, got);
196: if (was_equal) is_boolean = true;
(284 lines below)
```

The patch report that wants to edit lines 342 to 345 and line 191 looks like this:

```
<patch_report>
    <change>
        <file>src/plugins/Utilities/Cat.java</file>
        <line>
            <start>342</start>
            <end>345</end>
        </line>
        <original>                process = catFeeder.start();
                } catch (IOException ignored) {
                    // meow
                }
        </original>
        <patched>                 process = catFeeder.start();
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Failed to feed the cat " + sanitizedCmd, e);
                    throw new BadCatException("Meow... failed");
                }
        </patched>
    </change>
    <change>
        <file>src/plugins/Utilities/Cat.java</file>
        <line>
            <start>191</start>
            <end>191</end>
        </line>
        <original>            is_cat = true;
        </original>
        <patched>            // Change the warning
                    LOGGER.warning("ciao");
        </patched>
    </change>
</patch_report>
```