def build_patch(file: str = "mock_vp.c"):
    return (
        f"""
diff --git a/{file} b/{file}
index d4016f7..fbcbb12 100644
--- a/{file}
+++ b/{file}
"""
        + """
@@ -21,8 +21,10 @@ int main()
     int j;
     printf("display item #:");
     scanf("%d", &j);
-    buff = &items[j][0];
-    printf("item %d: %s\n", j, buff);
+    if (j < 0 || j>2){;}else{
+        buff = &items[j][0];
+        printf("item %d: %s\n", j, buff);
+    }


     return 0;

"""
    )
