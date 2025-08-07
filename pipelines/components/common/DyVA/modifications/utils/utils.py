import os
import re
import yaml
import argparse

from pathlib import Path
from code_parser import get_function_info

PROFILES = """
<profile>
    <id>build-classpath-profile-1337</id>
    <activation>
      <activeByDefault>true</activeByDefault>
    </activation>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                
                <configuration>
                    <source>1.8</source>
                    <target>1.8</target>
                    <encoding>UTF-8</encoding>
                    <compilerArgs>
                        <arg>-g:source,lines,vars</arg>
                    </compilerArgs>
                </configuration>
            </plugin>
        </plugins>
    </build>
</profile>
"""
# PROFILES = """
    # <profile>
        # <id>build-classpath-profile-1337</id>
        # <activation>
            # <activeByDefault>true</activeByDefault>
        # </activation>
        # <build>
            # <plugins>
                # <plugin>
                    # <groupId>org.apache.maven.plugins</groupId>
                    # <artifactId>maven-dependency-plugin</artifactId>
                    # <version>3.2.0</version>
                    # <executions>
                        # <execution>
                            # <id>build-classpath</id>
                            # <phase>compile</phase>
                            # <goals>
                                # <goal>build-classpath</goal>
                            # </goals>
                            # <configuration>
                                # <outputFile>/classpath.txt</outputFile>
                            # </configuration>
                        # </execution>
                    # </executions>
                # </plugin>
            # </plugins>
        # </build>
    # </profile>
    # <profile>
        # <id>debug-1337</id>
        # <activation>
            # <activeByDefault>true</activeByDefault>
        # </activation>
        # <build>
            # <plugins>
                # <plugin>
                    # <artifactId>maven-compiler-plugin</artifactId>
                    # <configuration>
                        # <debug>true</debug>
                        # <debuglevel>lines,vars,source</debuglevel>
                    # </configuration>
                # </plugin>
            # </plugins>
        # </build>
    # </profile>"""
JAVA_MAIN_FUNC = """
    public static void main(String[] args) {
        try {
            java.io.InputStream inputStream = System.in;
            byte[] input = new byte[inputStream.available()];
            inputStream.read(input);
            fuzzerTestOneInput(input);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
"""

JAR_CONFIG="""
        <configuration>
          <archive>
            <index>true</index>
            <manifest>
              <addClasspath>true</addClasspath>
            </manifest>
            <manifestEntries>
              <mode>development</mode>
              <url>${project.url}</url>
              <key>value</key>
            </manifestEntries>
          </archive>
        </configuration>"""

class TargetPrepper:

    def __init__(self, challenge_project: Path):
        self.cp = challenge_project

        self.setup()
    
    def setup(self):
        global JAVA_MAIN_FUNC
        with open(self.cp / "project.yaml", "r") as f:
            data = yaml.safe_load(f)
        if data["language"] == "java":
            for harness in data["harnesses"].values():
                harness_file = self.cp / harness["source"]
                self.replace_main_function(harness_file, JAVA_MAIN_FUNC)
                # self.replace_pom_configuration(harness_file)
            for source in data["cp_sources"].keys():
                pom = self.cp / "src" / source / "pom.xml"
                if not pom.exists():
                    continue
                self.add_profiles_to_pom(pom)

    @staticmethod
    def add_profiles_to_pom(pom: Path):
        global PROFILES
        pom_content = pom.read_text()
        pom_lines = pom_content.strip().split("\n")
        profiles_end = -1
        for idx, line in enumerate(pom_lines):
            if line.strip().startswith("</profiles>"):
                profiles_end = idx
                break
        profs = PROFILES
        if profiles_end == -1:
            profs = "\n<profiles>\n" + profs + "\n</profiles>\n"
        pom_content = "\n".join(pom_lines[:profiles_end] + [profs] + pom_lines[profiles_end:])
        print("----")
        print(pom_content)
        print("----")
        pom.write_text(pom_content)

    @staticmethod
    def replace_pom_configuration(pom: Path):
        global JAR_CONFIG
        # Check if file exists
        if not pom.is_file():
            print(f"File {pom} does not exist.")
            return

        # Read the Java file content
        content = pom.read_text()
        content_lines = content.split("\n")
        start = 0
        end = 0
        plugin_text = 0
        plugin_end = 0
        for idx, line in enumerate(content_lines):
            if "<groupId>org.apache.maven.plugins</groupId>" in line:
                if end == 0:
                    start = idx
            elif "<artifactId>maven-jar-plugin</artifactId>" in line:
                end = idx
                break

            elif "</plugins>" in line:
                plugin_end = idx
            
            elif "<plugin>" in line:
                plugin_text = idx

        if end == 0:
            config = """
            <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-jar-plugin</artifactId>
            <version>3.4.2</version>
            """ + JAR_CONFIG + "\n</plugin>"
            content_lines = content_lines[:plugin_end] + [config] + content_lines[plugin_end:]
        elif start  == 0:
            return
        elif not (start < plugin_text < end):
            content_lines = content_lines[:start+1] + [JAR_CONFIG] + content_lines[start+1:]
        
        pom.write_text("\n".join(content_lines))

    @staticmethod
    def replace_main_function(java_file_path: Path, main_func: str):
        # Check if file exists
        if not java_file_path.is_file():
            print(f"File {java_file_path} does not exist.")
            return

        # Read the Java file content
        content = java_file_path.read_text()
        function_info = get_function_info(content, "java")

        assert 'fuzzerTestOneInput' in function_info
        content_lines = content.split("\n")
        if 'main' in function_info:
            start, end = function_info["main"]
        else:
            start, end = sorted(function_info.values(), key=lambda x: x[1], reverse=True)[0]
        content_lines = content_lines[:start-1] + [main_func] + content_lines[end:]
        content = "\n".join(content_lines)

        # Insert the new main function before the closing brace of the class
        #content = content[:insert_pos] + main_function + content[insert_pos:]
        # Write back the modified content to the Java file
        with open(java_file_path, 'w') as file:
            file.write(content)

        print(f"Main function replaced in {java_file_path}.")

def get_args():
    argparser = argparse.ArgumentParser(description='invguy-build')

    argparser.add_argument('--target-dir', type=Path, help='Target program source code', required=True)
    return argparser.parse_args()
    
def main():
    args = get_args()
    TargetPrepper(args.target_dir)

if __name__ == '__main__':
    main()