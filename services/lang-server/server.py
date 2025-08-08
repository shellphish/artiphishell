import json
import logging
import mimetypes
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import uuid

from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Central location for uploads in the system's temporary directory.
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# JSON file that stores project details.
PROJECTS_FILE = os.path.join(UPLOAD_FOLDER, "projects.json")


def load_projects():
    if os.path.exists(PROJECTS_FILE):
        with open(PROJECTS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_projects(projects):
    with open(PROJECTS_FILE, "w") as f:
        json.dump(projects, f, indent=4)


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def update_compile_commands_for_lsp(project_dir):
    REPLACE_TARGET = '/src/harnesses/bld'
    REPLACE_WITH = project_dir
    try:
        with open(os.path.join(project_dir, 'compile_commands.json'), 'r') as f:
            data = json.load(f)
        out_data = []
        for entry in data:
            entry['file'] = entry['file'].replace(REPLACE_TARGET, REPLACE_WITH)
            entry['directory'] = entry['directory'].replace(REPLACE_TARGET, REPLACE_WITH)
            entry['output'] = entry['output'].replace(REPLACE_TARGET, REPLACE_WITH)
            if 'shellphish' not in entry['file']:
                out_data.append(entry)
        with open(os.path.join(project_dir, 'compile_commands.json'), 'w') as f:
            json.dump(out_data, f, indent=4)
    except Exception as e:
        logging.error(f"Error updating compile_commands.json: {e}")
        raise e


@app.route("/get_file_content", methods=["GET"])
def get_file():
    project_dir = request.args.get("project_dir")
    relative_file_path = request.args.get("relative_file_path")
    file_path = os.path.join(project_dir, relative_file_path)

    if not os.path.exists(file_path):
        app.logger.error("File not found: %s", file_path)
        return jsonify(error="File not found"), 404

    mime_type, _ = mimetypes.guess_type(file_path)
    if mime_type is None:
        mime_type = "application/octet-stream"

    with open(file_path, "r") as f:
        content = f.read()

    app.logger.info("File content retrieved: %s", file_path)
    return jsonify(content=content, file_type=mime_type)


@app.route("/upload_source", methods=["POST"])
def upload_source():
    if "file" not in request.files:
        app.logger.error("No file part in request")
        return jsonify(error="No file part"), 400

    file = request.files["file"]
    language = request.form.get("language")
    project_id = request.form.get("project_id")

    if not language:
        app.logger.error("Missing language parameter")
        return jsonify(error="Missing language parameter"), 400

    if not project_id:
        app.logger.error("Missing project_id parameter")
        return jsonify(error="Missing project_id parameter"), 400

    if file.filename == "":
        app.logger.error("No selected file")
        return jsonify(error="No selected file"), 400

    # Use the user-provided project_id to create a central folder.
    work_dir = os.path.join(UPLOAD_FOLDER, project_id)
    if os.path.exists(work_dir):
        app.logger.error("Project with ID %s already exists", project_id)
        return jsonify(error="Project ID already exists"), 400
    os.makedirs(work_dir, exist_ok=True)

    tar_path = os.path.join(work_dir, file.filename)
    file.save(tar_path)
    app.logger.info("File saved to %s", tar_path)

    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(path=work_dir)
        app.logger.info("Extracted tar.gz to %s", work_dir)
    except Exception as e:
        app.logger.error("Error extracting tar.gz: %s", e)
        return jsonify(error=f"Error extracting tar.gz: {e}"), 500

    # If there's exactly one subdirectory, use that as the project folder.
    extracted_dirs = [
        d for d in os.listdir(work_dir)
        if os.path.isdir(os.path.join(work_dir, d))
    ]
    if len(extracted_dirs) == 1:
        project_path = os.path.join(work_dir, extracted_dirs[0])
        app.logger.info("Project directory detected: %s", project_path)
    else:
        project_path = work_dir
        app.logger.info("No single project directory detected; using %s", project_path)

    # Store the project details.
    projects = load_projects()
    projects[project_id] = {
        "language": language,
        "project_dir": os.path.abspath(project_path),
        "status": "uploaded"
    }
    save_projects(projects)

    return jsonify(success=True, project_id=project_id, project_dir=os.path.abspath(project_path))


@app.route("/start_langserver", methods=["POST"])
def start_langserver():
    data = request.get_json()
    if not data:
        app.logger.error("No JSON data provided")
        return jsonify(error="No JSON data provided"), 400

    project_id = data.get("project_id")
    language = data.get("language")
    if not project_id or not language:
        app.logger.error("project_id and language are required")
        return jsonify(error="project_id and language are required"), 400

    projects = load_projects()
    if project_id not in projects:
        app.logger.error("Project ID not found: %s", project_id)
        return jsonify(error="Project not found"), 404

    project_info = projects[project_id]
    # original_project_dir is what was stored during upload.
    original_project_dir = project_info.get("project_dir")
    if not os.path.exists(original_project_dir):
        app.logger.error("Original project directory does not exist: %s", original_project_dir)
        return jsonify(error="Original project directory not found"), 404

    # Create a unique server copy directory that preserves the original folder name.
    unique_copy = str(uuid.uuid4())
    server_project_base = os.path.join(UPLOAD_FOLDER, f"{project_id}_server_{unique_copy}")
    # Ensure the base copy directory exists.
    os.makedirs(server_project_base, exist_ok=True)
    # Get the folder name from the original project directory.
    project_folder_name = os.path.basename(original_project_dir)
    # The final server project directory includes the copied project folder.
    server_project_dir = os.path.join(server_project_base, project_folder_name)

    try:
        shutil.copytree(original_project_dir, server_project_dir)
        app.logger.info("Copied source from %s to %s", original_project_dir, server_project_dir)
    except Exception as e:
        app.logger.error("Error copying source to server location: %s", e)
        return jsonify(error=f"Error copying source: {e}"), 500

    project_info["server_project_dir"] = os.path.abspath(server_project_dir)
    save_projects(projects)

    # Now start the language server using the copied source.
    if language.lower() == "java":
        os.makedirs(os.path.join(os.getcwd(), "java"), exist_ok=True)
        work_sh_filename = f"{project_id}-work.sh"
        work_sh_path = os.path.join(os.getcwd(), "java", work_sh_filename)
        java_command = f"""#!/bin/bash
java \\
    -Declipse.application=org.eclipse.jdt.ls.core.id1 \\
    -Dosgi.bundles.defaultStartLevel=4 \\
    -Declipse.product=org.eclipse.jdt.ls.core.product \\
    -Dlog.level=ALL \\
    -Xmx1G \\
    --add-modules=ALL-SYSTEM \\
    --add-opens java.base/java.util=ALL-UNNAMED \\
    --add-opens java.base/java.lang=ALL-UNNAMED \\
    -jar ./plugins/org.eclipse.equinox.launcher_1.6.900.v20240613-2009.jar \\
    -configuration ./config_linux \\
    -data {os.path.abspath(server_project_dir)}
"""
        with open(work_sh_path, "w") as f:
            f.write(java_command)
        os.chmod(work_sh_path, 0o755)
        free_port = get_free_port()
        socat_cmd = f'socat tcp-l:{free_port},reuseaddr,fork EXEC:"{work_sh_path}"'
        try:
            subprocess.Popen(socat_cmd, shell=True, cwd=os.path.join(os.getcwd(), "java"))
            app.logger.info("Launched Java language server on port %s", free_port)
        except Exception as e:
            app.logger.error("Error starting Java language server: %s", e)
            return jsonify(error=f"Error starting Java language server: {e}"), 500

        project_info["status"] = "running"
        project_info["server_port"] = free_port
        save_projects(projects)

        # Return the full server project directory path.
        return jsonify(language="java", project_id=project_id, port=free_port,
                       project_dir=os.path.abspath(server_project_dir))

    elif language.lower() in ["clang", "clangd", "c", "cpp"]:
        free_port = get_free_port()
        compile_commands_path = os.path.join(server_project_dir, "compile_commands.json")
        if not os.path.exists(compile_commands_path):
            try:
                subprocess.run("cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1", shell=True, cwd=server_project_dir,
                               check=True)
                app.logger.info("Generated compile_commands.json in %s", server_project_dir)
            except Exception as e:
                app.logger.error("Error generating compile_commands.json: %s", e)
                return jsonify(error=f"Error generating compile_commands.json: {e}"), 500
        else:
            try:
                update_compile_commands_for_lsp(os.path.abspath(server_project_dir))
                app.logger.info("Updated compile_commands.json in %s", server_project_dir)
            except Exception as e:
                app.logger.error("Error updating compile_commands.json: %s", e)
                return jsonify(error=f"Error updating compile_commands.json: {e}"), 500

        clangd_cmd = (
            f'./clangd_19.1.2/bin/clangd --log=verbose --background-index '
            f'--compile-commands-dir={os.path.abspath(server_project_dir)}'
        )
        socat_cmd = f'socat tcp-l:{free_port},reuseaddr,fork EXEC:"{clangd_cmd}"'
        try:
            subprocess.Popen(socat_cmd, shell=True, cwd=os.path.join(os.getcwd(), "c-cpp"))
            app.logger.info("Launched Clangd language server on port %s", free_port)
        except Exception as e:
            app.logger.error("Error launching Clangd language server: %s", e)
            return jsonify(error=f"Error launching C/C++ language server: {e}"), 500

        project_info["status"] = "running"
        project_info["server_port"] = free_port
        save_projects(projects)

        return jsonify(language=language, project_id=project_id, port=free_port,
                       project_dir=os.path.abspath(server_project_dir))
    else:
        app.logger.error("Unsupported language: %s", language)
        return jsonify(error="Unsupported language"), 400


@app.route("/list_projects", methods=["GET"])
def list_projects():
    projects = load_projects()
    return jsonify(projects=projects)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
