import os
import re
import subprocess

def get_git_commit_message(commit_id, repo_path):
    """Executes git show -s to retrieve the commit message from the local repo."""
    try:
        # Runs the git command specifically in the provided repository directory
        result = subprocess.run(
            ['git', 'show', '-s', '--format=%B', commit_id],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error fetching commit {commit_id}: {e.stderr}")
        return None

def update_md_files(md_folder, repo_path):
    # Regex to find the Commit Id line
    commit_id_pattern = re.compile(r"(### Commit Id:\s*)([a-f0-9]+)", re.IGNORECASE)

    # Process all markdown files in the folder
    for filename in os.listdir(md_folder):
        if filename.endswith(".md"):
            file_path = os.path.join(md_folder, filename)
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Skip if "## Commit Message" already exists to avoid duplicate appending
            if "## Commit Message" in content:
                print(f"Skipping {filename}: Commit message already exists.")
                continue

            match = commit_id_pattern.search(content)
            if match:
                commit_id = match.group(2)
                print(f"Processing {filename} (Commit: {commit_id})...")
                
                commit_msg = get_git_commit_message(commit_id, repo_path)
                
                if commit_msg:
                    # Construct the new section
                    commit_msg_segment = f"\n\n## Commit Message\n\n```\n{commit_msg}\n```"
                    
                    # Identify the end of the line where Commit Id was found
                    end_of_line_pos = match.end()
                    
                    # Find the next newline character to insert after the whole line
                    next_newline = content.find('\n', end_of_line_pos)
                    if next_newline == -1: # If it's the last line of the file
                        new_content = content + commit_msg_segment
                    else:
                        new_content = content[:next_newline] + commit_msg_segment + content[next_newline:]

                    # Write back to the file
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                else:
                    print(f"Warning: Could not retrieve message for {commit_id}")

if __name__ == "__main__":
    # CONFIGURATION:
    # 1. Path to the folder containing your .md files
    MD_FILES_DIR = './results_1' 
    # 2. EXACT directory where your local QEMU git repository is located
    QEMU_GIT_REPO_PATH = '/home/tanvir014/Class_Mat/Thesis/Qemu/qemu'
    FFMPEG_GIT_REPO_PATH = '/home/tanvir014/Class_Mat/Thesis/FFmpeg/FFmpeg'

    update_md_files(MD_FILES_DIR, QEMU_GIT_REPO_PATH)
    update_md_files(MD_FILES_DIR, FFMPEG_GIT_REPO_PATH)
    print("Task completed.")