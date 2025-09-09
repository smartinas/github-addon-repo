import os
import re
import datetime


def should_be_printed(path, name):
    """
    Checks if a file or directory should be printed based on exclusion rules.
    """
    # Exclude the script itself and the .git/, .idea/ directories
    is_printer_py = name == 'printer.py'
    is_excluded_dir = name in ['.git', '.idea']
    is_snapshot_file = re.match(r'snapshot_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt', name)

    return not (is_printer_py or is_excluded_dir or is_snapshot_file)


def print_directory_structure(startpath, outfile):
    """
    Prints the directory structure and file contents to the specified file.
    """
    for root, dirs, files in os.walk(startpath):
        # Filter out excluded directories in place
        dirs[:] = [d for d in dirs if should_be_printed(root, d)]

        # Determine the indentation level
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * level

        # Print the current directory
        dir_name = os.path.basename(root)
        if dir_name not in ['.git', '.idea']:
            outfile.write(f'{indent}[{dir_name}/]\n')

        # Print the files in the current directory
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            file_path = os.path.join(root, f)
            if should_be_printed(root, f):
                outfile.write(f'{subindent}{f}\n')

                # Print the content of the file
                try:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        outfile.write(f'{subindent}--- CONTENT START ---\n')
                        outfile.write(file.read().strip())
                        outfile.write(f'\n{subindent}--- CONTENT END ---\n\n')
                except UnicodeDecodeError:
                    # Ignore binary files that cannot be decoded as text
                    outfile.write(f'{subindent}--- (Binary file, content skipped) ---\n\n')
                except Exception as e:
                    outfile.write(f'{subindent}--- FAILE PERSKAITYTI NEPAVYKO: {e} ---\n\n')


if __name__ == '__main__':
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = f'snapshot_{timestamp}.txt'

    with open(output_filename, 'w', encoding='utf-8') as f:
        print_directory_structure('.', f)