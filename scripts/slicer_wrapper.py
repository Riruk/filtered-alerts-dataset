import os, subprocess, re, shutil, random
import urllib.request

cwd = os.path.dirname(__file__)
DATA_FOLDER = os.path.normpath(os.path.join(cwd, '..', 'data'))
SLICER_FOLDER = os.path.normpath(os.path.join(cwd, '..', 'slicer'))
CACHE_FOLDER = os.path.normpath(os.path.join(DATA_FOLDER, 'cache'))

GITHUB_FILE_RAW_START = 'https://raw.githubusercontent.com'

WORKERS = 6

if not os.path.exists(CACHE_FOLDER):
    os.makedirs(CACHE_FOLDER)


class Slicer:
    def __init__(self, slicer_folder=SLICER_FOLDER, cache_folder=CACHE_FOLDER):
        self.slicer_folder = slicer_folder
        self.cache_folder = cache_folder
        self.slice_lines = set()

    def get_slice(self, repo, path, lines, commit=None, path_relative=True, checkouted=False, slicetype='lightweight', starting_index=1):
        # if (not checkouted) and (not commit is None):
        #     self.checkout(repo, commit)
        # if path_relative:
        save_filename = os.path.join(self.cache_folder, '{}_{}_{}'.format(commit, os.path.basename(path), random.randrange(1000)))

        file_path = self.checkout_file_github(repo=repo, commit=commit, file=path, save_filename=save_filename)

        if 'error' in file_path:
            return 'error file'

        lines_to_return = set()
        lines = re.sub(r"[\[\]',;]", '', lines).split(' ')

        for i in range(len(lines)):
            try:
                lines[i] = str(int(lines[i]) - starting_index + 1)
            except Exception as e:
                print(str(e))
                return lines_to_return

        cmd = 'java -jar {}/repoman-1.0-SNAPSHOT.jar -f {} -s {} -l {}'.format(self.slicer_folder, file_path, slicetype, ' '.join(lines)).split()
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = p.communicate()
        error = error.decode().strip()

        os.remove(file_path)

        if error != '':
            return 'error file'

        output = re.sub(r'[\[\] ]', '', output.decode().strip())
        if 'error' in output.lower():
            print(output)
            return 'error file'
        if output != '':
            for line in output.split(','):
                lines_to_return.add(int(line) - 1 + starting_index)

        return lines_to_return

    def clone(self, repo):
        cmd = 'git clone {}'.format(repo)
        folder = os.path.join(self.cache_folder, os.path.basename(repo.split('.git')[0]))
        p = subprocess.Popen(cmd.split(), cwd=folder)
        p.wait()

    def checkout(self, repo, commit):
        folder = os.path.join(self.cache_folder, os.path.basename(repo.split('.git')[0]))
        if not os.path.exists(folder):
            self.clone(repo)
        cmd = 'git stash'
        p0 = subprocess.Popen(cmd.split(), cwd=folder)
        p0.wait()
        cmd = 'git checkout {}'.format(commit)
        p = subprocess.Popen(cmd.split(), cwd=folder)
        p.wait()

    def get_ground_truth(self, repo, commit_old, commit_new, vuln_revision=True):
        folder = os.path.join(self.cache_folder, os.path.basename(repo.split('.git')[0]))
        if not os.path.exists(folder):
            self.clone(repo)
        linenum_script = os.path.join(self.slicer_folder, 'showlinenum.awk')

        if vuln_revision:
            cmd1 = 'git diff {} {}'.format(commit_new, commit_old)
        else:
            cmd1 = 'git diff {} {}'.format(commit_old, commit_new)
        cmd2 = '{}'.format(linenum_script)

        p1 = subprocess.Popen(cmd1.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=folder)
        p2 = subprocess.Popen(cmd2.split(), stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.

        # p1_output, p1_error = p1.communicate()
        p2_output, p2_error = p2.communicate()

        # p1_error = p1_error.decode().strip()
        p2_error = p2_error.decode().strip()
        if p2_error != '':
            # print(p1_error)
            # print(p2_error)
            return 'error getting lines for {} {}'.format(commit_old, commit_new)

        output = p2_output.decode().splitlines()
        to_return = dict()  # to_return[file] = [lines]
        current_file = ''
        for line in output:
            if line.startswith('+++'):
                if line.strip().endswith('.java'):
                    current_file = line.split(' b/')[-1].strip()
                    to_return[current_file] = []
                else:
                    current_file = ''
            if current_file == '':
                continue
            if ':+ ' in line:
                to_return[current_file].append(line[:line.index(':')])
        return to_return

    def checkout_file_github(self, repo, commit, file, save_filename):
        # https://raw.githubusercontent.com/apache/tomcat/f00ac55c3b1dfa426967f7e657d1c0ef1aa07e51/TOMCAT-NEXT.txt
        user = os.path.basename(os.path.dirname(repo))
        project = os.path.basename(repo.split('.git')[0])
        url = '{}/{}/{}/{}/{}'.format(GITHUB_FILE_RAW_START, user, project, commit, file)
        # url = re.sub('//', '/', url)
        try:
            urllib.request.urlretrieve(url, save_filename)
        except Exception as e:
            print('An exeption occured, while trying to download {} {} from Github'.format(commit, file))
            print('Download link tryied: {}'.format(url))
            print(str(e))
            return 'error'
        return save_filename

    def get_previous_commit_hash(self, repo, commit):
        # git rev-list --parents -n 1 <commit>
        folder = os.path.join(self.cache_folder, os.path.basename(repo.split('.git')[0]))
        if not os.path.exists(folder):
            self.clone(repo)
        cmd = 'git rev-list --parents -n 1 {}'.format(commit)
        p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=folder)
        output, error = p.communicate()

        return output.decode().split(' ')[-1].strip()

    def get_line_mapping(self, repo, commit_new, file_old, file_new, start_index=1, reversed=False):
        folder = os.path.join(self.cache_folder, os.path.basename(repo.split('.git')[0]))
        if not os.path.exists(folder):
            self.clone(repo)
        commit_old = self.get_previous_commit_hash(repo, commit_new)
        if reversed:
            commit_old, commit_new = commit_new, commit_old
        #
        # print(commit_old)
        # print(commit_new)
        try:
            old_filename = 'old.java'
            response = self.checkout_file_github(repo, commit_old, file_old, os.path.join(self.cache_folder, old_filename))
            if response == 'error':
                return 'error mapping'

            new_filename = 'new.java'
            response = self.checkout_file_github(repo, commit_new, file_new, os.path.join(self.cache_folder, new_filename))
            if response == 'error':
                return 'error mapping'

        except Exception as e:
            print('An error occurred while trying to get line mapping for {} {} {}'.format(repo, commit_new, file_new))
            print(str(e))
            return 'error mapping'

        cmd = 'diff {} {}'.format(old_filename, new_filename)
        p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.cache_folder)
        output, error = p.communicate()
        if output.decode().strip() == '':
            return 'equals'
        # print(output.decode().strip())

        cmd = 'java -jar {}/lhdiff.jar {} {}'.format(self.slicer_folder, old_filename, new_filename).split()
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.cache_folder)
        output, error = p.communicate()
        error = error.decode().strip()
        if error != '':
            print('LHDiff error: {}'.format(error))
            return 'error mapping'

        output = re.sub(r'[\[\] ]', '', output.decode())
        to_return = dict()
        if output != '':
            for line in output.splitlines():
                loc = line.strip().split(',')
                if 'LHDiff' in loc[0]:
                    continue
                try:
                    to_return[str(int(loc[0]) - 1 + start_index)] = str(int(loc[1]) - 1 + start_index)
                except:
                    continue

        os.remove(os.path.join(self.cache_folder, old_filename))
        os.remove(os.path.join(self.cache_folder, new_filename))
        return to_return
