import os, csv, sys, re, json
from scripts.slicer_wrapper import Slicer
from multiprocessing.pool import Pool

cwd = os.path.dirname(__file__)
DATA_FOLDER = os.path.normpath(os.path.join(cwd, '..', 'data'))

INPUT_REVISIONS = os.path.join(DATA_FOLDER, 'input_tomcat.csv')
INPUT_GROUND_TRUTH = os.path.join(DATA_FOLDER, 'ground_truth.csv')
TOOL_ALERTS_FOLDER = os.path.join(DATA_FOLDER, 'tool_alerts')

OUTPUT_TABLE_FILE = os.path.join(DATA_FOLDER, 'tomcat_dataset_no_slice.csv')
OUTPUT_JSON_FILE = os.path.join(DATA_FOLDER, 'tomcat_dataset.json')
AUGMENTED_DATASET = os.path.join(DATA_FOLDER, 'alerts-dataset.csv')


class DatasetGenerator:
    def __init__(self, input_revisions=INPUT_REVISIONS, input_ground_truth=INPUT_GROUND_TRUTH):
        self.input_revisions_file = input_revisions
        self.input_ground_truth_file = input_ground_truth
        self.slicer = Slicer()

    def load_data_from(self, file_name, delimiter=','):
        print('Loading data from {}'.format(file_name))
        content = []
        try:
            with open(file_name, 'r', encoding='utf8') as f_in:
                reader = csv.reader(f_in, delimiter=delimiter)
                for line in reader:
                    content.append(line)
                print('Data from {} was successfully loaded'.format(file_name))
        except OSError as e:
            print('I cannot locate file {}'.format(file_name))
            print(str(e))
        except Exception as e:
            print('An exception happened, while reading data from {}'.format(file_name))
            print(str(e))
        return content

    def build_dictionary(self, file_name, key_columns, delimiter=',', columns_to_extract=None, title_row='True'):
        print('Building dictionary for {}'.format(file_name))
        dict_to_return = dict()
        data = self.load_data_from(file_name, delimiter=delimiter)
        # ground_truth = self.load_data_from(self.input_ground_truth_file, delimiter=';')
        counter = 0
        for row in data:
            if title_row and counter < 1:
                counter += 1
                continue

            tmp_key = []
            for key_column in key_columns:
                tmp_key.append(row[key_column])
            key = '_'.join(tmp_key)
            if not key in dict_to_return:
                dict_to_return[key] = []
            if columns_to_extract is None:
                dict_to_return[key].append(row)
            else:
                tmp = []
                for item in columns_to_extract:
                    tmp.append(row[item])
                dict_to_return[key].append(tmp)
        print('Dictionary for {} was successfully built'.format(file_name))
        return dict_to_return

    def combine_revisions_ground_truth(self, clean_filenames=True):
        dict_revisions = self.build_dictionary(self.input_revisions_file, key_columns=[0, 3],
                                               columns_to_extract=[0, 1, 2, 3])
        dict_ground_truth = self.build_dictionary(self.input_ground_truth_file, delimiter=';', key_columns=[0, 1],
                                                  columns_to_extract=[2, 3])
        if clean_filenames:
            for key in dict_ground_truth:
                for i in range(len(dict_ground_truth[key])):
                    dict_ground_truth[key][i][0] = dict_ground_truth[key][i][0].strip()
                    dict_ground_truth[key][i][0] = re.sub(r'\\', '/', dict_ground_truth[key][i][0])
                    if dict_ground_truth[key][i][0].startswith('/'):
                        dict_ground_truth[key][i][0] = dict_ground_truth[key][i][0][1:]
                    if dict_ground_truth[key][i][0].startswith('org/'):
                        dict_ground_truth[key][i][0] = 'java/{}'.format(dict_ground_truth[key][i][0])

        dict_combined = dict()
        for key in dict_revisions:
            try:
                dict_combined[key] = dict_revisions[key]
                dict_combined[key].append(dict_ground_truth[key])
            except Exception as e:
                print(
                    '[SKIPPING] An exception happened, while trying to merge {} for revisions and ground truth'.format(
                        key))
                print(str(e))
                dict_combined[key].append([])
        return dict_combined

    def get_alerts_dict(self, vuln=True, alerts_folder=TOOL_ALERTS_FOLDER, clean_spotted_filenames=True):
        alerts_dict = dict()
        if vuln:
            start_folder = os.path.join(alerts_folder, 'vuln')
            filename_end = '_out.csv'
        else:
            start_folder = os.path.join(alerts_folder, 'fix')
            filename_end = '_out_fix.csv'
        for path, dirs, filenames in os.walk(start_folder):
            for filename in filenames:
                if filename.endswith(filename_end):
                    tool_name = os.path.basename(path)
                    project_id = os.path.basename(os.path.dirname(path))
                    vuln_id = filename.split(filename_end)[0]

                    key = '{}_{}'.format(project_id, vuln_id)
                    if not key in alerts_dict:
                        alerts_dict[key] = dict()
                    if not tool_name in alerts_dict[key]:
                        alerts_dict[key][tool_name] = []
                    alerts_dict[key][tool_name] = self.load_data_from(os.path.join(path, filename), delimiter=';')
                    if clean_spotted_filenames:
                        for i in range(len(alerts_dict[key][tool_name])):
                            try:
                                alerts_dict[key][tool_name][i][2] = alerts_dict[key][tool_name][i][2].strip()
                                alerts_dict[key][tool_name][i][2] = re.sub(r'\\', '/',
                                                                           alerts_dict[key][tool_name][i][2])
                                if alerts_dict[key][tool_name][i][2].startswith('/'):
                                    alerts_dict[key][tool_name][i][2] = alerts_dict[key][tool_name][i][2][1:]
                                if alerts_dict[key][tool_name][i][2].startswith('org/'):
                                    alerts_dict[key][tool_name][i][2] = 'java/{}'.format(
                                        alerts_dict[key][tool_name][i][2])
                            except Exception as e:
                                print(
                                    'An exception occurred, while cleaning filename for {} {} {}'.format(key, tool_name,
                                                                                                         alerts_dict[
                                                                                                             key][
                                                                                                             tool_name][
                                                                                                             i]))
                                print(str(e))
                                continue
        return alerts_dict

    def combine_revisions_gtf_alerts(self, vuln=True):  # Set vuln=False to calculate for fix
        revisions_gtf_dict = self.combine_revisions_ground_truth()
        alerts_dict = self.get_alerts_dict(vuln=vuln)
        final_dict = dict()
        for key in revisions_gtf_dict:
            if not key in final_dict:
                final_dict[key] = []
            final_dict[key].extend(revisions_gtf_dict[key])
            try:
                final_dict[key].append(alerts_dict[key])
            except Exception as e:
                print('An exception occured, while trying to combine revisions_gtf information with alerts information')
                print(str(e))
                final_dict[key].append(dict())
                continue
        return final_dict

    def final_dict_as_table(self, output_table=OUTPUT_TABLE_FILE, vuln=True):
        final_dict = self.combine_revisions_gtf_alerts(vuln=vuln)
        if vuln:
            output = '{}_vuln.csv'.format(output_table.split('.csv')[0])
            commit_add = '^'
        else:
            output = '{}_fix.csv'.format(output_table.split('.csv')[0])
            commit_add = ''
        try:
            with open(output, 'w', newline='', encoding='utf8') as f_out:
                writer = csv.writer(f_out, delimiter=';')
                roww = ['project', 'repo', 'commit', 'vuln_id', 'tool', 'file', 'lines', 'lines_sliced_li',
                        'lines_sliced_pess']
                writer.writerow(roww)
                count = 0
                for key in final_dict:
                    count += 1
                    print('Processing key {} ({} out of {} - {}'.format(key, count, len(final_dict), vuln))
                    checkouted = False
                    slice_error = False

                    gt = self.slicer.get_ground_truth(repo=final_dict[key][0][1],
                                                      commit_old='{}^'.format(final_dict[key][0][2]),
                                                      commit_new=final_dict[key][0][2], vuln_revision=vuln)
                    if 'error' in gt:
                        # print('An error occured, while calculating ground truth for {}'.format(final_dict[key]))
                        continue
                    for file in gt:
                        roww = []
                        roww.extend(final_dict[key][0])
                        roww.append('ground_truth')
                        roww.append(file)
                        roww.append(str(gt[file]))
                        # try:
                        #     # roww.append(self.slicer.get_slice(repo=roww[1], path=file, lines=str(gt[file]), commit='{}{}'.format(roww[2], commit_add), checkouted=checkouted, slicetype='lightweight'))
                        #     # roww.append(self.slicer.get_slice(repo=roww[1], path=file, lines=str(gt[file]),
                        #     #                                   commit='{}{}'.format(roww[2], commit_add),
                        #     #                                   checkouted=checkouted, slicetype='pessimist'))
                        #     checkouted = True
                        # except Exception as e:
                        #     print(str(e))
                        #     # roww.append('')
                        #     # roww.append('')
                        #     slice_error = True
                        writer.writerow(roww)
                    # break
                    for tool in final_dict[key][2]:
                        for finding in final_dict[key][2][tool]:
                            roww = []
                            roww.extend(final_dict[key][0])
                            roww.append(tool)
                            roww.extend(finding[2:])
                            # try:
                            #     if not slice_error:
                            #         if tool == 'Tool_A':
                            #             start_index = 0
                            #         else:
                            #             start_index = 1
                            #         # roww.append(self.slicer.get_slice(repo=roww[1], path=roww[5], lines=roww[6],
                            #         #                               commit='{}{}'.format(roww[2], commit_add),
                            #         #                               checkouted=checkouted, slicetype='lightweight',
                            #         #                               starting_index=start_index))
                            #         # roww.append(self.slicer.get_slice(repo=roww[1], path=roww[5], lines=roww[6],
                            #         #                                   commit='{}{}'.format(roww[2], commit_add),
                            #         #                                   checkouted=checkouted, slicetype='pessimist',
                            #         #                                   starting_index=start_index))
                            #         checkouted = True
                            #     else:
                            #         roww.append('')
                            #         roww.append('')
                            # except Exception as e:
                            #     print(str(e))
                            #     roww.append('')
                            writer.writerow(roww)
        except OSError as e:
            print('An error occurred, while trying to create file {} for writing'.format(output_table))
            print(e)

    def load_dict_output(self, output_file):
        # roww = ['project', 'repo', 'commit', 'vuln_id', 'tool', 'file', 'lines', 'lines_sliced']
        to_return = dict()
        with open(output_file, 'r') as f_vuln_pess:
            r_vuln_pess = csv.reader(f_vuln_pess, delimiter=';')
            for line in r_vuln_pess:
                if line[0] == 'project':
                    continue
                key = '{}_{}_{}_{}'.format(line[0], line[3], line[4], line[5])
                to_return[key] = line
        return to_return

    def get_lines_mapping(self, repo, commit_new, file_old, file_new, start_index, reversed=False):
        return self.slicer.get_line_mapping(repo, commit_new, file_old, file_new, start_index=start_index,
                                            reversed=reversed)

    def get_filtered_lines(self, line_mapping, lines_old, lines_new):
        filtered_lines = []
        converted_lines = []
        if line_mapping == 'equals':
            converted_lines = lines_new
        else:
            for line in lines_new:
                try:
                    converted_lines.append(line_mapping[line])
                except Exception as e:
                    print('Line {} was not found in the mapping'.format(line))
                    print(str(e))
        for line in lines_old:
            if line not in converted_lines:
                filtered_lines.append(line)
        return filtered_lines

    def combine_final_dataset_file(self, common_output, WORKERS=7):
        dict_vuln_pess = self.load_dict_output('{}_vuln.csv'.format(OUTPUT_TABLE_FILE.split('.csv')[0]))
        dict_fix_pess = self.load_dict_output('{}_fix.csv'.format(OUTPUT_TABLE_FILE.split('.csv')[0]))

        with open(os.path.join(DATA_FOLDER, 'dict_vuln.json'), 'w') as f_json:
            json.dump(dict_vuln_pess, f_json)

        with open(os.path.join(DATA_FOLDER, 'dict_fix.json'), 'w') as f_json:
            json.dump(dict_fix_pess, f_json)


        with open(common_output, 'w', newline='', encoding='utf8') as f_out:
            writer = csv.writer(f_out, delimiter=';')
            roww = 'project; repo; commit; vuln_id; vul_or_fix; tool; file; LoC_vuln; LoC_sliced_lightweight; LoC_sliced_pessimist'.split(
                '; ')
            writer.writerow(roww)
            total = len(dict_fix_pess)
            count = 0

            for key in dict_fix_pess:
                count += 1
                if key in dict_vuln_pess:
                    print('Processing key {} ({} out of {})'.format(key, count, total))
                    roww = dict_fix_pess[key][:4]
                    roww.append('fix')
                    roww.append(dict_fix_pess[key][4])
                    roww.append(dict_fix_pess[key][5])
                    if dict_fix_pess[key][4] == 'ground_truth':
                        roww.extend(dict_fix_pess[key][6:])
                        writer.writerow(roww)
                    else:
                        start_index = 1
                        if dict_fix_pess[key][4] in ['Tool_A', 'Tool_B']:
                            start_index = 0
                        lines_mapping = self.get_lines_mapping(dict_fix_pess[key][1], dict_fix_pess[key][2],
                                                               dict_fix_pess[key][5], dict_vuln_pess[key][5],
                                                               start_index=start_index, reversed=True)

                        if not 'error' in lines_mapping:
                            lines_old = re.sub(r"['\[\]]", '', dict_fix_pess[key][6]).split(', ')
                            lines_new = re.sub(r"['\[\]]", '', dict_vuln_pess[key][6]).split(', ')
                            lines_filtered = self.get_filtered_lines(lines_mapping, lines_old, lines_new)
                            roww.append(str(lines_filtered))
                            # roww.append(self.slicer.get_slice(repo=roww[1], path=roww[5], lines=lines_filtered,
                            #                                   commit=dict_fix_pess[key][2],
                            #                                   checkouted=False, slicetype='lightweight',
                            #                                   starting_index=1))
                            # roww.append(self.slicer.get_slice(repo=roww[1], path=roww[5], lines=lines_filtered,
                            #                                   commit='{}{}'.format(roww[2], dict_fix_pess[key][2]),
                            #                                   checkouted=True, slicetype='pessimist',
                            #                                   starting_index=1))
                            if len(roww) < 8:
                                print(roww)
                            writer.writerow(roww)

                    roww = dict_vuln_pess[key][:4]
                    roww.append('vuln')
                    roww.append(dict_vuln_pess[key][4])
                    roww.append(dict_vuln_pess[key][5])
                    if dict_vuln_pess[key][4] == 'ground_truth':
                        roww.extend(dict_vuln_pess[key][6:])
                        writer.writerow(roww)
                    else:
                        start_index = 1
                        if dict_fix_pess[key][4] in ['Tool_A', 'Tool_B']:
                            start_index = 0
                        lines_mapping = self.get_lines_mapping(dict_vuln_pess[key][1], dict_vuln_pess[key][2],
                                                               dict_vuln_pess[key][5], dict_fix_pess[key][5],
                                                               start_index)
                        if not 'error' in lines_mapping:
                            lines_old = re.sub(r"['\[\]]", '', dict_fix_pess[key][6]).split(', ')
                            lines_new = re.sub(r"['\[\]]", '', dict_vuln_pess[key][6]).split(', ')

                            lines_filtered = self.get_filtered_lines(lines_mapping, lines_new, lines_old)
                            roww.append(str(lines_filtered))
                            if len(roww) < 8:
                                print(roww)
                            writer.writerow(roww)

    def _augment_helper(self, line):
        with open(AUGMENTED_DATASET, 'a', newline='', encoding='utf8') as f_out:
            writer = csv.writer(f_out, delimiter=';')
            print('Processing line {}'. format(line))
            # project;repo;commit;vuln_id;vul_or_fix;tool;file;LoC_vuln;LoC_sliced_lightweight;LoC_sliced_pessimist
            if line[0] == 'project':
                writer.writerow(line)
            else:
                roww = line
                starting_index = 1
                if line[4] in ['Tool_A', 'Tool_B']:
                    starting_index = 0
                file = line[-2]
                lines = line[-1]
                roww.append(str(self.slicer.get_slice(repo=line[1], path=file, lines=lines, commit=line[2],
                                                      slicetype='lightweight', starting_index=starting_index)))
                roww.append(str(self.slicer.get_slice(repo=line[1], path=file, lines=lines, commit=line[2],
                                                      slicetype='pessimist', starting_index=starting_index)))

                writer.writerow(roww)

    def augment_final_dataset_with_slices(self, input_dataset, WORKERS=4):
            read_lines = []
        # try:
            with open(input_dataset, 'r', encoding='utf8', newline='') as f_in:
                reader = csv.reader(f_in, delimiter=';')
                for line in reader:
                    read_lines.append(line)
                # read_lines = reader.readlines()
                with Pool(processes=3) as pool:
                    pool.map(self._augment_helper, read_lines)
                # with open(AUGMENTED_DATASET, 'w', newline='', encoding='utf8') as f_out:
                #     writer = csv.writer(f_out, delimiter=';')
                #     count = 0
                #     for line in reader:
                #         count += 1
                #         print('Augmenting item {}'.format(count))
                #         # project;repo;commit;vuln_id;vul_or_fix;tool;file;LoC_vuln;LoC_sliced_lightweight;LoC_sliced_pessimist
                #         if line[0] == 'project':
                #             continue
                #         roww = line
                #         roww.append(str(self.slicer.get_slice(repo=line[1], path=line[-2], lines=line[-1], commit=line[2], slicetype='lightweight')))
                #         roww.append(str(self.slicer.get_slice(repo=line[1], path=line[-2], lines=line[-1], commit=line[2], slicetype='pessimist')))
                #         writer.writerow(roww)
        # except Exception as e:
        #     print('I cannot open file {}'.format(input_dataset))
        #     print(str(e))


if __name__ == '__main__':
    # slicer = Slicer()
    # print(slicer.get_slice('git@github.com:apache/tomcat.git', path=os.path.join(DATA_FOLDER, 'cache', 'tomcat', 'java/org/apache/tomcat/util/buf/UDecoder.java'), lines='77, 78, 79, 81, 82, 84, 92, 95, 97, 98, 99, 100, 101, 104, 107, 108, 109, 113, 114, 115, 118, 145, 146, 147, 149, 150, 151, 152, 154, 159, 160, 163, 164, 165, 166, 167, 170, 174, 175, 176, 180, 181, 182, 185, 203, 205, 206, 209, 212, 213, 216, 217, 240, 241, 244, 245, 249, 250, 256, 257, 258, 262, 267, 268, 269, 270, 272, 276, 277, 278', commit='ec7ff88', slicetype='pessimist'))

    ds_gen = DatasetGenerator()
    # # ds_gen.combine_revisions_ground_truth()
    # # ds_gen.get_alerts_dict()
    # ds_gen.final_dict_as_table(vuln=True)
    # ds_gen.final_dict_as_table(vuln=False)
    common_output = os.path.join(DATA_FOLDER, 'combined_output.csv')
    # ds_gen.combine_final_dataset_file(common_output)

    ds_gen.augment_final_dataset_with_slices(common_output, AUGMENTED_DATASET)

    # args = sys.argv
    # if len(args) < 3:
    #     print('Usage: python3 dataset_generator.py <Vuln> <SliceType>')
    #     print('<Vuln> can be True or False')
    #     print('<SliceType> can be Lightweight or Pessimist')
    # else:
    #     ds_gen = DatasetGenerator()
    #     # # ds_gen.combine_revisions_ground_truth()
    #     # # ds_gen.get_alerts_dict()
    #     ds_gen.final_dict_as_table(vuln=args[1], slicetype=args[2])
