from ast import literal_eval
from pprint import pprint


def search(data_frame, func_name, filename, filepath, clash_line_number):
    try:
        # Ensure filepath is a string
        if not isinstance(filepath, str):
            filepath = ''

        data = data_frame.loc[
            (data_frame['func_name'] == func_name) &
            (data_frame['filename'] == filename) &
            (data_frame['filepath'].apply(lambda x: x.split('/', maxsplit=1)[1] in filepath))
            ]

        if not data.empty and data.shape[0] > 1:
            data = data.iloc[0]

        if data.empty:
            raise IndexError("No matching data found")

        try:
            function_signature = data['function_signature'].values[0]
            function_start_line = int(data['start_line'].values[0])
            function_end_line = int(data['end_line'].values[0])
            function_start_column = int(data['start_column'].values[0])
            function_end_column = int(data['end_column'].values[0])
            filepath = data['filepath'].values[0]
            line_map = literal_eval(data['line_map'].values[0])
        except AttributeError:
            function_signature = data['function_signature']
            function_start_line = int(data['start_line'])
            function_end_line = int(data['end_line'])
            function_start_column = int(data['start_column'])
            function_end_column = int(data['end_column'])
            filepath = data['filepath']
            line_map = literal_eval(data['line_map'])
        crash_line = "ERROR"
        try:
            crash_line = list(filter(lambda x: x[0] == clash_line_number, line_map))[0][1]
        except IndexError:
            crash_line = "ERROR"
            print("=====================================")
            print("🤡🤡🤡🤡🤡🤡🤡🤡🤡")
            # print(f"Error: {clash_line_number} not found in {line_map}")
            print(crash_line)
            print("=====================================")
            print('-------------------')
            print("FUNCTION NAME=> ", func_name)
            print("FILE NAME=> ", filename)
            print("FILE PATH=> ", filepath)
            print("CRASH LINE NUMBER=>", clash_line_number)
            print('+++++++++++++++++++')
            print("Data Frame")
            pprint(data)
            print('~~~~~~~~~~~~~~~~~~~')
            print("Line Map")

        return {
            'function_signature': function_signature.split("::")[
                1] if "::" in function_signature else function_signature,
            'key': function_signature,
            'function_start_line': function_start_line,
            'function_end_line': function_end_line,
            'function_start_column': function_start_column,
            'function_end_column': function_end_column,
            'crash_line': crash_line,
            'filepath': filepath
        }
    except IndexError:
        return {
            'function_signature': '',
            'key': '',
            'function_start_line': '',
            'function_end_line': '',
            'function_start_column': '',
            'function_end_column': '',
            'crash_line': '',
            'filepath': ''
        }
