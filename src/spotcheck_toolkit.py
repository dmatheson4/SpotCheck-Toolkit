import os
import sys
import scanner
import json

files_not_scanned = []


def read_lines_from_files(directory_path):
    """
    Reads lines from all files within a directory and its subdirectories.

    Args:
    directory_path (str): Path to the directory containing files.

    Returns:
    dict: Dictionary with file paths as keys and lists of lines as values.
    """
    lines_by_file = {}
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if os.path.isfile(file_path):
                # If the filename is not supported, then it will not be loaded or scanned
                if len(file_path.split(".py")) == 1 or file_path.split(".py")[1] != "":
                    files_not_scanned.append(file_path)
                    continue
                print(f"Reading file: {file_path}")
                with open(file_path, "r") as file:
                    lines_by_file[file_path] = file.readlines()
    return lines_by_file


def load_files(directory_path):
    """
    Main function to load lines from files within a directory and its subdirectories.

    Args:
    directory_path (str): Path to the directory containing files.

    Returns:
    Dictionary object containing the lines that have been read in from the files
    """
    lines_by_file = read_lines_from_files(directory_path)
    formatted_lines = {}

    # Process lines from each file
    for file_path, lines in lines_by_file.items():
        formatted_lines[file_path] = []
        line_count = 1
        for line in lines:
            if line.strip() == "":
                line_count += 1
                continue
            new_line = [line_count, line.strip()]
            formatted_lines[file_path].append(new_line)
            line_count += 1

    return formatted_lines


def append_lines_to_gpt_message(scanned_lines):
    """
    Function to look at lines that were returned back from a scanner and generate a question to ask
    to ChatGPT.

    Args:
    scanned_lines (dict): Dictionary object returned by the scanner function

    Returns:
    list of messages to send to the ChatGPT API
    """
    messages = []

    # Check to make sure there were lines scanned
    if len(scanned_lines) > 0:
        # Capture the lines from the scanned lines that were passed in
        for _, lines in scanned_lines.items():
            # Make sure there were findings
            if len(lines) > 0:
                # Loop through the lines and append to the messages list
                for suspicious_line in lines:
                    messages.append(
                        {
                            "role": "user",
                            "content": f"What are the potential backdoor vulnerabilities linked to the following python command: {suspicious_line[1]}",
                        }
                    )

    return messages


def combine_results(result_list_1, result_list_2):
    """
    Function take the results of two different scanners and combine their findings in one list.

    Args:
    result_list_1 (dict): Dictionary object containing scan results
    result_list_2 (dict): Dictionary object containing scan results

    Returns:
    Dictionary object containing scan results of both scanners
    """

    combined_results = {}
    # Loop through the first list and grab the file name and results
    for file_1_name, file_1_results in result_list_1.items():
        # Set the results of the combined results dict object to the first files results
        combined_results[file_1_name] = file_1_results
        # Loop through the second list and search for the matching file name
        for file_2_name, file_2_results in result_list_2.items():
            if file_1_name == file_2_name:
                # If there are not currently findings from the first file, make the second file results the combined results
                if len(file_1_results) == 0:
                    combined_results[file_1_name] = file_2_results
                # Otherwise, append them to the existing findings
                else:
                    combined_results[file_1_name] = (
                        combined_results[file_1_name] + file_2_results
                    )
                # Break out of the second for loop because the file was found
                break
    return combined_results


def format_markdown_openai(scan_result, openai_response):
    """
    Function to format the scan results with an answer from OpenAI on why it could be dangerous.
    This will return a list of lines to be printed in the markdown file.

    Args:
    scan_result (dict): Dictionary object containing scan results
    openai_response (dict): Dictionary object containing responses from the OpenAI api in the form
                            of the question as the key and response as the value.

    Returns:
    list of messages to be added to the markdown file
    """
    markdown_lines = []
    # Loop through the scan results
    for file, lines in scan_result.items():
        # Append the header for the potential vulnerabilities in the current file
        markdown_lines.append(f"### Potential vulnerabilities in file {file}")
        # Loop through all the findings
        for line_item in lines:
            # Loop through the responses from the OpenAI API
            for key, value in openai_response.items():
                # Check for a match in the question that was asked for the currently scanned item
                # Have to remove the last character when checking for a match. ChatGPT will remove trailing commas
                if line_item[1][:-1] in key:
                    markdown_lines.append(f"On line {line_item[0]}:")
                    markdown_lines.append("```python")
                    markdown_lines.append(f"{line_item[1]}")
                    markdown_lines.append("```")
                    markdown_lines.append("<details>")
                    markdown_lines.append("<summary>ChatGPT Response</summary>")
                    markdown_lines.append(f"{value}")
                    markdown_lines.append("</details>")
                    markdown_lines.append("\n")
                    markdown_lines.append("---")
                    markdown_lines.append("\n")
                    # Remove this response from the response messages so it is not searched again
                    del openai_response[key]
                    # Break out of this for loop because a match was found
                    break
    return markdown_lines


def format_markdown(scan_result):
    """
    Function to format the scan results into a list of lines that should be added to the markdown
    file. The list is returned to the caller.

    Args:
    scan_result (dict): Dictionary object containing scan results

    Returns:
    list of messages to be added to the markdown file
    """
    markdown_lines = []
    # Loop through the scan results
    for file, lines in scan_result.items():
        # Append the header for the potential vulnerabilities in the current file
        markdown_lines.append(f"### Potential vulnerabilities in file {file}")
        # Loop through the line items and append what line they were found on and what was found
        for line_item in lines:
            markdown_lines.append(f"On line {line_item[0]}:")
            markdown_lines.append("```python")
            markdown_lines.append(f"{line_item[1]}")
            markdown_lines.append("```")
            markdown_lines.append("\n")
            markdown_lines.append("---")
            markdown_lines.append("\n")
    return markdown_lines


if __name__ == "__main__":
    # Check for the correct number of inputs
    if len(sys.argv) < 2:
        print("Usage: python spotcheck_toolkit.py <directory_path> <markdown_path>")
    else:
        print(sys.argv[0])
        directory_path = sys.argv[1]
        markdown_path = sys.argv[2]
        lines_by_file = load_files(directory_path)
        import_results = scanner.scan_imports(lines_by_file)
        command_results = scanner.scan_commands(lines_by_file)
        markdown_lines = ["# SpotCheck Toolkit Scan Results", "\n"]

        # Grab the OpenAI API key from the environment variable
        api_key = os.environ.get("OPENAI_API_KEY", "not_set")
        if api_key != "not_set":
            # Only import the OpenAI library if it is going to be used.
            from openai import OpenAI

            # Establish the OpenAI client with the api key
            client = OpenAI(api_key=api_key)

            # Initialize the list of message queries
            messages = []

            # Add the initial system message to set up how the response should be returned
            messages.append(
                {
                    "role": "system",
                    "content": "You are a helpful assistant designed to output the answer to each question in json format with the question as the key and answer as the value.",
                }
            )

            # Combine the results that we got back from our scanners
            # Add more calls to combine_results to combine results from more scanners
            combined_results = combine_results(import_results, command_results)

            # Load the request messages with queries for the potential vulnerabilities found
            new_lines = append_lines_to_gpt_message(combined_results)
            if len(new_lines) > 0:
                for line in new_lines:
                    messages.append(line)

            # Make the call to the API to get the questions answered
            completion = client.chat.completions.create(
                model="gpt-3.5-turbo",
                response_format={"type": "json_object"},
                messages=messages,
            )

            # Capture the response message in a json object
            openai_response = json.loads(completion.choices[0].message.content)

            # Format the lines that will be added to the markdown file for the import results
            combined_markdown_lines = format_markdown_openai(
                combined_results, openai_response
            )
            if len(combined_markdown_lines) > 0:
                markdown_lines += combined_markdown_lines

        else:
            print("No API key detected, skipping OpenAI integration.")

            # Combine the results that we got back from our scanners
            combined_results = combine_results(import_results, command_results)

            # Format the lines that will be added to the markdown file for the import results
            combined_markdown_lines = format_markdown(combined_results)

            # If there are lines to add to the markdown file, append them
            if len(combined_markdown_lines) > 0:
                markdown_lines += combined_markdown_lines

        # Write the files that were not scanned to the markdown file
        if len(files_not_scanned) > 0:
            markdown_lines.append("### Files that were not scanned")
            for file in files_not_scanned:
                markdown_lines.append(f"* <div>{file}</div>")

        # Create the markdown file
        with open(f"{markdown_path}/spotcheck_results.md", "w+") as file:
            for line in markdown_lines:
                file.write(line)
                file.write("\n")
