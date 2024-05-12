# SpotCheck Toolkit
This is a python based tool kit that allows the user to perform a quick scan of some incoming python code and provide insight on potential backdoor vulnerabilities in that incoming source code. It is modular and is designed to have new scans added to it easily. It will output a markdown file showing any of the findings that it made. Also, it integrates with the ChatGPT/OpenAI API to provide an answer as to why that found source code might lead to a backdoor vulnerability. It does this by having an environment variable set that contains an api token.

### Prerequisites
Ensure you have python installed on the machine performing the scan. The only library requirement is to ensure you have the OpenAI python package installed if you want to use it. If you do not want to use it, then ensure you do not set the environment variable containing an api token and the library will not be imported and used.
```bash
pip install openai
```

### Installation

<div>Simply clone this repository and move the spotcheck_toolkit.py and scanner.py files to whatever directory you would like them to go to.</div>

### Run the Tool Kit

To run the toolkit you execute the spotcheck_toolkit.py file and pass in two arguments, the folder you would like to scan, and the folder you would like the markdown file to be written to. If you would like to use the OpenAI API functionality ensure your environment variable is set for your api token.
```bash
export OPENAI_API_KEY=your-api-key
python spotcheck_toolkit.py /my/scanned/files/directory/ /my/markdown/output/directory/
```
The output file is called spotcheck_results.md . This will contain a list of findings based on the file they were found in and line number the finding was found on.

### Testing Environment
To see some steps I have taken to set up my testing environment, check out the environment_setup directory of this repository. It contains some steps that were used to set up an Ubuntu VM running kubernetes that is hosting gitlab as well as a simple shell runner to execute the pipelines.
