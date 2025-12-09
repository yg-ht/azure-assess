# azure-assess
Python tool to capture configuration data from an Azure account and enable easy local viewing

## Installation

Example installation steps are as follows:

```
apt install azure-cli pipenv
git clone https://github.com/yg-ht/azure-assess.git
cd azure-assess
pipenv install -r requirements.txt
```

## Execution

It should be fairly obvious how to use it, essentially you just specify the output directory and run it.  A command like this will likely work:

```
mkdir ~/azure-collect-data
pipenv run python azure-collect.py -o ~/azure-collect-data
```

It will then ask you to launch a web browser, visit the Microsoft Azure Device login page and enter a code.  You will then need to follow the instructions, including when it tells you that you can close the window.
