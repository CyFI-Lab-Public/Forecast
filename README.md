# Forecast
Forecasting Malware Capabilities From Cyber Attack Memory Images

# Foreword
Before working with Forcast please make sure to read the 
[Forcast paper]() 
as it will help with understanding and extending the tool it if necessary!
Keep in mind that this tool is still not perfect, errors are not uncommon and knowing how to work with angr is essential.

With that being said Forecast is an incredible tool to speeds up analysis and can get you some insight into what a sample does without manually reversing it. Included are some sample memory images in (sample_dumps/windows_dynamic_loading/Dump) to illustrate in simple cases what Forsee is capable of.

# Requirements
Forcast has been primarily used on Ubuntu 14.xx and 18.xx machines and has been tested to work on those OS, but results may vary if using something else. Make sure to have all packages up to date and install prerequisites. Make sure Pip is also installed and upgraded: python3 -m pip install --upgrade pip

Python3.7-dev - Will not work without dev. Use: sudo apt install python3.7-dev

Python3.7-venv Also needed to create virtual environment, use: sudo apt install python3.7-venv

Once this repository is cloned navigate to /Forecast and create/activate the virtual environment then install angr, cle, simprocedures, and dependencies.
1) Setup the virtual environment python3.7 -m venv venv
2) Activate the virtual environment . ./venv/bin/activate
3) Install custom cle pip install -e ../path/to/Forcast/cle
4) Install custom angr pip install -e ../path/to/Forcast/angr
5) Install simprocedures pip install -e ../path/to/Forcast/simprocedures
6) Install forsee and dependencies pip install -e .[dev]




